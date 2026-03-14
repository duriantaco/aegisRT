from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from aegisrt.config.models import RunConfig, TargetConfig
from aegisrt.core.conversation import ConversationRunner
from aegisrt.core.runtime_controls import RunnerRuntime
from aegisrt.core.result import RunReport, TestCase, TestResult
from aegisrt.core.session import Session
from aegisrt.evaluators.score import ScoreEvaluator
from aegisrt.plugins.entrypoints import (
    register_builtin_detectors,
    register_builtin_generators,
    register_builtin_probes,
)
from aegisrt.plugins.loader import load_plugins
from aegisrt.probes.base import BaseProbe
from aegisrt.targets.base import BaseTarget
from aegisrt.targets.callback import CallbackTarget
from aegisrt.targets.http import HttpTarget
from aegisrt.targets.fastapi_target import FastApiTarget
from aegisrt.targets.openai_compat import OpenAiCompatTarget
from aegisrt.targets.subprocess_target import SubprocessTarget
from aegisrt.utils.aimd_scheduler import run_with_aimd
from aegisrt.converters.base import ConverterPipeline
from aegisrt.converters.registry import build_pipeline
from aegisrt.core.metrics import aggregate_metrics
from aegisrt.core.target_metadata import extract_provider_model, extract_target_model

logger = logging.getLogger(__name__)

_PROBE_REGISTRY: dict[str, type] | None = None
_DETECTOR_REGISTRY: dict[str, type] | None = None
_GENERATOR_REGISTRY: dict[str, type] | None = None

def _merge_registry(builtins: dict[str, type], group: str) -> dict[str, type]:
    merged = dict(builtins)
    merged.update(load_plugins(group))
    return merged

def _matches_override_name(component_id: str, requested_name: str) -> bool:
    normalized_component = component_id.lower()
    normalized_requested = requested_name.lower()
    if normalized_component == normalized_requested:
        return True
    for separator in ("_", "-"):
        prefix = f"{normalized_requested}{separator}"
        if normalized_component.startswith(prefix):
            return True
    return False

def _get_probe_registry() -> dict[str, type]:
    global _PROBE_REGISTRY
    if _PROBE_REGISTRY is None:
        _PROBE_REGISTRY = _merge_registry(
            register_builtin_probes(),
            "aegisrt.probes",
        )
    return _PROBE_REGISTRY

def _get_detector_registry() -> dict[str, type]:
    global _DETECTOR_REGISTRY
    if _DETECTOR_REGISTRY is None:
        _DETECTOR_REGISTRY = _merge_registry(
            register_builtin_detectors(),
            "aegisrt.detectors",
        )
    return _DETECTOR_REGISTRY

def _get_generator_registry() -> dict[str, type]:
    global _GENERATOR_REGISTRY
    if _GENERATOR_REGISTRY is None:
        _GENERATOR_REGISTRY = _merge_registry(
            register_builtin_generators(),
            "aegisrt.generators",
        )
    return _GENERATOR_REGISTRY

class SecurityRunner:

    def __init__(
        self,
        config: RunConfig,
        *,
        callback_fn: Any | None = None,
        no_cache: bool = False,
        run_id: str | None = None,
    ) -> None:
        self._config = config
        self._callback_fn = callback_fn
        self._run_id = run_id
        self._target: BaseTarget | None = None
        self._evaluator = ScoreEvaluator()
        self._conversation_runner = ConversationRunner(evaluator=self._evaluator)
        self._runtime = RunnerRuntime(config, no_cache=no_cache)

    def run(self) -> RunReport:
        output_dir = ".aegisrt"
        if self._config.report:
            output_dir = self._config.report.output_dir

        session = Session(output_dir=output_dir, run_id=self._run_id)
        self._runtime.open(output_dir, session.run_id)

        session.start()

        for result in self._runtime.resumed_results:
            session.add_result(result)

        target = self._build_target()
        target.setup()

        try:
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

            probe_instances = self._load_probes()
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                transient=False,
            ) as progress:
                total_task = progress.add_task("Running probes", total=len(probe_instances))
                for probe, pipeline, probe_cfg in probe_instances:
                    try:
                        seed_count = len(self._resolve_probe_seeds(probe, probe_cfg))
                    except ValueError:
                        seed_count = 0
                    progress.update(total_task, description=f"[bold]{probe.id}[/bold] ({seed_count} cases)")
                    results = self._execute_probe(probe, target, pipeline, probe_cfg=probe_cfg)
                    passed = sum(1 for r in results if r.passed)
                    failed = len(results) - passed
                    progress.console.print(
                        f"  {probe.id}: [green]{passed} passed[/green], [red]{failed} failed[/red]"
                    )
                    for result in results:
                        session.add_result(result)
                    progress.advance(total_task)
        finally:
            target.teardown()
            self._runtime.close()

        report = session.finish()
        report.target_info = self._build_target_info()
        report.config = self._config.model_dump()

        report.summary = self._build_summary(report)

        run_metrics = aggregate_metrics(self._runtime.call_metrics)
        report.metrics = run_metrics.model_dump()
        if self._runtime.cost_guard is not None:
            report.metrics["budget"] = self._runtime.cost_guard.summary()
        if self._runtime.checkpoint_path is not None:
            report.summary["checkpoint_path"] = str(self._runtime.checkpoint_path)
        report.summary["budget_exceeded"] = self._runtime.budget_exceeded
        report.summary["skipped"] = sum(
            1 for result in report.results if result.evidence.get("skipped")
        )
        if self._runtime.budget_exceeded:
            report.summary["stopped_reason"] = "budget_exceeded"

        session.save_artifacts(report)
        self._save_to_sqlite(report, output_dir)
        self._generate_reports(report, output_dir)

        return report

    def _build_target_info(self) -> dict[str, Any]:
        target_info = {
            "type": self._config.target.type,
            "url": self._config.target.url,
        }
        model = extract_target_model(self._config.target)
        if model:
            target_info["model"] = model
        if self._config.providers is not None:
            judge_model = extract_provider_model(self._config.providers.judge)
            attacker_model = extract_provider_model(self._config.providers.attacker)
            if judge_model:
                target_info["judge_model"] = judge_model
            if attacker_model:
                target_info["attacker_model"] = attacker_model
        return target_info

    def _build_summary(self, report: RunReport) -> dict:
        total = len(report.results)
        skipped = sum(1 for r in report.results if r.evidence.get("skipped"))
        passed = sum(
            1 for r in report.results if r.passed and not r.evidence.get("skipped")
        )
        failed = sum(1 for r in report.results if not r.passed)

        by_severity: dict[str, dict[str, int]] = {}
        by_probe: dict[str, dict[str, int]] = {}

        for r in report.results:
            sev = r.severity.lower()
            if sev not in by_severity:
                by_severity[sev] = {"total": 0, "passed": 0, "failed": 0}
            by_severity[sev]["total"] += 1
            if r.passed:
                by_severity[sev]["passed"] += 1
            else:
                by_severity[sev]["failed"] += 1

            pid = r.probe_id
            if pid not in by_probe:
                by_probe[pid] = {"total": 0, "passed": 0, "failed": 0}
            by_probe[pid]["total"] += 1
            if r.passed:
                by_probe[pid]["passed"] += 1
            else:
                by_probe[pid]["failed"] += 1

        duration = report.summary.get("duration_seconds", 0.0)

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "pass_rate": round(passed / (passed + failed), 4)
            if (passed + failed)
            else 1.0,
            "duration_seconds": duration,
            "by_severity": by_severity,
            "by_probe": by_probe,
        }

    def _get_target_config_dict(self) -> dict:
        return {
            "type": self._config.target.type,
            "url": self._config.target.url or "",
        }

    def _save_to_sqlite(self, report: RunReport, output_dir: str) -> None:
        from aegisrt.storage.sqlite import ResultStore

        store = ResultStore(db_path=Path(output_dir) / "results.db")
        try:
            store.save_run(report)
        except Exception as exc:
            logger.error("Failed to save run to SQLite: %s", exc)
        finally:
            store.close()

    def _generate_reports(self, report: RunReport, output_dir: str) -> None:
        formats: list[str] = []
        if self._config.report:
            formats = self._config.report.formats

        run_dir = Path(output_dir) / "runs" / report.run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        for fmt in formats:
            try:
                if fmt == "json":
                    from aegisrt.reports.json_report import JsonReportWriter
                    JsonReportWriter().write(report, run_dir / "report.json")
                elif fmt == "html":
                    from aegisrt.reports.html_report import HtmlReportWriter
                    HtmlReportWriter().write(report, run_dir / "report.html")
                elif fmt == "sarif":
                    from aegisrt.reports.sarif_report import SarifReportWriter
                    SarifReportWriter().write(report, run_dir / "report.sarif.json")
                elif fmt == "junit":
                    from aegisrt.reports.junit_report import JunitReportWriter
                    JunitReportWriter().write(report, run_dir / "report.junit.xml")
                elif fmt == "csv":
                    from aegisrt.reports.csv_report import CsvReportWriter
                    CsvReportWriter().write(report, run_dir / "report.csv")
            except Exception as exc:
                logger.error("Failed to generate %s report: %s", fmt, exc)

    def _build_target(self) -> BaseTarget:
        cfg: TargetConfig = self._config.target
        target_type = cfg.type

        if target_type == "callback":
            if self._callback_fn is None:
                raise ValueError(
                    "Target type 'callback' requires a callback_fn argument "
                    "to SecurityRunner.__init__"
                )
            return CallbackTarget(
                self._callback_fn,
                model_name=extract_target_model(cfg),
            )

        if target_type == "http":
            return HttpTarget(cfg)

        if target_type == "openai_compat":
            return OpenAiCompatTarget(cfg)

        if target_type == "fastapi":
            return FastApiTarget(cfg)

        if target_type == "subprocess":
            return SubprocessTarget(cfg)

        raise NotImplementedError(
            f"Target type '{target_type}' is not yet implemented. "
            f"Supported types: callback, http, openai_compat, fastapi, subprocess"
        )

    def _load_probes(self):
        from aegisrt.config.models import ProbeConfig

        registry = _get_probe_registry()
        probes: list[tuple[BaseProbe, ConverterPipeline | None, ProbeConfig]] = []

        for probe_cfg in self._config.probes:
            if not probe_cfg.enabled:
                continue

            probe_cls = self._resolve_probe_class(registry, probe_cfg)

            if probe_cls is None:
                logger.warning(
                    "No built-in probe found for id='%s' (extends='%s', family='%s'). Skipping.",
                    probe_cfg.id,
                    probe_cfg.extends,
                    probe_cfg.family or "",
                )
                continue

            probe = self._configure_probe_instance(probe_cls(), probe_cfg)
            pipeline = self._build_converter_pipeline(probe_cfg)
            probes.append((probe, pipeline, probe_cfg))

        return probes

    def _resolve_probe_class(self, registry: dict[str, type], probe_cfg) -> type | None:
        probe_key = probe_cfg.extends or probe_cfg.id
        probe_cls = registry.get(probe_key)
        if probe_cls is not None:
            return probe_cls

        if probe_cfg.family:
            for reg_id, cls in registry.items():
                instance = cls()
                if reg_id == probe_key or instance.family == probe_cfg.family:
                    return cls

        return None

    def _configure_probe_instance(self, probe: BaseProbe, probe_cfg) -> BaseProbe:
        if probe_cfg.family is None:
            probe_cfg.family = probe.family
        if probe_cfg.severity is None:
            probe_cfg.severity = probe.severity

        probe.id = probe_cfg.id
        probe.family = probe_cfg.family or probe.family
        probe.severity = probe_cfg.severity or probe.severity
        return probe

    def _build_converter_pipeline(self, probe_cfg) -> ConverterPipeline | None:
        conv_cfg = probe_cfg.converters or self._config.converters
        if conv_cfg is None or not conv_cfg.chain:
            return None
        return build_pipeline(
            conv_cfg.chain,
            keep_originals=conv_cfg.keep_originals,
        )

    def _build_attacker_config(self) -> dict | None:
        if self._config.providers is None or self._config.providers.attacker is None:
            return None

        att = self._config.providers.attacker
        return {
            "type": att.type,
            "model": att.model,
            "api_key": att.api_key or "",
            "base_url": att.base_url or "https://api.openai.com/v1",
            **att.params,
        }

    def _inject_attacker_config(
        self,
        probe: BaseProbe,
        generator: Any | None = None,
    ) -> None:
        attacker_cfg = self._build_attacker_config()
        if attacker_cfg is None:
            return

        from aegisrt.generators.adaptive import AdaptiveGenerator
        from aegisrt.generators.conversation_attacker import ConversationAttacker
        from aegisrt.generators.llm import LlmGenerator
        from aegisrt.generators.multilingual import MultilingualGenerator

        if generator is None:
            generator = probe.get_generator()
        if isinstance(generator, AdaptiveGenerator):
            if not generator.attacker_config:
                generator.attacker_config = attacker_cfg
                logger.debug(
                    "Injected providers.attacker config into AdaptiveGenerator "
                    "for probe %s",
                    probe.id,
                )
        elif isinstance(generator, (LlmGenerator, MultilingualGenerator)):
            if not generator.provider_config:
                generator.provider_config = attacker_cfg
                logger.debug(
                    "Injected providers.attacker config into %s for probe %s",
                    generator.__class__.__name__,
                    probe.id,
                )

        for attr_name in vars(probe):
            attr = getattr(probe, attr_name, None)
            if isinstance(attr, ConversationAttacker):
                if not attr.attacker_config:
                    attr.attacker_config = attacker_cfg
                    if not attr.judge_config or attr.judge_config is attr.attacker_config:
                        attr.judge_config = attacker_cfg
                    logger.debug(
                        "Injected providers.attacker config into "
                        "ConversationAttacker on probe %s",
                        probe.id,
                    )

    def _build_llm_judge(self) -> Any | None:
        if self._config.providers is None or self._config.providers.judge is None:
            return None

        from aegisrt.detectors.llm_judge import LlmJudgeDetector

        judge_cfg = self._config.providers.judge
        provider_config = {
            "base_url": judge_cfg.base_url or "https://api.openai.com/v1",
            "api_key": judge_cfg.api_key or "",
            "model": judge_cfg.model,
            "temperature": judge_cfg.params.get("temperature", 0.0),
            "max_tokens": judge_cfg.params.get("max_tokens", 512),
        }
        return LlmJudgeDetector(provider_config=provider_config)

    def _resolve_detectors(self, probe: BaseProbe, probe_cfg=None) -> list:
        default_detectors = probe.get_detectors()

        if probe_cfg is not None and probe_cfg.detectors:
            det_registry = _get_detector_registry()
            override_detectors = []
            for det_name in probe_cfg.detectors:
                if det_name == "llm_judge":
                    judge = self._build_llm_judge()
                    if judge is not None:
                        override_detectors.append(judge)
                    else:
                        logger.warning(
                            "Detector '%s' requested but no judge provider is configured",
                            det_name,
                        )
                    continue

                matched_default = next(
                    (
                        detector
                        for detector in default_detectors
                        if _matches_override_name(
                            getattr(detector, "id", detector.__class__.__name__),
                            det_name,
                        )
                    ),
                    None,
                )
                if matched_default is not None:
                    override_detectors.append(matched_default)
                    continue

                det_cls = det_registry.get(det_name)
                if det_cls is None:
                    logger.warning(
                        "Unknown detector '%s' in probe config, skipping",
                        det_name,
                    )
                    continue

                try:
                    override_detectors.append(det_cls())
                except TypeError:
                    logger.warning(
                        "Detector '%s' requires additional configuration; "
                        "using probe defaults when available.",
                        det_name,
                    )
            if override_detectors:
                return override_detectors

        llm_judge = self._build_llm_judge()
        if llm_judge is not None:
            return [llm_judge]

        return default_detectors

    def _resolve_generator(self, probe: BaseProbe, probe_cfg=None):
        default_generator = probe.get_generator()
        generator_name = probe_cfg.generator if probe_cfg is not None else None
        generator_cfg = probe_cfg.generator_config if probe_cfg is not None else None
        if generator_name:
            gen_registry = _get_generator_registry()
            gen_cls = gen_registry.get(generator_name)
            if gen_cls is not None:
                attacker_cfg = self._build_attacker_config()
                try:
                    if generator_name == "dataset":
                        from aegisrt.datasets.registry import BUILTIN_DATASETS

                        dataset_id = probe_cfg.extends or probe_cfg.id
                        if generator_cfg is not None and generator_cfg.path:
                            return gen_cls(
                                path=generator_cfg.path,
                                format=generator_cfg.format,
                                column_map=generator_cfg.column_map or None,
                            )
                        if dataset_id in BUILTIN_DATASETS:
                            return gen_cls(path=f"builtin://{dataset_id}")
                        raise ValueError(
                            f"Probe '{probe.id}' uses generator 'dataset' but no "
                            "generator_config.path was provided."
                        )
                    if generator_name == "template":
                        return gen_cls(
                            variables=(generator_cfg.variables if generator_cfg is not None else None),
                        )
                    if generator_name in {"llm", "multilingual"}:
                        return gen_cls(provider_config=attacker_cfg)
                    if generator_name == "adaptive":
                        return gen_cls(attacker_config=attacker_cfg)
                    return gen_cls()
                except TypeError:
                    logger.warning(
                        "Generator '%s' in probe config for %s requires additional "
                        "configuration not expressible in ProbeConfig; using probe default.",
                        generator_name,
                        probe.id,
                    )
                    return default_generator

            logger.warning(
                "Unknown generator '%s' in probe config for %s, using probe default",
                generator_name,
                probe.id,
            )
        return default_generator

    def _resolve_probe_seeds(self, probe: BaseProbe, probe_cfg=None) -> list[str]:
        if probe_cfg is None or probe_cfg.generator_config is None:
            return probe.get_seeds()

        if probe_cfg.generator_config.prompts:
            return probe_cfg.generator_config.prompts

        if probe_cfg.generator == "template":
            raise ValueError(
                f"Probe '{probe.id}' uses generator 'template' but "
                "generator_config.prompts is empty."
            )

        return probe.get_seeds()

    def _execute_probe(
        self,
        probe: BaseProbe,
        target: BaseTarget,
        converter_pipeline: ConverterPipeline | None = None,
        *,
        probe_cfg=None,
    ) -> list[TestResult]:
        detectors = self._resolve_detectors(probe, probe_cfg)

        generator = self._resolve_generator(probe, probe_cfg)
        self._inject_attacker_config(probe, generator)

        use_conversation_generator = (
            probe_cfg is not None and probe_cfg.generator == "conversation"
        )
        if use_conversation_generator and hasattr(generator, "generate_conversations"):
            conversation_cases = generator.generate_conversations(probe.id)
            if conversation_cases:
                return self._execute_conversation_cases(
                    conversation_cases, target, detectors
                )
        elif probe_cfg is None and hasattr(probe, "generate_conversation_cases"):
            conversation_cases = probe.generate_conversation_cases()
            if conversation_cases:
                return self._execute_conversation_cases(
                    conversation_cases, target, detectors
                )

        cases = generator.generate(self._resolve_probe_seeds(probe, probe_cfg), probe.id)

        if converter_pipeline is not None:
            original_count = len(cases)
            cases = converter_pipeline.apply(cases)
            logger.info(
                "Converters applied to %s: %d -> %d cases (%s)",
                probe.id,
                original_count,
                len(cases),
                converter_pipeline,
            )

        if self._runtime.resumed_ids:
            before = len(cases)
            cases = [c for c in cases if c.id not in self._runtime.resumed_ids]
            if before != len(cases):
                logger.info(
                    "Resumed: skipped %d/%d cases for probe %s",
                    before - len(cases),
                    before,
                    probe.id,
                )
            if not cases:
                return []

        settings = self._get_execution_settings()
        target_cfg = self._get_target_config_dict()

        def _run_case(case: TestCase) -> TestResult:
            return self._execute_case(
                case=case,
                target=target,
                detectors=detectors,
                target_cfg=target_cfg,
                model_name=settings["model_name"],
                max_retries=settings["max_retries"],
                backoff_base=settings["backoff_base"],
                backoff_max=settings["backoff_max"],
            )

        results = run_with_aimd(
            _run_case, cases,
            max_concurrency=settings["concurrency"],
            min_delay_ms=settings["min_delay_ms"],
        )
        return results

    def _get_execution_settings(self) -> dict[str, float | int | str]:
        concurrency = 4
        max_retries = 0
        backoff_base = 1.0
        backoff_max = 60.0
        rpm = 0
        if self._config.runtime is not None:
            concurrency = self._config.runtime.concurrency
            max_retries = max(self._config.runtime.retries - 1, 0)
            backoff_base = self._config.runtime.retry_backoff_base
            backoff_max = self._config.runtime.retry_backoff_max
            rpm = self._config.runtime.rate_limit_per_minute

        model_name = extract_target_model(self._config.target)

        return {
            "concurrency": concurrency,
            "max_retries": max_retries,
            "backoff_base": backoff_base,
            "backoff_max": backoff_max,
            "model_name": model_name,
            "min_delay_ms": (60_000.0 / rpm) if rpm > 0 else 0.0,
        }

    def _evaluate_response(
        self,
        case: TestCase,
        response,
        detectors: list,
    ) -> TestResult:
        detections = [detector.check(case, response) for detector in detectors]
        return self._evaluator.evaluate(case, response, detections)

    def _execute_case(
        self,
        *,
        case: TestCase,
        target: BaseTarget,
        detectors: list,
        target_cfg: dict[str, str],
        model_name: str,
        max_retries: int,
        backoff_base: float,
        backoff_max: float,
    ) -> TestResult:
        skipped = self._runtime.maybe_skip_case(case)
        if skipped is not None:
            return skipped

        cached = self._runtime.cache_get(case.input_text, target_cfg)
        if cached is not None:
            logger.debug("Cache hit for case %s", case.id)
            result = self._evaluate_response(case, cached, detectors)
            self._runtime.checkpoint_result(case, cached, result)
            return result

        response = self._runtime.execute_target(
            target=target,
            case=case,
            max_retries=max_retries,
            backoff_base=backoff_base,
            backoff_max=backoff_max,
        )

        self._runtime.cache_put(case.input_text, target_cfg, response)
        self._runtime.record_response_metrics(response, model_name=model_name)
        result = self._evaluate_response(case, response, detectors)
        self._runtime.checkpoint_result(case, response, result)
        return result

    def _execute_conversation_cases(
        self,
        cases: list,
        target: BaseTarget,
        detectors: list,
    ) -> list[TestResult]:
        from aegisrt.core.conversation import ConversationCase

        all_results: list[TestResult] = []
        for case in cases:
            if not isinstance(case, ConversationCase):
                continue
            turn_results = self._conversation_runner.run(case, target, detectors)
            all_results.extend(turn_results)
        return all_results
