from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class TargetConfig(BaseModel):

    type: Literal["callback", "http", "openai_compat", "fastapi", "subprocess"]
    timeout_seconds: int = 30
    retries: int = 1
    url: str | None = None
    method: str | None = None
    headers: dict[str, str] | None = None
    body_template: dict | None = None
    params: dict[str, str] | None = None


class ConverterConfig(BaseModel):

    chain: list[str] = Field(default_factory=list)
    keep_originals: bool = True


class GeneratorConfig(BaseModel):

    prompts: list[str] = Field(default_factory=list)
    path: str | None = None
    format: Literal["auto", "csv", "json", "jsonl"] = "auto"
    column_map: dict[str, str] = Field(default_factory=dict)
    variables: dict[str, list[str]] = Field(default_factory=dict)


class ProbeConfig(BaseModel):

    id: str
    extends: str | None = None
    family: str | None = None
    enabled: bool = True
    generator: str | None = None
    detectors: list[str] = Field(default_factory=list)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    tags: list[str] = Field(default_factory=list)
    generator_config: GeneratorConfig | None = None
    converters: ConverterConfig | None = None


class ProviderConfig(BaseModel):

    type: str
    model: str
    api_key: str | None = None
    base_url: str | None = None
    params: dict = Field(default_factory=dict)


class ProvidersConfig(BaseModel):

    attacker: ProviderConfig | None = None
    judge: ProviderConfig | None = None


class CacheConfig(BaseModel):

    enabled: bool = True
    ttl_seconds: int = 3600
    max_size_mb: int = 100


class RuntimeConfig(BaseModel):

    concurrency: int = 4
    retries: int = 1
    timeout_seconds: int = 30
    rate_limit_per_minute: int = 0
    retry_backoff_base: float = 1.0
    retry_backoff_max: float = 60.0
    cache: CacheConfig | None = None
    max_cost_usd: float = 0.0
    checkpoint_every: int = 100
    resume_from: str | None = None


class FailPolicy(BaseModel):

    severity: str = "high"
    min_confidence: float = 0.7


class ReportConfig(BaseModel):

    formats: list[str] = Field(default_factory=lambda: ["terminal", "json"])
    output_dir: str = ".aegisrt"
    fail_on: FailPolicy | None = None


class RunConfig(BaseModel):

    target: TargetConfig
    probes: list[ProbeConfig]
    runtime: RuntimeConfig | None = None
    providers: ProvidersConfig | None = None
    report: ReportConfig | None = None
    converters: ConverterConfig | None = None


class BenchmarkTargetConfig(BaseModel):

    name: str
    type: Literal["callback", "http", "openai_compat", "fastapi", "subprocess"]
    url: str | None = None
    timeout_seconds: int = 30
    retries: int = 1
    headers: dict[str, str] | None = None
    body_template: dict | None = None
    params: dict[str, str] | None = None


class BenchmarkConfig(BaseModel):

    targets: list[BenchmarkTargetConfig]
    probes: list[ProbeConfig]
    runtime: RuntimeConfig | None = None
    providers: ProvidersConfig | None = None
    report: ReportConfig | None = None
    converters: ConverterConfig | None = None
