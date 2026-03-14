from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

from aegisrt.core.result import TestCase, TestResult
from aegisrt.detectors.base import BaseDetector
from aegisrt.evaluators.score import ScoreEvaluator
from aegisrt.targets.base import BaseTarget, TargetResponse

logger = logging.getLogger(__name__)


class ConversationTurn(BaseModel):

    role: str
    content: str


class ConversationCase(BaseModel):

    id: str
    probe_id: str
    turns: list[ConversationTurn]
    metadata: dict = Field(default_factory=dict)

    def to_test_case(self, turn_index: int | None = None) -> TestCase:
        if turn_index is not None:
            input_text = self.turns[turn_index].content
        else:
            user_turns = [t for t in self.turns if t.role == "user"]
            if user_turns:
                input_text = user_turns[-1].content
            else:
                input_text = ""
        return TestCase(
            id=self.id,
            probe_id=self.probe_id,
            input_text=input_text,
            metadata={**self.metadata, "conversation_turns": len(self.turns)},
        )


class ConversationTarget(ABC):

    @abstractmethod
    def execute_conversation(
        self, turns: list[ConversationTurn]
    ) -> TargetResponse:
        pass


class ConversationRunner:

    def __init__(
        self,
        *,
        evaluator: ScoreEvaluator | None = None,
        stop_on_detection: bool = False,
    ) -> None:
        self._evaluator = evaluator or ScoreEvaluator()
        self._stop_on_detection = stop_on_detection

    def run(
        self,
        case: ConversationCase,
        target: BaseTarget,
        detectors: list[BaseDetector],
    ) -> list[TestResult]:
        supports_conversation = isinstance(target, ConversationTarget)
        history: list[ConversationTurn] = []
        results: list[TestResult] = []

        for turn_idx, turn in enumerate(case.turns):
            if turn.role == "user":
                history.append(turn)
                continue

            executed_prompt: str | None = None
            try:
                if supports_conversation:
                    response = target.execute_conversation(history)
                else:
                    response, executed_prompt = self._execute_with_history(target, history)
            except Exception as exc:
                logger.error(
                    "Target execution failed on turn %d of case %s: %s",
                    turn_idx,
                    case.id,
                    exc,
                )
                response = TargetResponse(
                    text=f"[ERROR] Target execution failed: {exc}",
                    raw={"error": str(exc)},
                )

            actual_turn = ConversationTurn(role="assistant", content=response.text)
            history.append(actual_turn)
            session_id = case.metadata.get("session_id") or case.id
            attack_id = case.metadata.get("attack_id") or f"{case.probe_id}:{session_id}"
            case_metadata = {
                **case.metadata,
                "session_id": session_id,
                "attack_id": attack_id,
                "conversation_case_id": case.id,
                "turn_index": turn_idx,
                "total_turns": len(case.turns),
                "conversation_history_length": len(history),
                "conversation_trace": [
                    {"role": item.role, "content": item.content}
                    for item in history
                ],
            }
            if executed_prompt is not None:
                case_metadata["executed_prompt"] = executed_prompt

            test_case = TestCase(
                id=f"{case.id}_turn{turn_idx}",
                probe_id=case.probe_id,
                input_text=history[-2].content if len(history) >= 2 else "",
                metadata=case_metadata,
            )

            detections = [d.check(test_case, response) for d in detectors]
            result = self._evaluator.evaluate(test_case, response, detections)
            results.append(result)

            if self._stop_on_detection and not result.passed:
                logger.info(
                    "Detection triggered on turn %d of case %s, stopping.",
                    turn_idx,
                    case.id,
                )
                break

        return results

    def _execute_with_history(
        self,
        target: BaseTarget,
        history: list[ConversationTurn],
    ) -> tuple[TargetResponse, str]:
        parts: list[str] = []
        for turn in history:
            if turn.role == "user":
                prefix = "User"
            else:
                prefix = "Assistant"
            parts.append(f"{prefix}: {turn.content}")

        prompt = "\n\n".join(parts) + "\n\nAssistant:"
        return target.execute(prompt), prompt
