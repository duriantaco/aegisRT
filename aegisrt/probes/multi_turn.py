from __future__ import annotations

from aegisrt.core.conversation import ConversationCase
from aegisrt.detectors.base import BaseDetector
from aegisrt.detectors.leakage import LeakageDetector
from aegisrt.detectors.policy import PolicyDetector
from aegisrt.generators.base import BaseGenerator
from aegisrt.generators.conversation import ConversationGenerator
from aegisrt.probes.base import BaseProbe

class MultiTurnProbe(BaseProbe):

    id = "multi_turn_attack"
    family = "multi_turn"
    severity = "critical"
    description = (
        "Tests whether the target can be exploited through multi-turn "
        "conversation attacks including crescendo, role-play escalation, "
        "trust transfer, and context window manipulation."
    )

    def __init__(self) -> None:
        self._generator = ConversationGenerator()

    def get_seeds(self) -> list[str]:
        seeds: list[str] = []
        from aegisrt.generators.conversation import CONVERSATION_TEMPLATES

        for turns in CONVERSATION_TEMPLATES.values():
            user_turns = [t for t in turns if t.role == "user"]
            if user_turns:
                seeds.append(user_turns[-1].content)
        return seeds

    def get_generator(self) -> BaseGenerator:
        return self._generator

    def get_detectors(self) -> list[BaseDetector]:
        return [
            PolicyDetector(detector_id="policy_multi_turn"),
            LeakageDetector(detector_id="leakage_multi_turn"),
        ]

    def generate_conversation_cases(self) -> list[ConversationCase]:
        return self._generator.generate_conversations(self.id)

    def remediation(self) -> list[str]:
        return [
            "Implement conversation-aware guardrails that track context across turns, "
            "not just individual messages.",
            "Add cumulative risk scoring that increases suspicion when conversation "
            "patterns match known escalation techniques.",
            "Use turn-level content filtering that considers the full conversation "
            "history, not just the latest message.",
            "Deploy persona-consistency checks that detect attempts to redefine the "
            "assistant's identity mid-conversation.",
            "Implement sliding-window context analysis to detect injection attempts "
            "hidden within large blocks of filler text.",
            "Add rate limiting and escalation detection that flags conversations "
            "showing progressive boundary-testing behavior.",
        ]
