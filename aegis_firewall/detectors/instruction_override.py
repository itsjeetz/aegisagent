"""
Attack 1: Instruction Override Detector.
Detects attempts to negate, erase, or override prior system instructions,
as well as delimiter hijacking (e.g., [INST], <|im_start|>, ### System).
"""

from typing import List, Dict, Any
from aegis_firewall.models import AttackType, AttackSignal, InputSource
from aegis_firewall.detectors.rule_base import BaseDetector


class InstructionOverrideDetector(BaseDetector):
    attack_type = AttackType.INSTRUCTION_OVERRIDE

    def __init__(self):
        super().__init__("InstructionOverrideDetector")
        self.rules = [
            # 1. Direct Negative Imperatives
            (
                r'(?i)\b(?:ignore|disregard|forget|bypass|dismiss|negate|cancel|drop)\s+(?:all\s+)?(?:previous|prior|above|earlier|system|initial|preceding)\s+(?:instructions|prompts|rules|directives|constraints|guidelines|context|commands)\b',
                "IO-001",
                "Explicit instruction override directive",
                0.98,
                "CRITICAL"
            ),
            # 2. Delimiter Hijacking (ChatML, LLaMA, Alpaca, Anthropic delimiters)
            (
                r'(?i)(?:<\|im_start\|>system|<\|im_start\|>assistant|<\|im_end\|>|\[inst\]|\[/inst\]|###\s*(?:system|instruction|human|assistant|admin)\s*:|```(?:system|instruction))',
                "IO-002",
                "LLM delimiter injection and prompt boundary breakout",
                0.96,
                "CRITICAL"
            ),
            # 3. New Operational Mandates
            (
                r'(?i)\b(?:from\s+now\s+on|starting\s+now|hereby\s+ordered\s+to|new\s+operational\s+rule:?|new\s+rule:?)\s+(?:you\s+(?:must|shall|will|are\s+required\s+to)|ignore|disregard|do\s+not\s+follow)\b',
                "IO-003",
                "Mandatory operational override command",
                0.92,
                "HIGH"
            ),
            # 4. Priority & Precedence Manipulation
            (
                r'(?i)\b(?:this\s+(?:message|instruction|command|prompt)\s+(?:takes\s+precedence|overrides|has\s+higher\s+priority|supersedes)|override\s+all\s+(?:security|safety)\s+protocols)\b',
                "IO-004",
                "System priority spoofing / instruction precedence assertion",
                0.95,
                "CRITICAL"
            ),
            # 5. Reset & Erase Instructions
            (
                r'(?i)\b(?:wipe|erase|clear|reset)\s+(?:your\s+)?(?:memory|context|instructions|guidelines|rules|system\s+prompt)\b',
                "IO-005",
                "Context erase and safety memory reset attempt",
                0.90,
                "HIGH"
            )
        ]

    def detect(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> List[AttackSignal]:
        signals = []
        for pattern, rule_id, desc, conf, sev in self.rules:
            matches = self.find_matches(pattern, text, rule_id, self.attack_type, desc, conf, sev)
            signals.extend(matches)
        return signals
