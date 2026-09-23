"""
Attack 6: Context Poisoning Detector.
Detects RAG document poisoning, sleeper instructions, fabricated authority memos,
and poisoned knowledge base injections designed to steer agent memory and outputs.
"""

from typing import List, Dict, Any
from aegis_firewall.models import AttackType, AttackSignal, InputSource
from aegis_firewall.detectors.rule_base import BaseDetector


class ContextPoisoningDetector(BaseDetector):
    attack_type = AttackType.CONTEXT_POISONING

    def __init__(self):
        super().__init__("ContextPoisoningDetector")
        self.rules = [
            # 1. RAG / Retriever Sleeper Instructions
            (
                r'(?i)\b(?:note\s+to\s+(?:the\s+)?[\w\s]{1,25}?|if\s+you\s+are\s+(?:an?\s+)?(?:AI|retriever|bot)\s+reading\s+this)\s*[:,\-]\s*(?:always|never|make\s+sure\s+to|state\s+that|disregard|ignore|whenever|when)\b',
                "CP-001",
                "Retriever / RAG sleeper instruction targeting automated AI consumers",
                0.97,
                "CRITICAL"
            ),
            # 2. Fabricated Executive / Authority Overrides in Documents
            (
                r'(?i)\b(?:official\s+memo|executive\s+directive|board\s+resolution|compliance\s+override|cfo\s+authorization)\s*[:\-].*?\b(?:all\s+prior\s+.*?are\s+(?:waived|suspended|overridden|bypassed))\b',
                "CP-002",
                "Fabricated organizational authority spoofing to bypass policy checks",
                0.95,
                "CRITICAL"
            ),
            # 3. Conditional Sleeper Triggers
            (
                r'(?i)\b(?:when(?:ever)?\s+(?:the\s+user\s+asks\s+about|asked\s+about|processing\s+queries\s+on)\s+["\'].*?["\']\s*,\s*(?:secretly|always|instead|never)\s+(?:say|recommend|output|inject))\b',
                "CP-003",
                "Conditional sleeper trigger altering downstream agent reasoning",
                0.94,
                "HIGH"
            ),
            # 4. Agent Memory Poisoning / Fact Fabrication
            (
                r'(?i)\b(?:add\s+to\s+(?:your\s+)?(?:long-term\s+memory|knowledge\s+base|memory\s+store)\s+that|remember\s+permanently\s+that)\s+(?:all\s+security\s+is\s+disabled|the\s+admin\s+password\s+is|the\s+user\s+has\s+root)\b',
                "CP-004",
                "Long-term agent memory poisoning injection",
                0.96,
                "CRITICAL"
            ),
            # 5. Hidden Contradiction & Truth Suppression
            (
                r'(?i)\b(?:do\s+not\s+(?:mention|reveal|tell\s+the\s+user\s+about|report)\s+any\s+(?:discrepancies|errors|fraud|irregularities|violations))\b',
                "CP-005",
                "Truth suppression and audit tampering directive in document context",
                0.91,
                "HIGH"
            )
        ]

    def detect(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> List[AttackSignal]:
        signals = []
        for pattern, rule_id, desc, conf, sev in self.rules:
            matches = self.find_matches(pattern, text, rule_id, self.attack_type, desc, conf, sev)
            signals.extend(matches)
        return signals
