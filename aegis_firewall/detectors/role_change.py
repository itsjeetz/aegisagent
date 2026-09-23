"""
Attack 2: Role Change Detector.
Detects persona hijacking, DAN (Do Anything Now), Developer Mode toggles,
and unrestricted actor simulations.
"""

from typing import List, Dict, Any
from aegis_firewall.models import AttackType, AttackSignal, InputSource
from aegis_firewall.detectors.rule_base import BaseDetector


class RoleChangeDetector(BaseDetector):
    attack_type = AttackType.ROLE_CHANGE

    def __init__(self):
        super().__init__("RoleChangeDetector")
        self.rules = [
            # 1. Classic Jailbreak Personas (DAN, EvilGPT, AIM, ChaosGPT, Stanford jailbreaks)
            (
                r'(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:DAN|Do\s+Anything\s+Now|EvilGPT|AIM|ChaosGPT|DUDE|STAN|Mongo|BetterDAN|an\s+unrestricted\s+AI|an\s+unfiltered\s+AI)\b',
                "RC-001",
                "Explicit jailbreak persona assignment (DAN/EvilGPT/AIM)",
                0.99,
                "CRITICAL"
            ),
            # 2. Developer / Maintenance / Debug Mode simulation
            (
                r'(?i)\b(?:enter|enable|activate|switch\s+to)\s+(?:developer\s+mode|maintenance\s+mode|debug\s+mode|god\s+mode|unrestricted\s+mode|jailbreak\s+mode)\b',
                "RC-002",
                "Developer/Debug mode privilege escalation attempt",
                0.95,
                "CRITICAL"
            ),
            # 3. Unconstrained Actor Framing
            (
                r'(?i)\b(?:pretend|simulate|imagine|act\s+as\s+if)\s+(?:you\s+have\s+no\s+(?:rules|filters|morals|ethics|limitations|safety)|there\s+are\s+no\s+restrictions)\b',
                "RC-003",
                "Fictional framing to bypass ethical and safety constraints",
                0.93,
                "HIGH"
            ),
            # 4. Identity Negation and Rebranding
            (
                r'(?i)\b(?:you\s+are\s+no\s+longer\s+(?:an?\s+)?(?:AI|assistant|helpful|language\s+model)|forget\s+you\s+are\s+an\s+AI)\b',
                "RC-004",
                "Identity negation and assistant role stripping",
                0.92,
                "HIGH"
            ),
            # 5. Two-response / Dual Persona pattern
            (
                r'(?i)\b(?:provide\s+two\s+responses|standard\s+response\s+and\s+jailbroken\s+response|output\s+as\s+both\s+\[normal\]\s+and\s+\[jailbroken\])\b',
                "RC-005",
                "Dual persona evasion pattern (jailbroken companion mode)",
                0.96,
                "CRITICAL"
            )
        ]

    def detect(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> List[AttackSignal]:
        signals = []
        for pattern, rule_id, desc, conf, sev in self.rules:
            matches = self.find_matches(pattern, text, rule_id, self.attack_type, desc, conf, sev)
            signals.extend(matches)
        return signals
