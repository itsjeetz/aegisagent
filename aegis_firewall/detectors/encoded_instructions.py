"""
Attack 8: Encoded Instructions Detector.
Detects obfuscated, encoded, and encrypted directives (Base64, Hexadecimal,
ROT13, Binary, Leetspeak, Unicode Tag Smuggling) and decode-and-execute requests.
"""

import re
from typing import List, Dict, Any
from aegis_firewall.models import AttackType, AttackSignal, InputSource
from aegis_firewall.detectors.rule_base import BaseDetector


class EncodedInstructionsDetector(BaseDetector):
    attack_type = AttackType.ENCODED_INSTRUCTIONS

    def __init__(self):
        super().__init__("EncodedInstructionsDetector")
        self.rules = [
            # 1. Decode & Execute Commands
            (
                r'(?i)\b(?:decode|decrypt|unhash|de-obfuscate)\s+(?:the\s+following|this)?\s*(?:base64|hex|rot13|binary|string|payload)\s+(?:and\s+)?(?:execute|run|follow|comply|obey|output)\b',
                "ENC-001",
                "Explicit decode-and-execute directive commanding AI to evaluate encoded instructions",
                0.98,
                "CRITICAL"
            ),
            # 2. Raw Base64 Block with Injection Indicator
            (
                r'(?i)\[DECODED_BASE64:\s*.*?\]|\b[A-Za-z0-9+/]{24,}={0,2}\b',
                "ENC-002",
                "Encoded Base64 payload block detected in input stream",
                0.90,
                "HIGH"
            ),
            # 3. Raw Hexadecimal Block with Injection Indicator
            (
                r'(?i)\[DECODED_HEX:\s*.*?\]|(?:\\x[0-9a-fA-F]{2}){4,}',
                "ENC-003",
                "Hexadecimal encoded instruction sequence detected",
                0.92,
                "HIGH"
            ),
            # 4. ROT13 Cipher Indicator
            (
                r'(?i)\[DECODED_ROT13:\s*.*?\]',
                "ENC-004",
                "ROT13 cipher payload resolved by deobfuscation engine",
                0.94,
                "CRITICAL"
            ),
            # 5. Canonicalized Leetspeak Indicator
            (
                r'(?i)\[CANONICAL_LEETSPEAK:\s*.*?\]',
                "ENC-005",
                "Leetspeak obfuscated directive resolved to adversarial keywords",
                0.91,
                "HIGH"
            ),
            # 6. Binary String Stream
            (
                r'\b(?:[01]{8}\s+){4,}[01]{8}\b',
                "ENC-006",
                "Binary encoded byte stream detected in text",
                0.93,
                "HIGH"
            )
        ]

    def detect(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> List[AttackSignal]:
        signals = []
        for pattern, rule_id, desc, conf, sev in self.rules:
            matches = self.find_matches(pattern, text, rule_id, self.attack_type, desc, conf, sev)
            signals.extend(matches)
        return signals
