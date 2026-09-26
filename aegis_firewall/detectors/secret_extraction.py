"""
Attack 3: Secret Extraction Detector.
Detects attempts to leak system prompts, developer preambles, API keys,
canary tokens, environment variables, or private internal agent memory.
"""

from typing import List, Dict, Any
from aegis_firewall.models import AttackType, AttackSignal, InputSource
from aegis_firewall.detectors.rule_base import BaseDetector


class SecretExtractionDetector(BaseDetector):
    attack_type = AttackType.SECRET_EXTRACTION

    def __init__(self):
        super().__init__("SecretExtractionDetector")
        self.rules = [
            # 1. System Prompt Exfiltration (Verbatim / Repeat / Output)
            (
                r'(?i)\b(?:repeat|print|output|display|show|reveal|echo|dump|recite|leak)\s+(?:the\s+)?(?:system\s+prompt|initial\s+prompt|system\s+instructions|system\s+message|preamble|developer\s+instructions|prompt\s+above)\s*(?:verbatim|in\s+full|completely|word\s+for\s+word)?\b',
                "SE-001",
                "System prompt exfiltration request",
                0.97,
                "CRITICAL"
            ),
            # 2. Pre-conversation Context Extraction
            (
                r'(?i)\b(?:what\s+(?:were|are)\s+(?:the\s+)?(?:initial|first|system|developer|hidden)\s+(?:instructions|prompts|rules|guidelines|words))\b',
                "SE-002",
                "Query probing initial system configuration or developer prompt",
                0.94,
                "HIGH"
            ),
            # 3. Environment Variable & API Key Harvesting
            (
                r'(?i)\b(?:print|show|reveal|extract|dump|exfiltrate|get|output)\s+(?:all\s+)?(?:api[_\s]?keys?|env(?:ironment)?\s*(?:variables?|vars?)?|tokens?|secrets?|credentials?|passwords?|\.env\s+file)\b|\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET|DATABASE_URL)\b',
                "SE-003",
                "Environment variable and API key exfiltration",
                0.98,
                "CRITICAL"
            ),
            # 4. Canary Token Probing
            (
                r'(?i)\b(?:canary\s+token|secret\s+canary|system\s+token|verification\s+token|hidden\s+token)\b',
                "SE-004",
                "Canary token extraction probe",
                0.93,
                "HIGH"
            ),
            # 5. Translation / Encoding Trick for System Prompt Leak
            (
                r'(?i)\b(?:translate|encode|convert)\s+(?:the\s+)?(?:system\s+prompt|above\s+text|initial\s+instructions)\s+(?:into|to)\s+(?:base64|json|hex|spanish|french|pig\s+latin|morse)\b',
                "SE-005",
                "Transformed exfiltration trick targeting system instructions",
                0.95,
                "CRITICAL"
            )
        ]

    def detect(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> List[AttackSignal]:
        signals = []
        for pattern, rule_id, desc, conf, sev in self.rules:
            matches = self.find_matches(pattern, text, rule_id, self.attack_type, desc, conf, sev)
            signals.extend(matches)
        return signals
