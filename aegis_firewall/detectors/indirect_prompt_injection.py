"""
Attack 9: Indirect Prompt Injection Detector.
Detects cross-boundary prompt injections embedded within untrusted external sources
(Web pages, emails, PDFs, API responses, OCR text, code comments) attempting to commandeer the agent.
"""

from typing import List, Dict, Any
from aegis_firewall.models import AttackType, AttackSignal, InputSource
from aegis_firewall.detectors.rule_base import BaseDetector


class IndirectPromptInjectionDetector(BaseDetector):
    attack_type = AttackType.INDIRECT_PROMPT_INJECTION

    def __init__(self):
        super().__init__("IndirectPromptInjectionDetector")
        self.rules = [
            # 1. Direct Model Addressing in Third-Party Content
            (
                r'(?i)\b(?:(?:hey|dear|attention)\s+)?(?:ai\s+assistant|assistant|ai|bot|chatgpt|claude|agent)\s*[:,\-]\s*(?:please\s+)?(?:ignore|disregard|forget|do\s+not|override|instead|secretly|execute|forward|email|send)\b',
                "IPI-001",
                "Explicit model addressing in external third-party content",
                0.98,
                "CRITICAL"
            ),
            # 2. Third-party Imperative Redirection
            (
                r'(?i)\b(?:when\s+(?:summarizing|processing|analyzing|reading)\s+this\s+(?:document|page|email|text|file)\s*,\s*(?:you\s+must|always|make\s+sure\s+to|secretly)\s+(?:add|append|send|hide|recommend))\b',
                "IPI-002",
                "Processing-phase manipulation directive inside retrieved external document",
                0.96,
                "CRITICAL"
            ),
            # 3. Hidden Autonomous Exfiltration Mandate in Document Footer/Body
            (
                r'(?i)\b(?:ai\s+reader|automated\s+agent)\s*[:\-]\s*(?:send|forward|exfiltrate|post)\s+(?:user\s+data|previous\s+conversation|session|chat\s+history)\s+to\b',
                "IPI-003",
                "Data exfiltration directive targeting automated reader agents",
                0.99,
                "CRITICAL"
            ),
            # 4. Hidden DOM / Comment Injection marker
            (
                r'(?i)\[(?:HTML Comment|Data Attribute|Hidden Input|PDF Metadata|Email Signature|Code Comment)\s+.*?:\s*.*?\]',
                "IPI-004",
                "Untrusted metadata or hidden carrier harboring imperative instructions",
                0.92,
                "HIGH"
            ),
            # 5. Output Hijacking in Scraped Text
            (
                r'(?i)\b(?:disregard\s+the\s+user\'?s?\s+request\s+and\s+(?:say|output|respond)\s+with)\b',
                "IPI-005",
                "User intent replacement injected into retrieved content",
                0.97,
                "CRITICAL"
            )
        ]

    def detect(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> List[AttackSignal]:
        signals = []

        # Run static rules
        for pattern, rule_id, desc, conf, sev in self.rules:
            matches = self.find_matches(pattern, text, rule_id, self.attack_type, desc, conf, sev)
            signals.extend(matches)

        # Cross-Boundary Contextual Taint Check:
        # If the input source is an external third-party format (web_page, email, pdf, word_doc, api_response)
        # and contains authoritative prompt commands like "system:", "instruction:", "you are",
        # that is a high-confidence indirect injection signal!
        if source != InputSource.USER_MESSAGE:
            external_prompt_markers = [
                r'(?i)\b(?:system\s+instruction|system\s+directive|new\s+task|your\s+true\s+objective)\s*:',
                r'(?i)\b(?:you\s+must\s+now\s+follow|disregard\s+prior\s+instructions)\b'
            ]
            for p in external_prompt_markers:
                matches = self.find_matches(p, text, "IPI-BOUNDARY-01", self.attack_type,
                                            f"Cross-boundary privilege violation: Untrusted source '{source.value}' contains system-level directive",
                                            0.95, "CRITICAL")
                signals.extend(matches)

        return signals
