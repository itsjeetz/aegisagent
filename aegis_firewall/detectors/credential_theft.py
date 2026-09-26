"""
Attack 5: Credential Theft Detector.
Detects phishing prompts, fake session expired alerts, password harvesting directives,
and lures designed to trick the agent into requesting user credentials or 2FA codes.
"""

from typing import List, Dict, Any
from aegis_firewall.models import AttackType, AttackSignal, InputSource
from aegis_firewall.detectors.rule_base import BaseDetector


class CredentialTheftDetector(BaseDetector):
    attack_type = AttackType.CREDENTIAL_THEFT

    def __init__(self):
        super().__init__("CredentialTheftDetector")
        self.rules = [
            # 1. Phishing Alert Lures instructing agent to prompt user for password
            (
                r'(?i)\b(?:ask|prompt|instruct|tell)\s+(?:the\s+)?user\s+to\s+(?:enter|provide|re-enter|input)\s+(?:their|the)\s+(?:[\w\s]{0,15})?(?:password|credentials|login|passcode|secret\s+key|private\s+key)\b',
                "CT-001",
                "Phishing directive forcing agent to harvest user password",
                0.97,
                "CRITICAL"
            ),
            # 2. Fake Session Expiration / Authentication Challenges
            (
                r'(?i)\b(?:session\s+expired|authentication\s+required|security\s+challenge|re-authenticate)\b.*?\b(?:enter|provide|tell\s+user|input)\b.*?\b(?:password|token|pin|otp|mfa|credentials)\b',
                "CT-002",
                "Spoofed authentication challenge / session expiration lure",
                0.96,
                "CRITICAL"
            ),
            # 3. 2FA / OTP Harvesting
            (
                r'(?i)\b(?:ask|request|prompt|extract)\b.*?\b(?:2fa|mfa|otp|authenticator|verification)\b.*?\b(?:code|password|token)\b|\b(?:one-time\s+password|authenticator\s+code)\b',
                "CT-003",
                "Two-Factor Authentication (2FA) / OTP harvesting prompt",
                0.95,
                "CRITICAL"
            ),
            # 4. Cloud & Infrastructure Key Harvesting
            (
                r'(?i)\b(?:provide|share|reveal|output)\s+(?:your\s+)?(?:aws_secret_access_key|private_key|ssh[_-]key|id_rsa|jwt\s+token|bearer\s+token|github_token)\b',
                "CT-004",
                "Infrastructure secret & bearer token harvesting query",
                0.98,
                "CRITICAL"
            ),
            # 5. Phishing URLs with login/auth lure in injected text
            (
                r'(?i)https?://[^\s\'"<>]+(?:login|auth|verify|signin|password-reset|account-update)[^\s\'"<>]*\b',
                "CT-005",
                "Suspicious authentication / password reset link in unauthenticated context",
                0.85,
                "HIGH"
            )
        ]

    def detect(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> List[AttackSignal]:
        signals = []
        for pattern, rule_id, desc, conf, sev in self.rules:
            matches = self.find_matches(pattern, text, rule_id, self.attack_type, desc, conf, sev)
            signals.extend(matches)
        return signals
