"""Memory guard protecting persistent agent memory from context poisoning and stealth persistence (§6 G3)."""

from dataclasses import dataclass, field
import re
from typing import Literal, Optional

from aegis.models import AttackType, Finding, InputSource

MemoryAction = Literal["ALLOW", "SANITIZE", "BLOCK"]


@dataclass
class MemoryVerdict:
    """Verdict returned by MemoryGuard before writing to persistent agent memory (§6 G3)."""
    action: MemoryAction
    sanitized_text: str
    findings: list[Finding] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


class MemoryGuard:
    """Runtime guard validating and sanitizing content before persistent memory insertion (§6 G3)."""

    PERSISTENCE_PATTERNS = [
        (r"(?:from\s+now\s+on\s+always|always\s+remember\s+that|permanently\s+record|add\s+to\s+(?:your\s+)?memory)", "Persistent memory override phrasing"),
        (r"(?:cfo\s+memo|ceo\s+memo|official\s+it\s+policy|admin\s+has\s+authorized|security\s+team\s+memo)", "Authority spoofing claim"),
        (r"(?:safety\s+restrictions\s+are\s+lifted|prompt\s+injection\s+checks\s+are\s+suspended|treat\s+this\s+as\s+trusted)", "Security relaxation claim"),
        (r"(?:always\s+forward\s+confidential|bypass\s+tool\s+guard)", "Unauthorized tool persistence directive"),
    ]

    def check_memory_write(
        self,
        text: str,
        source: InputSource = InputSource.USER_MESSAGE,
        session_id: str = "",
    ) -> MemoryVerdict:
        """Scan proposed memory text for context poisoning (§6 G3)."""
        reasons: list[str] = []
        findings: list[Finding] = []
        sanitized_text = text
        action: MemoryAction = "ALLOW"

        for pat, desc in self.PERSISTENCE_PATTERNS:
            match = re.search(pat, text, re.IGNORECASE)
            if match:
                reasons.append(desc)
                findings.append(
                    Finding(
                        attack_type=AttackType.CONTEXT_POISONING,
                        score=0.85,
                        segment_id="memory",
                        span_original=(match.start(), match.end()),
                        evidence=match.group(0),
                        detector="memory_poisoning_rule",
                        layer="guard",
                    )
                )

        if findings:
            max_score = max(f.score for f in findings)
            if max_score >= 0.70:
                action = "BLOCK"
                sanitized_text = ""
            elif max_score >= 0.40:
                action = "SANITIZE"
                # Strip matched malicious persistence tokens
                for pat, _ in self.PERSISTENCE_PATTERNS:
                    sanitized_text = re.sub(pat, "[REDACTED:PERSISTENCE]", sanitized_text, flags=re.IGNORECASE)

        return MemoryVerdict(
            action=action,
            sanitized_text=sanitized_text,
            findings=findings,
            reasons=reasons,
        )
