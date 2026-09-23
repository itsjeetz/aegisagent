"""Rule-based prompt injection detector with offset mapping and meta-label generation (§5.3)."""

from typing import TYPE_CHECKING
from aegis.detection.base import DetectionContext
from aegis.detection.patterns import ALL_RULE_PATTERNS
from aegis.models import AttackType, Finding, Segment, Trust
from aegis.normalize.deobfuscate import Variant
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class RuleDetector:
    """Evaluates regex pattern families across segment variants and generates findings (§5.3)."""

    def __init__(self, policy: "PolicyConfig | None" = None):
        self.policy = policy or get_policy()
        self.patterns = ALL_RULE_PATTERNS

    def detect(
        self,
        segment: Segment,
        variants: list[Variant],
        ctx: DetectionContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_keys: set[tuple[AttackType, tuple[int, int] | None, str]] = set()

        for variant in variants:
            mt = variant.mapped_text
            text = mt.text
            v_chain = variant.chain

            # Check for high-risk Unicode Tag hiding
            if "unicode_tags" in v_chain:
                # Unicode tags carrying ASCII is a strong signal of obfuscated instructions
                key = (AttackType.ENCODED_INSTRUCTIONS, None, "unicode_tags")
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(
                        Finding(
                            attack_type=AttackType.ENCODED_INSTRUCTIONS,
                            score=0.85,
                            segment_id=segment.id,
                            span_original=(0, len(segment.text)),
                            evidence="Unicode tags (U+E0000) carrying hidden ASCII",
                            detector="unicode_tags_high",
                            layer="rules",
                            variant_chain=v_chain,
                        )
                    )

            # Match all regex patterns
            for pat in self.patterns:
                for m in pat.regex.finditer(text):
                    orig_span = mt.to_original(m.start(), m.end())
                    evidence = m.group(0)[:120]
                    key = (pat.attack_type, orig_span, pat.id)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)

                    base_finding = Finding(
                        attack_type=pat.attack_type,
                        score=pat.weight,
                        segment_id=segment.id,
                        span_original=orig_span,
                        evidence=evidence,
                        detector=pat.id,
                        layer="rules",
                        variant_chain=v_chain,
                    )
                    findings.append(base_finding)

                    # Meta-label 1: ENCODED_INSTRUCTIONS if finding came from a non-original variant
                    if v_chain:
                        enc_key = (AttackType.ENCODED_INSTRUCTIONS, orig_span, "encoded_meta")
                        if enc_key not in seen_keys:
                            seen_keys.add(enc_key)
                            findings.append(
                                Finding(
                                    attack_type=AttackType.ENCODED_INSTRUCTIONS,
                                    score=min(1.0, pat.weight + 0.10),
                                    segment_id=segment.id,
                                    span_original=orig_span,
                                    evidence=evidence,
                                    detector="encoded_instructions_meta",
                                    layer="rules",
                                    variant_chain=v_chain,
                                )
                            )

                    # Meta-label 2: INDIRECT_PROMPT_INJECTION if delivered on an untrusted source
                    if ctx and ctx.trust == Trust.UNTRUSTED:
                        ind_key = (AttackType.INDIRECT_PROMPT_INJECTION, orig_span, "indirect_meta")
                        if ind_key not in seen_keys:
                            seen_keys.add(ind_key)
                            findings.append(
                                Finding(
                                    attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
                                    score=min(1.0, pat.weight * 0.90),
                                    segment_id=segment.id,
                                    span_original=orig_span,
                                    evidence=evidence,
                                    detector="indirect_prompt_meta",
                                    layer="rules",
                                    variant_chain=v_chain,
                                )
                            )

        return findings
