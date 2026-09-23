"""AegisAgent Pipeline orchestrating L1 Ingestion through L5 Neutralization (§2, §5)."""

import hashlib
import secrets
import time
from typing import TYPE_CHECKING

from aegis.detection.base import DetectionContext
from aegis.detection.fusion import fuse_findings
from aegis.detection.instruction_in_data import InstructionInDataDetector
from aegis.detection.rules import RuleDetector
from aegis.detection.session import SessionTracker
from aegis.ingestion.registry import extract
from aegis.models import (
    AttackType,
    Finding,
    InputSource,
    Segment,
    Trust,
    Verdict,
)
from aegis.neutralize.envelope import wrap_in_nonce_envelope
from aegis.neutralize.redact import redact_all_segments
from aegis.normalize.deobfuscate import deobfuscate
from aegis.policy.config import PolicyConfig, get_policy
from aegis.policy.engine import PolicyEngine

if TYPE_CHECKING:
    pass


class FirewallPipeline:
    """End-to-end prompt injection firewall pipeline (§2)."""

    def __init__(self, policy: PolicyConfig | None = None):
        self.policy = policy or get_policy()
        self.rule_detector = RuleDetector(self.policy)
        self.iid_detector = InstructionInDataDetector(self.policy)
        self.session_tracker = SessionTracker(policy=self.policy)
        self.policy_engine = PolicyEngine(self.policy)

    def process(
        self,
        content: bytes | str,
        *,
        source: InputSource | None = None,
        filename: str | None = None,
        session_id: str | None = None,
        trust: Trust | None = None,
        neutralize_content: bool = True,
    ) -> Verdict:
        """Process content through L1-L5 layers and return full Verdict."""
        t_start = time.perf_counter()
        timings: dict[str, float] = {}
        layer_status: dict[str, dict] = {}

        # Content hash
        content_bytes = content.encode("utf-8") if isinstance(content, str) else content
        content_sha256 = hashlib.sha256(content_bytes).hexdigest()
        request_id = f"req-{secrets.token_hex(6)}"

        # ----------------------------------------------------
        # L1: Ingestion
        # ----------------------------------------------------
        t0 = time.perf_counter()
        detected_source, segments = extract(content, source=source, filename=filename, policy=self.policy)
        timings["l1_ingestion_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        layer_status["ingestion"] = {"status": "ok", "segments_count": len(segments)}

        # Trust determination: USER for direct user message, UNTRUSTED for all external channels
        resolved_trust = trust or (
            Trust.USER if detected_source == InputSource.USER_MESSAGE else Trust.UNTRUSTED
        )

        all_findings: list[Finding] = []
        hidden_count = sum(1 for s in segments if s.origin == "hidden")

        # ----------------------------------------------------
        # L2 & L3: Normalization and Detection Cascade
        # ----------------------------------------------------
        t_l2_l3 = time.perf_counter()
        for seg in segments:
            # L2: Variants generation
            t_norm = time.perf_counter()
            variants = deobfuscate(seg, policy=self.policy)
            timings.setdefault("l2_normalize_ms", 0.0)
            timings["l2_normalize_ms"] += (time.perf_counter() - t_norm) * 1000

            ctx = DetectionContext(
                request_id=request_id,
                source=detected_source,
                trust=resolved_trust,
                session_id=session_id,
                is_hidden=(seg.origin == "hidden"),
            )

            # L3a: Rules
            rule_findings = self.rule_detector.detect(seg, variants, ctx)
            all_findings.extend(rule_findings)

            # L3a: Instruction-in-data
            iid_findings = self.iid_detector.detect(seg, variants, ctx)
            all_findings.extend(iid_findings)

        # L3d: Session Tracker (if session_id provided)
        if session_id:
            combined_user_text = " ".join(s.text for s in segments if s.text.strip())
            session_findings = self.session_tracker.process_turn(
                session_id,
                combined_user_text,
                all_findings,
                self.rule_detector,
            )
            all_findings.extend(session_findings)

        timings["l2_normalize_ms"] = round(timings.get("l2_normalize_ms", 0.0), 2)
        timings["l3_detection_ms"] = round((time.perf_counter() - t_l2_l3) * 1000 - timings["l2_normalize_ms"], 2)
        layer_status["rules"] = {"status": "ok", "findings_count": len(all_findings)}

        # ----------------------------------------------------
        # L4: Fusion and Policy
        # ----------------------------------------------------
        t_l4 = time.perf_counter()
        source_mult = self.policy.source_multipliers.get(detected_source.value, 1.0)
        is_hidden = hidden_count > 0

        risk, category_scores = fuse_findings(all_findings, source_mult, is_hidden, self.policy)

        # Check localizable spans: can we redact spans or is whole-document redaction needed?
        has_localizable = all(f.span_original is not None for f in all_findings) if all_findings else True
        action = self.policy_engine.evaluate(
            risk=risk,
            category_scores=category_scores,
            findings=all_findings,
            trust=resolved_trust,
            has_localizable_spans=has_localizable,
        )
        timings["l4_fusion_policy_ms"] = round((time.perf_counter() - t_l4) * 1000, 2)
        layer_status["policy"] = {"status": "ok", "action": action, "risk": round(risk, 4)}

        # ----------------------------------------------------
        # L5: Neutralizer
        # ----------------------------------------------------
        t_l5 = time.perf_counter()
        sanitized_text: str | None = None
        envelope_text: str | None = None

        if action == "SANITIZE" or (neutralize_content and has_localizable and all_findings):
            sanitized_text = redact_all_segments(segments, all_findings)
            if resolved_trust == Trust.UNTRUSTED:
                envelope_text = wrap_in_nonce_envelope(
                    sanitized_text,
                    detected_source,
                    request_id=request_id,
                    hidden_segments_removed=hidden_count,
                )
        elif action == "ALLOW":
            raw_text = "\n\n".join(s.text for s in segments if s.text.strip())
            sanitized_text = raw_text
            if resolved_trust == Trust.UNTRUSTED:
                envelope_text = wrap_in_nonce_envelope(
                    raw_text,
                    detected_source,
                    request_id=request_id,
                    hidden_segments_removed=hidden_count,
                )
        else:  # BLOCK or ESCALATE
            sanitized_text = None
            envelope_text = None

        timings["l5_neutralize_ms"] = round((time.perf_counter() - t_l5) * 1000, 2)
        timings["total_pipeline_ms"] = round((time.perf_counter() - t_start) * 1000, 2)

        return Verdict(
            request_id=request_id,
            source=detected_source,
            trust=resolved_trust,
            action=action,
            risk=round(risk, 4),
            category_scores=category_scores,
            findings=all_findings,
            degraded=False,
            layer_status=layer_status,
            sanitized_text=sanitized_text,
            envelope_text=envelope_text,
            timings_ms=timings,
            content_sha256=content_sha256,
        )


_PIPELINE_INSTANCE = FirewallPipeline()


def get_pipeline() -> FirewallPipeline:
    return _PIPELINE_INSTANCE
