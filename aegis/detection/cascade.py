"""Detection cascade orchestrating Rules -> ML Classifier -> LLM Judge (§5.3)."""

from typing import Optional

from aegis.detection.base import DetectionContext
from aegis.detection.classifier import MLClassifier
from aegis.detection.instruction_in_data import InstructionInDataDetector
from aegis.detection.judge import LLMJudge
from aegis.detection.rules import RuleDetector
from aegis.models import Finding, Segment
from aegis.policy.config import PolicyConfig, get_policy


class DetectionCascade:
    """Orchestrates L3 detection cascade across rules, classifier, and judge (§5.3)."""

    def __init__(
        self,
        policy: Optional[PolicyConfig] = None,
        enable_rules: bool = True,
        enable_classifier: bool = True,
        enable_judge: bool = True,
    ):
        self.policy = policy or get_policy()
        self.enable_rules = enable_rules
        self.enable_classifier = enable_classifier
        self.enable_judge = enable_judge

        self.rule_detector = RuleDetector(self.policy)
        self.iid_detector = InstructionInDataDetector(self.policy)
        self.classifier = MLClassifier(policy=self.policy)
        self.judge = LLMJudge(self.policy)

    def detect(
        self,
        segment: Segment,
        variants: list,
        ctx: DetectionContext,
    ) -> tuple[list[Finding], dict[str, dict]]:
        """Run cascade across enabled layers. Returns (findings, layer_status)."""
        findings: list[Finding] = []
        layer_status: dict[str, dict] = {}

        # 1. Rules and Instruction-in-Data (L3a)
        if self.enable_rules:
            r_findings = self.rule_detector.detect(segment, variants, ctx)
            iid_findings = self.iid_detector.detect(segment, variants, ctx)
            findings.extend(r_findings)
            findings.extend(iid_findings)
            layer_status["rules"] = {
                "status": "ok",
                "findings_count": len(r_findings) + len(iid_findings),
            }
        else:
            layer_status["rules"] = {"status": "disabled", "findings_count": 0}

        rule_categories = {f.attack_type for f in findings}
        prior_score = max([f.score for f in findings], default=0.0)

        # 2. ML Classifier (L3b)
        if self.enable_classifier and self.classifier.is_trained:
            c_findings = self.classifier.detect(segment, variants, ctx, rule_categories=rule_categories)
            findings.extend(c_findings)
            layer_status["classifier"] = {
                "status": "ok",
                "findings_count": len(c_findings),
            }
            if c_findings:
                prior_score = max(prior_score, max(f.score for f in c_findings))
        else:
            layer_status["classifier"] = {
                "status": "disabled" if not self.enable_classifier else "not_trained",
                "findings_count": 0,
            }

        # 3. LLM Judge on Grey-Zone (L3c)
        if self.enable_judge:
            if self.judge.is_available:
                j_findings = self.judge.detect(segment, variants, ctx, prior_score=prior_score)
                findings.extend(j_findings)
                layer_status["judge"] = {
                    "status": "ok",
                    "findings_count": len(j_findings),
                }
            else:
                layer_status["judge"] = {
                    "status": "degraded_offline",
                    "findings_count": 0,
                }
        else:
            layer_status["judge"] = {"status": "disabled", "findings_count": 0}

        return findings, layer_status
