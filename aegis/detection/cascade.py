"""Detection cascade orchestrating Rules -> ML Classifier -> LLM Judge (§5.3, §8.3)."""

from typing import Optional

from aegis.detection.base import DetectionContext
from aegis.detection.classifier import MLClassifier
from aegis.detection.instruction_in_data import InstructionInDataDetector
from aegis.detection.judge import LLMJudge
from aegis.detection.rules import RuleDetector
from aegis.models import Finding, Segment
from aegis.policy.config import PolicyConfig, get_policy
from aegis.resilience import TIMEOUTS, run_with_timeout


class DetectionCascade:
    """Orchestrates L3 detection cascade across rules, classifier, and judge (§5.3, §8.3)."""

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

    def _run_rules(
        self, segment: Segment, variants: list, ctx: DetectionContext
    ) -> list[Finding]:
        r_findings = self.rule_detector.detect(segment, variants, ctx)
        iid_findings = self.iid_detector.detect(segment, variants, ctx)
        return r_findings + iid_findings

    def detect(
        self,
        segment: Segment,
        variants: list,
        ctx: DetectionContext,
    ) -> tuple[list[Finding], dict[str, dict]]:
        """Run cascade across enabled layers with timeouts and resilience. Returns (findings, layer_status)."""
        findings: list[Finding] = []
        layer_status: dict[str, dict] = {}

        # 1. Rules and Instruction-in-Data (L3a)
        if self.enable_rules:
            res, degraded, err = run_with_timeout(
                self._run_rules,
                args=(segment, variants, ctx),
                timeout_sec=TIMEOUTS["rules"],
                layer_name="rules",
            )
            if degraded or res is None:
                layer_status["rules"] = {
                    "status": "degraded_error",
                    "error": err or "Rules layer execution failed",
                    "findings_count": 0,
                }
            else:
                findings.extend(res)
                layer_status["rules"] = {
                    "status": "ok",
                    "findings_count": len(res),
                }
        else:
            layer_status["rules"] = {"status": "disabled", "findings_count": 0}

        rule_categories = {f.attack_type for f in findings}
        prior_score = max([f.score for f in findings], default=0.0)

        # 2. ML Classifier (L3b)
        if self.enable_classifier and self.classifier.is_trained:
            res, degraded, err = run_with_timeout(
                self.classifier.detect,
                args=(segment, variants, ctx),
                kwargs={"rule_categories": rule_categories},
                timeout_sec=TIMEOUTS["classifier"],
                layer_name="classifier",
            )
            if degraded or res is None:
                layer_status["classifier"] = {
                    "status": "degraded_error",
                    "error": err or "Classifier layer execution failed",
                    "findings_count": 0,
                }
            else:
                findings.extend(res)
                layer_status["classifier"] = {
                    "status": "ok",
                    "findings_count": len(res),
                }
                if res:
                    prior_score = max(prior_score, max(f.score for f in res))
        else:
            layer_status["classifier"] = {
                "status": "disabled" if not self.enable_classifier else "not_trained",
                "findings_count": 0,
            }

        # 3. LLM Judge on Grey-Zone (L3c)
        if self.enable_judge:
            if self.judge.is_available:
                res, degraded, err = run_with_timeout(
                    self.judge.detect,
                    args=(segment, variants, ctx),
                    kwargs={"prior_score": prior_score},
                    timeout_sec=TIMEOUTS["judge"],
                    layer_name="judge",
                )
                if degraded or res is None:
                    layer_status["judge"] = {
                        "status": "degraded_error",
                        "error": err or "Judge execution failed or timed out",
                        "findings_count": 0,
                    }
                else:
                    findings.extend(res)
                    layer_status["judge"] = {
                        "status": "ok",
                        "findings_count": len(res),
                    }
            else:
                layer_status["judge"] = {
                    "status": "degraded_offline",
                    "findings_count": 0,
                }
        else:
            layer_status["judge"] = {"status": "disabled", "findings_count": 0}

        return findings, layer_status
