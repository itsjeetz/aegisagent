"""L4 Policy Engine deciding firewall actions based on risk and findings (§5.4)."""

from aegis.models import AttackType, Finding, FirewallAction, Trust
from aegis.policy.config import PolicyConfig, get_policy


class PolicyEngine:
    """Evaluates fused risk scores against policy thresholds to determine firewall action (§5.4)."""

    def __init__(self, policy: PolicyConfig | None = None):
        self.policy = policy or get_policy()

    def evaluate(
        self,
        risk: float,
        category_scores: dict[AttackType, float],
        findings: list[Finding],
        trust: Trust,
        has_localizable_spans: bool = True,
        is_escalated: bool = False,
    ) -> FirewallAction:
        """Evaluate decision table (§5.4):
        - risk < allow_below -> ALLOW
        - allow_below <= risk < block_at and localizable spans -> SANITIZE
        - risk >= block_at, or high_severity category >= threshold on untrusted -> BLOCK
        - ambiguity / judge error / strong disagreement -> ESCALATE
        """
        if is_escalated:
            return "ESCALATE"

        # 1. High-severity immediate block check (CREDENTIAL_THEFT, TOOL_ABUSE on untrusted)
        if trust == Trust.UNTRUSTED:
            for high_cat in self.policy.high_severity_categories:
                if category_scores.get(high_cat, 0.0) >= self.policy.high_severity_threshold:
                    return "BLOCK"

        # 2. Risk threshold checks
        if risk >= self.policy.thresholds.block_at:
            return "BLOCK"

        if risk < self.policy.thresholds.allow_below:
            return "ALLOW"

        # 3. Grey-zone between allow_below and block_at
        if has_localizable_spans:
            return "SANITIZE"
        else:
            return "BLOCK"
