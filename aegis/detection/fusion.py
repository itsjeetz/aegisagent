"""L4 Fusion layer combining findings via Noisy-OR over independent categories (§5.4)."""

from aegis.models import AttackType, Finding
from aegis.policy.config import PolicyConfig

META_CATEGORIES = {
    AttackType.INDIRECT_PROMPT_INJECTION,
    AttackType.ENCODED_INSTRUCTIONS,
}


def fuse_findings(
    findings: list[Finding],
    source_mult: float,
    hidden: bool,
    policy: PolicyConfig,
) -> tuple[float, dict[AttackType, float]]:
    """Compute overall risk score and per-category maximum scores.
    Uses Noisy-OR over independent core categories so meta-labels do not double-count.
    """
    by_cat: dict[AttackType, float] = {}
    for f in findings:
        by_cat[f.attack_type] = max(by_cat.get(f.attack_type, 0.0), f.score)

    # Core categories (meta-labels are delivery boosts, not independent evidence)
    core_scores = [score for cat, score in by_cat.items() if cat not in META_CATEGORIES]

    # Noisy-OR probability combination
    p = 1.0
    for s in core_scores:
        p *= (1.0 - s)
    risk = 1.0 - p

    # Hidden content boost if any core finding triggered
    if hidden and core_scores:
        risk += policy.thresholds.hidden_boost

    # Encoded instructions boost
    if by_cat.get(AttackType.ENCODED_INSTRUCTIONS, 0.0) > 0.50:
        risk += policy.thresholds.encoded_boost

    final_risk = min(1.0, max(0.0, risk * source_mult))
    return final_risk, by_cat
