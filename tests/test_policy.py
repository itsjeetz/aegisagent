"""Unit tests for policy configuration (§5.4, §8.3)."""

from aegis.models import AttackType, InputSource
from aegis.policy.config import PolicyConfig, load_policy, get_policy


def test_default_policy_loads():
    policy = get_policy()
    assert isinstance(policy, PolicyConfig)
    assert policy.version == "2.0"
    assert policy.thresholds.allow_below == 0.25
    assert policy.thresholds.block_at == 0.85
    assert policy.thresholds.hidden_boost == 0.15


def test_source_multipliers():
    policy = get_policy()
    assert policy.source_multipliers.get(InputSource.USER_MESSAGE.value) == 1.0
    assert policy.source_multipliers.get(InputSource.EMAIL.value) >= 1.1


def test_high_severity_categories():
    policy = get_policy()
    assert AttackType.TOOL_ABUSE in policy.high_severity_categories
    assert AttackType.CREDENTIAL_THEFT in policy.high_severity_categories
    assert policy.high_severity_threshold == 0.60


def test_limits_and_timeouts():
    policy = get_policy()
    assert policy.limits.max_upload_bytes == 10 * 1024 * 1024
    assert policy.limits.max_json_depth == 20
    assert policy.timeouts_seconds.rules <= 1.0
    assert policy.timeouts_seconds.judge <= 10.0
