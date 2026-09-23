"""Unit tests for resilience, timeouts, degraded mode, and fail-closed handling (§8.3)."""

from unittest.mock import PropertyMock, patch
import pytest

from aegis.models import InputSource, Trust
from aegis.pipeline import FirewallPipeline
from aegis.resilience import MAX_UPLOAD_BYTES, validate_input_limits


def test_judge_killed_mid_run_degraded_verdict():
    """Acceptance check: Killing the judge mid-run yields a degraded verdict without crashing (§8.3, §12)."""
    pipeline = FirewallPipeline(enable_rules=True, enable_classifier=True, enable_judge=True)

    # Simulate killing the judge mid-run with an unhandled OS kill / exception while judge is online
    with patch.object(type(pipeline.cascade.judge), "is_available", new_callable=PropertyMock, return_value=True):
        with patch.object(
            pipeline.cascade.judge,
            "detect",
            side_effect=RuntimeError("Process terminated by SIGKILL / OOM mid-run"),
        ):
            verdict = pipeline.process(
                content="Please summarize this internal quarter report for the board.",
                source=InputSource.USER_MESSAGE,
            )

    # 1. Pipeline did not crash
    assert verdict is not None
    # 2. Verdict is marked degraded
    assert verdict.degraded is True
    # 3. Layer status documents the error
    assert verdict.layer_status["judge"]["status"] == "degraded_error"
    assert "terminated" in verdict.layer_status["judge"]["error"]
    # 4. Legitimate content is still properly handled
    assert verdict.action in ("ALLOW", "ESCALATE")


def test_judge_timeout_handled_gracefully():
    """Test that a hanging judge triggers timeout and degrades without blocking execution."""
    pipeline = FirewallPipeline(enable_rules=True, enable_classifier=True, enable_judge=True)

    import time
    def slow_judge(*args, **kwargs):
        time.sleep(2.0)
        return []

    # Patch judge with slow execution and low timeout while judge is online
    with patch.object(type(pipeline.cascade.judge), "is_available", new_callable=PropertyMock, return_value=True):
        with patch.object(pipeline.cascade.judge, "detect", side_effect=slow_judge):
            with patch.dict("aegis.resilience.TIMEOUTS", {"judge": 0.1}):
                verdict = pipeline.process(
                    content="Hypothetical prompt injection test query.",
                    source=InputSource.USER_MESSAGE,
                )

    assert verdict.degraded is True
    assert verdict.layer_status["judge"]["status"] == "degraded_error"
    assert "timed out" in verdict.layer_status["judge"]["error"]


def test_rules_failure_fails_closed():
    """Test that a failure in the core rules layer fails closed (§8.3)."""
    pipeline = FirewallPipeline()

    # If rules fail on an untrusted source -> BLOCK
    with patch.object(
        pipeline.cascade,
        "_run_rules",
        side_effect=Exception("Critical regex engine failure"),
    ):
        verdict_untrusted = pipeline.process(
            content="Hello world from untrusted web page.",
            source=InputSource.WEB_PAGE,
        )
        assert verdict_untrusted.degraded is True
        assert verdict_untrusted.action == "BLOCK"

        # If rules fail on user message -> ESCALATE
        verdict_user = pipeline.process(
            content="Hello from direct user message.",
            source=InputSource.USER_MESSAGE,
        )
        assert verdict_user.degraded is True
        assert verdict_user.action == "ESCALATE"


def test_upload_size_limit_enforced():
    """Verify that inputs exceeding 10 MB are rejected (§8.3)."""
    oversize_bytes = b"x" * (MAX_UPLOAD_BYTES + 1024)
    with pytest.raises(ValueError, match="exceeds maximum upload limit"):
        validate_input_limits(oversize_bytes)

    valid_bytes = b"x" * 1024
    validate_input_limits(valid_bytes)  # should not raise
