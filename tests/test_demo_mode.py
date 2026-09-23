"""Tests for DEMO_MODE=1 protections, rate limiting, quotas, and endpoint restrictions (§10)."""

import os
from fastapi.testclient import TestClient
import pytest

from aegis.models import InputSource, Trust, Verdict
from aegis.observability.audit import AuditLogger
from aegis.policy.config import load_policy
from aegis.resilience import get_max_image_pixels, get_max_pdf_pages, get_max_upload_bytes, validate_input_limits
from server.demo_mode import get_demo_manager
from server.main import app


@pytest.fixture(autouse=True)
def reset_demo_state(monkeypatch):
    """Ensure clean demo state before each test."""
    import aegis.policy.config as pol_cfg
    pol_cfg._CACHED_POLICY = None
    pol_cfg._CACHED_POLICY_DEMO = None
    mgr = get_demo_manager()
    mgr.reset_for_tests()
    yield
    pol_cfg._CACHED_POLICY = None
    pol_cfg._CACHED_POLICY_DEMO = None
    mgr.reset_for_tests()


def test_health_reports_demo_mode(monkeypatch):
    """Verify /api/health accurately reflects DEMO_MODE=1 and quotas."""
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_MAX_DAILY_LLM_CALLS", "150")

    client = TestClient(app)
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()

    assert data["demo_mode"] is True
    assert data["rate_limit_per_minute"] == 30
    assert data["daily_llm_calls_limit"] == 150
    assert data["daily_llm_calls_used"] == 0
    assert data["daily_llm_calls_remaining"] == 150


def test_ip_rate_limiter_general_endpoint(monkeypatch):
    """Verify general endpoints enforce 30 requests/minute per IP."""
    monkeypatch.setenv("DEMO_MODE", "1")
    client = TestClient(app)

    # 30 requests should succeed
    for i in range(30):
        res = client.get("/api/metrics", headers={"X-Forwarded-For": "198.51.100.1"})
        assert res.status_code == 200, f"Request {i+1} failed"

    # 31st request from same IP should receive 429 Too Many Requests
    res = client.get("/api/metrics", headers={"X-Forwarded-For": "198.51.100.1"})
    assert res.status_code == 429
    data = res.json()
    assert "Rate limit exceeded" in data["detail"]
    assert "Retry-After" in res.headers

    # A different IP should still be allowed
    res_other = client.get("/api/metrics", headers={"X-Forwarded-For": "198.51.100.2"})
    assert res_other.status_code == 200


def test_ip_rate_limiter_strict_agent_endpoint(monkeypatch):
    """Verify strict endpoints (/api/agent/run) enforce 5 requests/minute."""
    monkeypatch.setenv("DEMO_MODE", "1")
    client = TestClient(app)

    # 5 requests should succeed
    for i in range(5):
        res = client.post(
            "/api/agent/run",
            json={"scenario_id": "B1", "protected": True},
            headers={"X-Forwarded-For": "203.0.113.5"},
        )
        assert res.status_code == 200, f"Run {i+1} failed"

    # 6th request should be blocked with 429
    res = client.post(
        "/api/agent/run",
        json={"scenario_id": "B1", "protected": True},
        headers={"X-Forwarded-For": "203.0.113.5"},
    )
    assert res.status_code == 429
    assert res.json()["limit_per_minute"] == 5


def test_demo_mode_disabled_endpoints(monkeypatch):
    """Verify write, training, policy, eval, and red-team endpoints return 403 Forbidden in demo mode."""
    monkeypatch.setenv("DEMO_MODE", "1")
    client = TestClient(app)

    # 1. PUT /api/policy
    res = client.put("/api/policy", json={"version": "3.0"})
    assert res.status_code == 403
    assert "disabled in public demo mode" in res.json()["detail"]

    # 2. POST /api/train
    res = client.post("/api/train")
    assert res.status_code == 403
    assert "disabled in public demo mode" in res.json()["detail"]

    # 3. POST /api/review-queue/1/approve
    res = client.post("/api/review-queue/1/approve")
    assert res.status_code == 403

    # 4. POST /api/review-queue/1/reject
    res = client.post("/api/review-queue/1/reject")
    assert res.status_code == 403

    # 5. POST /api/eval/run
    res = client.post("/api/eval/run")
    assert res.status_code == 403
    assert "disabled in public demo mode" in res.json()["detail"]

    # 6. POST /api/redteam/run
    res = client.post("/api/redteam/run")
    assert res.status_code == 403


def test_upload_caps_in_demo_mode(monkeypatch):
    """Verify upload limits tighten to 2 MB, 20 pages, and 5 MP in DEMO_MODE."""
    monkeypatch.setenv("DEMO_MODE", "1")

    assert get_max_upload_bytes() == 2 * 1024 * 1024
    assert get_max_pdf_pages() == 20
    assert get_max_image_pixels() == 5_000_000

    pol = load_policy()
    assert pol.limits.max_upload_bytes == 2 * 1024 * 1024
    assert pol.limits.max_pdf_pages == 20
    assert pol.limits.max_image_megapixels == 5

    # Valid under 2 MB
    validate_input_limits("Safe small text")

    # Exceeding 2 MB raises ValueError
    oversized = b"A" * (2 * 1024 * 1024 + 10)
    with pytest.raises(ValueError, match="exceeds maximum upload limit of 2097152 bytes"):
        validate_input_limits(oversized)


def test_store_content_disabled_in_demo_mode(monkeypatch, tmp_path):
    """Verify raw uploaded content is never stored in audit_log in demo mode, even if STORE_CONTENT=1."""
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("STORE_CONTENT", "1")  # Attempt to force raw storage

    db_path = tmp_path / "test_demo_audit.sqlite"
    audit = AuditLogger(db_path=db_path)

    verdict = Verdict(
        request_id="req-demo-privacy",
        source=InputSource.USER_MESSAGE,
        trust=Trust.USER,
        action="ALLOW",
        risk=0.1,
        sanitized_text="Redacted safe text",
        content_sha256="abc123sha",
    )

    sensitive_content = "Super Secret Password 12345! Do not leak!"
    audit.log_verdict(verdict, content=sensitive_content)

    logs = audit.query(limit=10)
    assert len(logs) == 1
    # Plain text password should not be stored in excerpt_redacted
    assert "Super Secret Password" not in logs[0]["excerpt_redacted"]
    assert "Redacted safe text" in logs[0]["excerpt_redacted"]


def test_daily_llm_counter_and_fallback(monkeypatch):
    """Verify daily LLM call quota enforcement and graceful fallback."""
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_MAX_DAILY_LLM_CALLS", "2")

    mgr = get_demo_manager()
    assert mgr.can_call_llm() is True

    # Call 1
    assert mgr.record_llm_call() is True
    assert mgr.get_llm_stats()["remaining"] == 1
    assert mgr.can_call_llm() is True

    # Call 2
    assert mgr.record_llm_call() is True
    assert mgr.get_llm_stats()["remaining"] == 0

    # Quota reached: call 3 cannot proceed
    assert mgr.can_call_llm() is False
    assert mgr.record_llm_call() is False


def test_eval_markdown_report_served():
    """Verify GET /api/eval/report-markdown serves the pre-generated EVAL_REPORT.md."""
    client = TestClient(app)
    res = client.get("/api/eval/report-markdown")
    assert res.status_code == 200
    data = res.json()
    assert "markdown" in data
    assert "# AegisAgent Evaluation Report" in data["markdown"]

