"""Operational endpoints: audit, metrics, feedback, policy, guards, agent sandbox (§10)."""

import json
from pathlib import Path
from typing import Any, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from aegis.guard.egress import get_egress_guard
from aegis.guard.memory import get_memory_guard
from aegis.guard.tool_guard import GuardContext, get_tool_guard
from aegis.observability.audit import get_audit_logger
from aegis.observability.metrics import get_metrics_tracker
from aegis.policy.config import get_policy, save_policy
from aegis.train import (
    add_feedback,
    approve_feedback,
    get_review_queue,
    reject_feedback,
    retrain_model,
)
from agent.victim import run_scenario

router = APIRouter(prefix="/api", tags=["ops"])


# -------------------------------------------------------------------------
# Audit and Metrics (§8.1, §10)
# -------------------------------------------------------------------------

@router.get("/audit")
def query_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    source: Optional[str] = None,
    action: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Query structured firewall audit records."""
    audit_logger = get_audit_logger()
    return audit_logger.query(limit=limit, offset=offset, source=source, action=action)


@router.get("/metrics")
def get_system_metrics() -> dict[str, Any]:
    """Retrieve aggregate firewall performance metrics and percentiles."""
    metrics_tracker = get_metrics_tracker()
    return metrics_tracker.get_metrics()


# -------------------------------------------------------------------------
# Feedback Loop and Retraining (§8.2, §10)
# -------------------------------------------------------------------------

class FeedbackSubmission(BaseModel):
    request_id: str
    label: str  # "false_positive" or "false_negative"
    note: str = ""
    content: Optional[str] = None


@router.post("/feedback")
def submit_feedback_item(payload: FeedbackSubmission) -> dict[str, Any]:
    """Submit a false positive / false negative finding to the review queue."""
    if payload.label not in ("false_positive", "false_negative"):
        raise HTTPException(status_code=400, detail="Label must be 'false_positive' or 'false_negative'")

    item_id = add_feedback(
        request_id=payload.request_id,
        label=payload.label,
        note=payload.note,
        content=payload.content,
    )
    return {"id": item_id, "status": "pending", "request_id": payload.request_id}


@router.get("/review-queue")
def list_review_queue(status: Optional[str] = None) -> list[dict[str, Any]]:
    """List pending or approved review queue items."""
    return get_review_queue(status=status)


@router.post("/review-queue/{item_id}/approve")
def approve_review_item(item_id: int) -> dict[str, Any]:
    """Approve a review queue item for future model retraining."""
    success = approve_feedback(item_id)
    if not success:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"id": item_id, "status": "approved"}


@router.post("/review-queue/{item_id}/reject")
def reject_review_item(item_id: int) -> dict[str, Any]:
    """Reject a review queue item."""
    success = reject_feedback(item_id)
    if not success:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"id": item_id, "status": "rejected"}


@router.post("/train")
def trigger_retraining() -> dict[str, Any]:
    """Trigger retraining of the ML classifier with approved feedback items."""
    try:
        report = retrain_model()
        return {"status": "success", "report": report}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Retraining failed: {exc}")


# -------------------------------------------------------------------------
# Policy Configuration (§4, §10)
# -------------------------------------------------------------------------

@router.get("/policy")
def get_current_policy() -> dict[str, Any]:
    """Read active policy thresholds, multipliers, and limits."""
    return get_policy().model_dump()


@router.put("/policy")
def update_firewall_policy(policy_data: dict[str, Any]) -> dict[str, Any]:
    """Hot-reload and persist updated firewall policy settings."""
    try:
        updated = save_policy(policy_data)
        return {"status": "updated", "policy": updated.model_dump()}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid policy schema: {exc}")


# -------------------------------------------------------------------------
# Guard Check Endpoints (§6, §10)
# -------------------------------------------------------------------------

class ToolGuardCheckRequest(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    session_id: str


@router.post("/guard/tool-call")
def check_tool_call(payload: ToolGuardCheckRequest) -> dict[str, Any]:
    """Check tool execution against tool tiers and taint state."""
    tool_guard = get_tool_guard()
    ctx = GuardContext(session_id=payload.session_id)
    res = tool_guard.check(payload.tool, payload.args, ctx)
    return {
        "tool": payload.tool,
        "decision": res.action,
        "reason": res.reason,
        "tier": res.tier.value,
    }


class EgressCheckRequest(BaseModel):
    text: str
    session_id: Optional[str] = None


@router.post("/guard/output")
def check_agent_output(payload: EgressCheckRequest) -> dict[str, Any]:
    """Check agent output for credentials, canary exfiltration, or leaked prompts."""
    egress_guard = get_egress_guard()
    verdict = egress_guard.scan_output(payload.text, payload.session_id or "")
    return {
        "action": verdict.action,
        "text": verdict.text,
        "reasons": verdict.reasons,
        "blocked_canary": verdict.blocked_canary,
        "findings_count": len(verdict.findings),
    }


class MemoryCheckRequest(BaseModel):
    text: str
    source: str = "user_message"
    session_id: Optional[str] = None


@router.post("/guard/memory-write")
def check_memory_write(payload: MemoryCheckRequest) -> dict[str, Any]:
    """Inspect prospective memory writes for context poisoning or authority spoofing."""
    from aegis.models import InputSource
    try:
        src = InputSource(payload.source)
    except Exception:
        src = InputSource.USER_MESSAGE
    memory_guard = get_memory_guard()
    verdict = memory_guard.check_memory_write(payload.text, source=src, session_id=payload.session_id or "")
    return {
        "action": verdict.action,
        "sanitized_text": verdict.sanitized_text,
        "reasons": verdict.reasons,
        "findings_count": len(verdict.findings),
    }


# -------------------------------------------------------------------------
# Agent Sandbox & Eval Runs (§7, §9, §10)
# -------------------------------------------------------------------------

class AgentRunPayload(BaseModel):
    scenario_id: str
    protected: bool = True


@router.post("/agent/run")
def run_victim_agent_scenario(payload: AgentRunPayload) -> dict[str, Any]:
    """Execute a victim agent scenario (S1-S9, B1-B3) unprotected or protected."""
    try:
        report = run_scenario(payload.scenario_id, protected=payload.protected)
        return {
            "scenario_id": report.scenario_id,
            "attack_type": report.attack_type,
            "carrier": report.carrier,
            "technique": report.technique,
            "protected": report.protected,
            "attack_succeeded": report.attack_succeeded,
            "benign_task_succeeded": report.benign_task_succeeded,
            "tool_calls_attempted": report.tool_calls_attempted,
            "tool_calls_blocked": report.tool_calls_blocked,
            "canary_leaked": report.canary_leaked,
            "final_response": report.final_response,
            "execution_log": report.execution_log,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scenario execution failed: {exc}")


@router.get("/eval/latest")
def get_latest_eval_report() -> dict[str, Any]:
    """Retrieve the latest evaluation report from disk."""
    report_file = Path("reports/report.json")
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="No evaluation report found. Run evaluation first.")
    try:
        return json.loads(report_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error reading report: {exc}")
