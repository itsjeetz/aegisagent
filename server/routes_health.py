"""Health and capabilities check endpoint (§10, §8.4)."""

import os
from pathlib import Path
from fastapi import APIRouter
from aegis.models import HealthResponse

from server.demo_mode import (
    DEFAULT_GENERAL_LIMIT_PER_MINUTE,
    get_demo_manager,
    is_demo_mode,
)

router = APIRouter(prefix="/api", tags=["health"])


def is_ocr_available() -> bool:
    """Check if Tesseract binary is accessible and functional."""
    try:
        import pytesseract

        version = pytesseract.get_tesseract_version()
        return bool(version)
    except Exception:
        return False


def get_classifier_backend() -> str:
    """Check configured and available classifier backend."""
    hf_id = os.environ.get("HF_CLASSIFIER_ID")
    if hf_id:
        return f"hf:{hf_id}"

    if Path("data/models/classifier.joblib").exists() or Path("data/models/clf.joblib").exists():
        return "scikit-learn"
    return "none (untrained)"


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return health status and capabilities of the firewall."""
    ocr_avail = is_ocr_available()
    api_key_set = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    demo_active = is_demo_mode()
    demo_mgr = get_demo_manager()

    # In demo mode, judge is available only if API key is set AND remaining quota > 0
    quota_exhausted = False
    rate_limit = None
    llm_limit = None
    llm_used = None
    llm_rem = None

    if demo_active:
        rate_limit = DEFAULT_GENERAL_LIMIT_PER_MINUTE
        stats = demo_mgr.get_llm_stats()
        llm_limit = stats["limit"]
        llm_used = stats["used"]
        llm_rem = stats["remaining"]
        if llm_rem <= 0:
            quota_exhausted = True

    judge_avail = api_key_set and (not quota_exhausted)
    clf_backend = get_classifier_backend()
    judge_model = os.environ.get("JUDGE_MODEL", "claude-haiku-4-5-20251001")
    agent_model = os.environ.get("AGENT_MODEL", "claude-sonnet-5")
    hf_id = os.environ.get("HF_CLASSIFIER_ID")

    degraded = not ocr_avail or not judge_avail

    return HealthResponse(
        status="ok",
        version="0.1.0",
        ocr_available=ocr_avail,
        classifier_backend=clf_backend,
        judge_available=judge_avail,
        anthropic_key_set=api_key_set,
        judge_model=judge_model,
        agent_model=agent_model,
        hf_classifier_id=hf_id,
        degraded_mode=degraded,
        demo_mode=demo_active,
        rate_limit_per_minute=rate_limit,
        daily_llm_calls_limit=llm_limit,
        daily_llm_calls_used=llm_used,
        daily_llm_calls_remaining=llm_rem,
    )
