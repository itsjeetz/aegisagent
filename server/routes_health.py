"""Health and capabilities check endpoint (§10, §8.4)."""

import os
from pathlib import Path
from fastapi import APIRouter
from aegis.models import HealthResponse

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
    judge_avail = api_key_set
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
    )
