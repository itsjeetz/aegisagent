"""Inspection and neutralization API endpoints supporting JSON and multipart upload (§10)."""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from aegis.models import InputSource, Verdict
from aegis.pipeline import get_pipeline

router = APIRouter(prefix="/api", tags=["inspection"])


class InspectJsonRequest(BaseModel):
    content: str
    source: InputSource | None = None
    session_id: str | None = None


@router.post("/inspect", response_model=Verdict)
async def inspect_content(request: Request) -> Verdict:
    """Analyze input content through firewall cascade and return detailed verdict."""
    pipeline = get_pipeline()
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            body = await request.json()
            payload = InspectJsonRequest.model_validate(body)
            return pipeline.process(
                content=payload.content,
                source=payload.source,
                session_id=payload.session_id,
                neutralize_content=False,
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {e}")

    elif "multipart/form-data" in content_type:
        try:
            form = await request.form()
            file = form.get("file")
            source_str = form.get("source")
            session_id = form.get("session_id")
            src = InputSource(source_str) if source_str else None

            if file is not None and hasattr(file, "read"):
                data = await file.read()
                filename = getattr(file, "filename", None)
                return pipeline.process(
                    content=data,
                    source=src,
                    filename=filename,
                    session_id=str(session_id) if session_id else None,
                    neutralize_content=False,
                )

            content_field = form.get("content")
            if content_field:
                return pipeline.process(
                    content=str(content_field),
                    source=src,
                    session_id=str(session_id) if session_id else None,
                    neutralize_content=False,
                )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to process multipart upload: {e}")

    raise HTTPException(status_code=400, detail="Must provide either JSON content or a multipart file upload.")


@router.post("/neutralize", response_model=Verdict)
async def neutralize_content(request: Request) -> Verdict:
    """Analyze and sanitize input content, returning Verdict with sanitized_text and envelope_text."""
    pipeline = get_pipeline()
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            body = await request.json()
            payload = InspectJsonRequest.model_validate(body)
            return pipeline.process(
                content=payload.content,
                source=payload.source,
                session_id=payload.session_id,
                neutralize_content=True,
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {e}")

    elif "multipart/form-data" in content_type:
        try:
            form = await request.form()
            file = form.get("file")
            source_str = form.get("source")
            session_id = form.get("session_id")
            src = InputSource(source_str) if source_str else None

            if file is not None and hasattr(file, "read"):
                data = await file.read()
                filename = getattr(file, "filename", None)
                return pipeline.process(
                    content=data,
                    source=src,
                    filename=filename,
                    session_id=str(session_id) if session_id else None,
                    neutralize_content=True,
                )

            content_field = form.get("content")
            if content_field:
                return pipeline.process(
                    content=str(content_field),
                    source=src,
                    session_id=str(session_id) if session_id else None,
                    neutralize_content=True,
                )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to process multipart upload: {e}")

    raise HTTPException(status_code=400, detail="Must provide either JSON content or a multipart file upload.")
