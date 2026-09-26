"""Ingestion adapter for pre-extracted OCR text (§5.1)."""

import re
from typing import TYPE_CHECKING
from aegis.ingestion.base import BaseAdapter, OversizeContentError
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class OcrTextAdapter(BaseAdapter):
    """Adapter for OCR_TEXT source with OCR confusion normalization."""

    source = InputSource.OCR_TEXT

    def _apply_ocr_fixes(self, text: str) -> str:
        """Fix common OCR letter/digit confusions in word contexts."""
        s = text
        # 'rn' -> 'm' inside letters
        s = re.sub(r"(?<=[a-zA-Z])rn(?=[a-zA-Z])", "m", s)
        # 'vv' -> 'w'
        s = re.sub(r"(?<=[a-zA-Z])vv(?=[a-zA-Z])", "w", s)
        # 'cl' -> 'd'
        s = re.sub(r"(?<=[a-zA-Z])cl(?=[a-zA-Z])", "d", s)
        # '0' -> 'o' inside words
        s = re.sub(r"(?<=[a-zA-Z])0(?=[a-zA-Z])", "o", s)
        # '1' -> 'l' or 'i' inside words
        s = re.sub(r"(?<=[a-zA-Z])1(?=[a-zA-Z])", "l", s)
        return s

    def extract(
        self,
        data: bytes | str,
        *,
        filename: str | None = None,
        policy: "PolicyConfig | None" = None,
    ) -> list[Segment]:
        pol = policy or get_policy()

        if isinstance(data, bytes):
            if len(data) > pol.limits.max_upload_bytes:
                raise OversizeContentError(
                    f"OCR text size exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            text = data.decode("utf-8", errors="replace")
        else:
            if len(data.encode("utf-8")) > pol.limits.max_upload_bytes:
                raise OversizeContentError(
                    f"OCR text size exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            text = data

        segments = [
            Segment(
                id="seg-ocr-0",
                text=text,
                origin="ocr",
                location="ocr_raw",
                hidden_reason=None,
            )
        ]

        fixed_text = self._apply_ocr_fixes(text)
        if fixed_text != text:
            segments.append(
                Segment(
                    id="seg-ocr-1",
                    text=fixed_text,
                    origin="ocr",
                    location="ocr_fixed",
                    hidden_reason=None,
                )
            )

        return segments
