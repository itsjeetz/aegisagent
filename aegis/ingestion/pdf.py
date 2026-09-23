"""Ingestion adapter for PDF documents (§5.1)."""

import io
from typing import TYPE_CHECKING
import pymupdf

from aegis.ingestion.base import BaseAdapter, OversizeContentError, IngestionError
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class PdfAdapter(BaseAdapter):
    """Adapter for PDF source using PyMuPDF (fitz)."""

    source = InputSource.PDF

    def extract(
        self,
        data: bytes | str,
        *,
        filename: str | None = None,
        policy: "PolicyConfig | None" = None,
    ) -> list[Segment]:
        pol = policy or get_policy()

        if isinstance(data, str):
            raw_bytes = data.encode("utf-8")
        else:
            raw_bytes = data

        if len(raw_bytes) > pol.limits.max_upload_bytes:
            raise OversizeContentError(
                f"PDF size {len(raw_bytes)} exceeds limit of {pol.limits.max_upload_bytes} bytes"
            )

        try:
            doc = pymupdf.open(stream=raw_bytes, filetype="pdf")
        except Exception as e:
            raise IngestionError(f"Failed to parse PDF document: {e}") from e

        if len(doc) > pol.limits.max_pdf_pages:
            doc.close()
            raise OversizeContentError(
                f"PDF page count {len(doc)} exceeds limit of {pol.limits.max_pdf_pages} pages"
            )

        segments: list[Segment] = []
        seg_idx = 0

        # 1. Document metadata
        meta = doc.metadata or {}
        for key in ("title", "author", "subject", "keywords"):
            val = meta.get(key)
            if val and val.strip():
                segments.append(
                    Segment(
                        id=f"seg-pdf-{seg_idx}",
                        text=val.strip(),
                        origin="metadata",
                        location=f"doc.metadata[{key}]",
                        hidden_reason=None,
                    )
                )
                seg_idx += 1

        # 2. Embedded files
        try:
            for emb_name in doc.embfile_names():
                segments.append(
                    Segment(
                        id=f"seg-pdf-{seg_idx}",
                        text=emb_name,
                        origin="metadata",
                        location="doc.embedded_files",
                        hidden_reason=None,
                    )
                )
                seg_idx += 1
        except Exception:
            pass

        # 3. Pages iteration (dict spans)
        for page_num in range(len(doc)):
            page = doc[page_num]
            page_rect = page.rect

            # Annotations
            for annot in page.annots() or []:
                info = annot.info or {}
                content = info.get("content", "").strip()
                if content:
                    segments.append(
                        Segment(
                            id=f"seg-pdf-{seg_idx}",
                            text=content,
                            origin="comment",
                            location=f"page {page_num + 1} annot",
                            hidden_reason="pdf_annotation",
                        )
                    )
                    seg_idx += 1

            # Text spans via page.get_text("dict")
            page_dict = page.get_text("dict")
            for block in page_dict.get("blocks", []):
                if block.get("type") != 0:  # 0 is text block
                    continue

                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        text = span.get("text", "").strip()
                        if not text:
                            continue

                        size = span.get("size", 12.0)
                        color = span.get("color", 0)  # integer sRGB
                        bbox = span.get("bbox", (0, 0, 0, 0))

                        # Determine if hidden
                        hidden_reason = None

                        # Check color: near-white on white background
                        # color is int: 0xRRGGBB
                        r = (color >> 16) & 0xFF
                        g = (color >> 8) & 0xFF
                        b = color & 0xFF
                        if r >= 240 and g >= 240 and b >= 240:
                            hidden_reason = "white_text"

                        # Check size: < 2pt
                        elif size < 2.0:
                            hidden_reason = "tiny_font"

                        # Check bbox outside page boundary
                        elif (
                            bbox[2] < 0
                            or bbox[3] < 0
                            or bbox[0] > page_rect.width
                            or bbox[1] > page_rect.height
                        ):
                            hidden_reason = "offscreen"

                        origin = "hidden" if hidden_reason else "visible"
                        segments.append(
                            Segment(
                                id=f"seg-pdf-{seg_idx}",
                                text=text,
                                origin=origin,
                                location=f"page {page_num + 1}",
                                hidden_reason=hidden_reason,
                            )
                        )
                        seg_idx += 1

        doc.close()

        if not segments:
            segments.append(
                Segment(
                    id=f"seg-pdf-{seg_idx}",
                    text="",
                    origin="visible",
                    location="page 1",
                    hidden_reason=None,
                )
            )

        return segments
