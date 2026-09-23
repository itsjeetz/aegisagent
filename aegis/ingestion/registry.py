"""Ingestion adapter registry, source detection, and extraction router (§5.1)."""

import io
import json
import re
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from aegis.ingestion.api_json import ApiResponseAdapter
from aegis.ingestion.base import BaseAdapter, IngestionError, UnsupportedFormatError
from aegis.ingestion.code import SourceCodeAdapter
from aegis.ingestion.docx import DocxAdapter
from aegis.ingestion.email import EmailAdapter
from aegis.ingestion.html import HtmlAdapter
from aegis.ingestion.image_ocr import ImageOcrAdapter
from aegis.ingestion.markdown import MarkdownAdapter
from aegis.ingestion.ocr_text import OcrTextAdapter
from aegis.ingestion.pdf import PdfAdapter
from aegis.ingestion.text import UserMessageAdapter
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class IngestionRegistry:
    """Registry maintaining instances of all 11 format adapters."""

    def __init__(self):
        self._adapters: dict[InputSource, BaseAdapter] = {
            InputSource.USER_MESSAGE: UserMessageAdapter(),
            InputSource.WEB_PAGE: HtmlAdapter(is_web_page=True),
            InputSource.HTML: HtmlAdapter(is_web_page=False),
            InputSource.MARKDOWN: MarkdownAdapter(),
            InputSource.PDF: PdfAdapter(),
            InputSource.DOCX: DocxAdapter(),
            InputSource.EMAIL: EmailAdapter(),
            InputSource.API_RESPONSE: ApiResponseAdapter(),
            InputSource.OCR_TEXT: OcrTextAdapter(),
            InputSource.SOURCE_CODE: SourceCodeAdapter(),
            InputSource.IMAGE: ImageOcrAdapter(),
        }

    def get_adapter(self, source: InputSource) -> BaseAdapter:
        adapter = self._adapters.get(source)
        if not adapter:
            raise UnsupportedFormatError(f"No ingestion adapter registered for source: {source}")
        return adapter

    def detect_source(
        self,
        data: bytes | str,
        filename: str | None = None,
        explicit_source: InputSource | None = None,
    ) -> InputSource:
        """Detect input format by magic bytes/MIME first, structure second, extension third (§5.1)."""
        if explicit_source:
            return explicit_source

        raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
        ext = Path(filename).suffix.lower() if filename else ""

        # 1. Magic bytes detection
        if raw_bytes.startswith(b"%PDF-"):
            return InputSource.PDF

        if (
            raw_bytes.startswith(b"\x89PNG\r\n\x1a\n")
            or raw_bytes.startswith(b"\xff\xd8\xff")
            or raw_bytes.startswith(b"GIF87a")
            or raw_bytes.startswith(b"GIF89a")
            or (raw_bytes.startswith(b"RIFF") and b"WEBP" in raw_bytes[:16])
        ):
            return InputSource.IMAGE

        if raw_bytes.startswith(b"PK\x03\x04"):
            # Check if this zip archive is a DOCX file
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
                    if "word/document.xml" in z.namelist():
                        return InputSource.DOCX
            except Exception:
                pass

        # 2. Structural text checks
        head_sample = raw_bytes[:2048]
        try:
            head_str = head_sample.decode("utf-8", errors="ignore").strip()
        except Exception:
            head_str = ""

        # Email RFC 822 detection
        email_header_pat = re.compile(
            r"^(?:From|To|Subject|Date|Return-Path|Received|MIME-Version):\s+", re.MULTILINE | re.IGNORECASE
        )
        if ext in (".eml", ".msg") or (
            len(email_header_pat.findall(head_str)) >= 2 and "\n\n" in head_str
        ):
            return InputSource.EMAIL

        # HTML / Web page detection
        head_str_lower = head_str.lower()
        if (
            head_str_lower.startswith("<!doctype html")
            or "<html" in head_str_lower
            or "<head" in head_str_lower
            or "<body" in head_str_lower
        ):
            if ext in (".html", ".htm"):
                return InputSource.HTML
            return InputSource.HTML

        # JSON / XML API Response
        if head_str.startswith("{") or head_str.startswith("["):
            try:
                full_text = raw_bytes.decode("utf-8")
                json.loads(full_text)
                return InputSource.API_RESPONSE
            except Exception:
                pass

        if head_str.startswith("<?xml") or (
            head_str.startswith("<") and not head_str_lower.startswith("<html")
        ):
            if ext == ".xml" or "<api" in head_str_lower or "<response" in head_str_lower:
                return InputSource.API_RESPONSE

        # Source code detection
        if ext in (
            ".py",
            ".js",
            ".ts",
            ".c",
            ".cpp",
            ".h",
            ".java",
            ".go",
            ".rs",
            ".rb",
            ".php",
            ".sh",
            ".bash",
            ".sql",
        ):
            return InputSource.SOURCE_CODE

        if head_str.startswith("#!") or re.search(r"^(?:import |from \w+ import |def \w+\(|class \w+)", head_str, re.MULTILINE):
            return InputSource.SOURCE_CODE

        # Markdown detection
        if ext in (".md", ".markdown") or re.search(r"^#{1,6}\s+", head_str, re.MULTILINE) or re.search(r"\[.+\]\(.+\)", head_str):
            return InputSource.MARKDOWN

        # OCR text extension
        if ext == ".ocr":
            return InputSource.OCR_TEXT

        # Extension fallbacks
        if ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff"):
            return InputSource.IMAGE
        if ext == ".pdf":
            return InputSource.PDF
        if ext == ".docx":
            return InputSource.DOCX
        if ext in (".html", ".htm"):
            return InputSource.HTML

        # Default fallback
        return InputSource.USER_MESSAGE


_GLOBAL_REGISTRY = IngestionRegistry()


def extract(
    data: bytes | str,
    *,
    source: InputSource | None = None,
    filename: str | None = None,
    policy: "PolicyConfig | None" = None,
) -> tuple[InputSource, list[Segment]]:
    """Extract segments using the auto-detected or explicitly specified format adapter.
    Returns (detected_or_resolved_source, segments).
    """
    resolved_source = _GLOBAL_REGISTRY.detect_source(data, filename, explicit_source=source)
    adapter = _GLOBAL_REGISTRY.get_adapter(resolved_source)
    segments = adapter.extract(data, filename=filename, policy=policy)
    return resolved_source, segments
