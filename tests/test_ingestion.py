"""Unit tests for ingestion adapters and security limits (§5.1, §8.3)."""

import io
import json
import zipfile
import pytest

from aegis.ingestion.base import OversizeContentError, ZipBombError
from aegis.ingestion.registry import extract, IngestionRegistry
from aegis.models import InputSource
from aegis.policy.config import PolicyConfig, LimitsConfig


def test_user_message_adapter():
    source, segs = extract("Hello AI, summarize this.", source=InputSource.USER_MESSAGE)
    assert source == InputSource.USER_MESSAGE
    assert len(segs) == 1
    assert segs[0].origin == "visible"
    assert segs[0].text == "Hello AI, summarize this."


def test_oversize_content_rejection():
    # Configure tiny 100-byte limit
    tight_policy = PolicyConfig(limits=LimitsConfig(max_upload_bytes=100))
    large_input = "A" * 200

    with pytest.raises(OversizeContentError):
        extract(large_input, source=InputSource.USER_MESSAGE, policy=tight_policy)


def test_docx_zip_bomb_rejection():
    # Create an archive whose uncompressed size exceeds max_zip_uncompressed_bytes
    tight_policy = PolicyConfig(limits=LimitsConfig(max_zip_uncompressed_bytes=1000))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # Write 5000 bytes of zeros (compresses to ~20 bytes)
        z.writestr("word/document.xml", b"0" * 5000)

    with pytest.raises(ZipBombError):
        extract(buf.getvalue(), source=InputSource.DOCX, policy=tight_policy)


def test_json_depth_limit_rejection():
    tight_policy = PolicyConfig(limits=LimitsConfig(max_json_depth=3))
    # Nesting depth 5
    nested = {"a": {"b": {"c": {"d": {"e": "too deep"}}}}}

    with pytest.raises(OversizeContentError):
        extract(json.dumps(nested), source=InputSource.API_RESPONSE, policy=tight_policy)


def test_source_auto_detection():
    registry = IngestionRegistry()

    # PDF detection by magic bytes
    pdf_bytes = b"%PDF-1.4 header..."
    assert registry.detect_source(pdf_bytes) == InputSource.PDF

    # Image PNG detection by magic bytes
    png_bytes = b"\x89PNG\r\n\x1a\n\x00..."
    assert registry.detect_source(png_bytes) == InputSource.IMAGE

    # HTML detection by structure
    html_str = "<!DOCTYPE html><html><body>Test</body></html>"
    assert registry.detect_source(html_str) == InputSource.HTML

    # Email detection by RFC 822 headers
    email_str = "From: alice@test.com\nTo: bob@test.com\nSubject: Hi\n\nBody"
    assert registry.detect_source(email_str) == InputSource.EMAIL

    # API response JSON detection
    json_str = '{"status": "ok", "items": [1, 2, 3]}'
    assert registry.detect_source(json_str) == InputSource.API_RESPONSE

    # Source code detection by extension
    py_code = "def foo():\n    return 42\n"
    assert registry.detect_source(py_code, filename="script.py") == InputSource.SOURCE_CODE


def test_api_xml_parsing():
    xml_data = '<?xml version="1.0"?><response><item id="1">Order Placed</item></response>'
    source, segs = extract(xml_data, source=InputSource.API_RESPONSE)
    assert source == InputSource.API_RESPONSE
    texts = [s.text for s in segs]
    assert "Order Placed" in texts
    assert "1" in texts
