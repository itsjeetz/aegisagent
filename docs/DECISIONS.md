# Architectural and Implementation Decisions

This document records technical and design decisions made during the development of AegisAgent, per Section 0 Rule 8 of the implementation plan.

## Decision Log

### DEC-001: Graceful Degradation for Environment & OCR (Phase 0)
- **Context:** On the host development environment (Windows 10/11), `tesseract` binary is not in PATH, and `ANTHROPIC_API_KEY` is not set by default.
- **Decision:** Follow Section 0 Rule 2 and Section 8.4:
  1. The `image_ocr` ingestion adapter checks for Tesseract availability via `pytesseract.get_tesseract_version()`. If unavailable, it degrades gracefully (returns segments marked with notice or raises a recoverable `IngestionError` caught by the pipeline to mark degraded layer status, instead of crashing).
  2. `GET /api/health` reports `ocr_available: false` and `anthropic_key_set: false`.
  3. Dockerfile bundles `tesseract-ocr` and `tesseract-ocr-eng` for complete deployment parity.
- **Status:** Approved.

### DEC-002: Ingestion Adapter Source Detection and Precedence (Phase 1)
- **Context:** Section 5.1 specifies: "Auto-detect the source from magic bytes / MIME first, then extension; the API allows an explicit override. Never trust the extension alone."
- **Decision:**
  - `registry.detect_source(data: bytes | str, filename: str | None = None, explicit_source: InputSource | None = None) -> InputSource` will:
    1. If `explicit_source` is supplied and valid, use it.
    2. Check binary magic bytes (e.g. PDF `%PDF-`, DOCX/ZIP `PK\x03\x04` containing Word document entries, PNG `\x89PNG`, JPEG `\xff\xd8\xff`, GIF `GIF8`).
    3. If text-based or ambiguous, inspect structure (e.g. JSON parse candidate, HTML tags like `<!DOCTYPE html>` or `<html>`, Email headers `From:` / `Subject:`, Markdown markers).
    4. Fall back to file extension.
    5. Default to `USER_MESSAGE` or `TEXT` if plain text.
- **Status:** Approved.

### DEC-003: DOCX XML Parsing and Zip Bomb Security (Phase 1)
- **Context:** DOCX files can carry hidden text via `<w:vanish/>`, white font color (`<w:color w:val="FFFFFF"/>`), tiny font sizes, or in comments (`word/comments.xml`). High-level docx libraries often ignore or strip vanished runs. Furthermore, malicious archives can pose zip-bomb denial of service.
- **Decision:**
  1. Inspect the zip archive directly: sum `ZipInfo.file_size` before decompression and raise `ZipBombError` if total uncompressed size exceeds policy `max_zip_uncompressed_bytes`.
  2. Parse `word/document.xml`, `word/comments.xml`, `word/footer*.xml`, and `docProps/core.xml` via `lxml.etree` to reliably identify run-level formatting (`<w:vanish/>`, `<w:color>`, `<w:sz>`) and map them to `origin="hidden"` or `origin="comment"` with exact reason codes.
- **Status:** Approved.

### DEC-004: Fixture Factory Architecture (Phase 1)
- **Context:** Section 9.1 requires reproducible generation of fixtures across 10 carriers and all specified hiding techniques.
- **Decision:**
  - Implemented `eval/fixture_factory.py` with `make(payload: str, carrier: str, technique: str) -> bytes | str`.
  - Used `pymupdf` to generate real PDF files with exact coordinates and font/color properties.
  - Used `PIL.Image` and `PIL.ImageDraw` for image synthesis with EXIF metadata chunks.
  - Used in-memory `zipfile` for bit-exact WordprocessingML package creation.
- **Status:** Approved.
