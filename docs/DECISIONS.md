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

### DEC-005: Normalization, Offset Mapping, and Deobfuscation (Phase 2)
- **Context:** Section 5.2 requires all text transformations to maintain character-level offset maps back to the original document text. Furthermore, obfuscated tokens (such as Base64, Hex, or despaced runs) must map back to the exact outer encoded token span in the original text, while enforcing caps (depth <= 3, variants <= 12, blob <= 64 KB).
- **Decision:**
  1. Implemented `MappedText` with `replace_spans` for single-pass non-overlapping batch token replacements, avoiding repeated string allocations.
  2. In `decode_base64`, used negative lookahead `(?![A-Za-z0-9+/_-])` instead of word boundary `\b` after padding characters to ensure trailing `=` signs are cleanly included in the detected span.
  3. Included zero-width spaces (`ZERO_WIDTH_CODEPOINTS`) and Unicode tag codepoints in the printable UTF-8 calculation for decoded binary/base64/hex payloads to seamlessly support chained multi-layer evasions (e.g. Base64 containing zero-width spaces).
  4. Enforced BFS variant generation capped at 12 unique variants and 3 recursion steps, deduplicating text strings to maximize detector diversity.
- **Status:** Approved.

### DEC-006: Rule Cascade, Policy Decisions, and Spotlighting Neutralizer (Phase 3)
- **Context:** Section 5.3 through 5.5 requires implementing 9 attack rule families, an instruction-in-data detector, cross-turn session tracking, noisy-OR risk fusion, and spotlighting envelope neutralization.
- **Decision:**
  1. **ReDoS-Safe Regex Design:** Bounded all wildcards with explicit limits (e.g. `{0,60}?`) and word boundaries. Avoided unbounded nested quantifiers to ensure sub-millisecond execution even on large texts.
  2. **Hard-Negative Separation in Indirect Injection:** Configured `InstructionInDataDetector` to require imperative verbs to strictly co-occur with an AI cue, a tool/exfiltration target object, or a hidden segment origin. This explicitly prevents false positives on benign business requests (e.g. "Please send me the report").
  3. **Nonce Envelope Hardening:** Neutralized all delimiter lookalikes (`<<<`, `>>>`, `UNTRUSTED_DATA`) within inbound content before envelope packaging, ensuring attackers cannot break out of spotlighting boundaries.
  4. **Multi-Turn Session Tracking:** Persisted turn history with SQLite backing and implemented a cross-turn fragmentation check that concatenates turns $t-3 \dots t$ and reruns rules to detect fragmented attack delivery.
  5. **Unified API Route Handling:** Utilized `fastapi.Request` inspection in `/api/inspect` and `/api/neutralize` to seamlessly process both JSON payloads and multipart file uploads without schema parsing conflicts.
- **Status:** Approved.
