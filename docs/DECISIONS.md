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

### DEC-007: Evaluation Harness, Deterministic Fixture Builds, and Pre-Registered Claims (Phase 4)
- **Context:** Section 9 specifies benchmark composition (dev + held-out test split), freeze protocol via SHA-256 (`data/test.frozen.sha256`), calculation of binary, per-category, per-source, and latency percentiles, and automated generation of `docs/CLAIMS.md`.
- **Decision:**
  1. **Conversational Multi-Turn Carrier Routing:** Multi-turn jailbreak items in `eval/build_dataset.py` are explicitly assigned carrier `user_message` and source `InputSource.USER_MESSAGE`, reflecting interactive user conversations.
  2. **Valid Benign Binary Fixtures:** Benign carrier files for binary formats (`pdf`, `docx`, `image`) are generated via `fixture_factory.make()` with visible paragraph/text techniques, ensuring structurally valid files that test real ingestion adapters without spurious format errors.
  3. **Strict Test Freeze Enforcement:** `verify_test_freeze()` checks the SHA-256 of `data/test.jsonl` against `data/test.frozen.sha256`. If mismatched, `eval/run_eval.py --split test` immediately halts with an error, preventing test-split data leakage or post-hoc tampering.
  4. **Automated Claims Reporting:** `eval/claims.py` consumes `reports/report.json` and writes `docs/CLAIMS.md` purely from measured numbers, fulfilling Section 0 Rule 4.
- **Status:** Approved.

### DEC-008: Detection Cascade, ML Classifier Scoring, and Hardened Judge (Phase 5)
- **Context:** Section 5.3b and 5.3c require an ML classifier and an LLM judge with §5.3c hardening, orchestrated in a cascade, with ablation demonstrating measured lift on dev.
- **Decision:**
  1. **Category Attribution per §5.3b:** The ML classifier provides a generic $P(\text{injection})$. It contributes its probability to attack categories via the rules' labels, or emits `INDIRECT_PROMPT_INJECTION` for untrusted sources, rather than inventing unverified rule categories on clean user messages.
  2. **Non-Destructive Span Redaction:** `redact_segment()` prioritizes localized spans identified by rules. A whole-segment redaction is only performed if no localized spans exist, preserving benign context around detected injections.
  3. **LLM Judge Hardening:** The judge enforces a nonce-delimited envelope with escaped delimiter lookalikes, strict Pydantic JSON validation (treating malformed outputs as "no opinion"), and a circuit breaker that trips after 3 consecutive failures.
  4. **Measured Ablation Lift:** On the dev split, adding the ML classifier to the rules cascade increased recall from 54.95% to 80.63% (+25.68% lift) and F1 from 0.7072 to 0.8504 (+0.1432 lift).
- **Status:** Approved.

### DEC-009: Runtime Guards (G1-G3) and Victim Agent Simulation (Phase 6)
- **Context:** Section 6 and 7 require tool guard (tiers + taint + argument validation), egress guard (canary + credential + prompt leakage), memory guard (persistence + context poisoning), and victim agent evaluating scenarios S1-S9 and B1-B3.
- **Decision:**
  1. **Taint Enforcement & Tiers:** `ToolGuard` enforces strict tiers where tainted context unconditionally denies `EGRESS` and `EXEC_DESTRUCTIVE` tools unless user confirmation is granted, and denies `READ_SENSITIVE` if active attack findings exist.
  2. **Multi-Vector Egress Protection:** `EgressGuard` scans outbound responses for session canary tokens, credential patterns (AWS, API keys, JWTs), system prompt n-gram leakage, and markdown rendering image exfiltration.
  3. **Realistic Mock Tool Sandboxing (§0 Rule 5):** All agent tools (`send_email`, `run_sql`, `run_bash`, `transfer_funds`, `read_file`, `write_file`) are non-destructive mocks operating on in-memory SQLite and local `demo_data/`.
  4. **Measured ASR Reduction:** Attack success rate was measured directly from tool execution logs: dropping from 88.9% (unprotected) to 0.0% (protected), while all benign utility tasks (B1-B3) succeeded without hindrance.
- **Status:** Approved.

### DEC-010: Ops Features, Resilience, Retraining, and Red-Team Loop (Phase 7)
- **Context:** Section 8 requires structured audit logging, performance metrics with percentiles, human-in-the-loop feedback with model retraining, fault tolerance (per-layer timeouts, degraded mode, fail-closed policy), and an adversarial red-team loop logging bypasses.
- **Decision:**
  1. **Privacy-Preserving Audit Logging (§8.1):** Structured entries are persisted to SQLite `data/audit.sqlite`. To protect confidentiality, raw content is never stored unless `STORE_CONTENT=1`; instead, a SHA-256 hash and redacted excerpt are logged.
  2. **Continuity-Aware Metrics (§8.1):** `MetricsTracker` records thread-safe in-memory latencies and counters with percentile calculations (p50/p95). If in-memory state is empty (e.g. fresh process restart), it aggregates historical counts directly from `data/audit.sqlite`.
  3. **Layer Timeouts, Degraded Mode & Fail-Closed (§8.3):** Implemented `run_with_timeout` using thread pools. If an active layer (e.g. Judge or Classifier) times out or raises an exception, the pipeline gracefully marks the verdict `degraded=True` and applies stricter policy thresholds (`allow_below - 0.10`). If the rules layer itself fails, it fails closed (`BLOCK` for untrusted sources, `ESCALATE` for direct user messages).
  4. **Review Queue and Retraining (§8.2):** User submissions to `POST /api/feedback` enter `review_queue`. Once approved by a reviewer, `python -m aegis.train` merges them with the dev split, retrains the TF-IDF char n-gram Logistic Regression classifier, and outputs a timestamped versioned model (`classifier_v_*.joblib`) and training report.
  5. **Adversarial Red-Team Generator (§8.2):** `eval/redteam.py` generates adversarial mutations (polite indirect framing, roleplay hijacking, syntax concealment) across attack categories, submitting them against the firewall and appending bypasses (`action == "ALLOW"`) to `data/redteam_bypasses.jsonl`.
- **Status:** Approved.

