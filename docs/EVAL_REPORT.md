# AegisAgent Evaluation Report (DEV Split)

- **Generated At:** 2026-09-23 20:13:16 UTC
- **Evaluation Split:** `dev`
- **Firewall Mode:** `rules_only` (Phase 4 Baseline)


---

## 1. Executive Summary

| Metric | Measured Value | Target / Reference |
|---|---|---|
| **Total Items Evaluated** | 311 | - |
| **Attack Payloads** | 222 | - |
| **Benign Items** | 89 | - |
| **Detection Recall** | **54.95%** | Target >= 85.0% |
| **Detection Precision** | **99.19%** | - |
| **F1 Score** | **0.7072** | - |
| **False Positive Rate (FPR)** | **1.12%** | Target <= 5.0% on Benign |
| **Residual Attack Rate** | **0.00%** | Target <= 5.0% |
| **Sanitization Retention** | **72.35%** | High text preservation |
| **p50 Total Latency** | **12.72 ms** | - |
| **p95 Total Latency** | **19.62 ms** | Target < 50 ms for text |

---

## 2. Per-Category Detection Performance

> Pre-registered target: Category is "detected" if $n \ge 15$, flagged-recall $\ge 0.80$, and category-correct recall $\ge 0.70$ (§9.5).

| Attack Category | Items ($n$) | Flagged Recall | Category-Correct Recall | Status |
|---|---|---|---|---|
| `CONTEXT_POISONING` | 24 | 16.7% | 16.7% | FAIL |
| `CREDENTIAL_THEFT` | 24 | 41.7% | 41.7% | FAIL |
| `ENCODED_INSTRUCTIONS` | 20 | 75.0% | 75.0% | PARTIAL |
| `INDIRECT_PROMPT_INJECTION` | 176 | 54.0% | 58.0% | FAIL |
| `INSTRUCTION_OVERRIDE` | 32 | 87.5% | 87.5% | PASS (Detected) |
| `MULTI_STEP_JAILBREAK` | 18 | 55.6% | 55.6% | FAIL |
| `ROLE_CHANGE` | 28 | 82.1% | 82.1% | PASS (Detected) |
| `SECRET_EXTRACTION` | 28 | 42.9% | 42.9% | FAIL |
| `TOOL_ABUSE` | 28 | 32.1% | 32.1% | FAIL |

---

## 3. Per-Source Breakdown (All 11 Input Sources)

| Source | Total ($n$) | Attack ($n$) | Recall | Benign ($n$) | FPR |
|---|---|---|---|---|---|
| `api_response` | 23 | 16 | 87.5% | 7 | 0.0% |
| `docx` | 31 | 22 | 59.1% | 9 | 0.0% |
| `email` | 36 | 26 | 42.3% | 10 | 0.0% |
| `html` | 9 | 0 | N/A | 9 | 0.0% |
| `image` | 30 | 26 | 19.2% | 4 | 0.0% |
| `markdown` | 37 | 30 | 66.7% | 7 | 0.0% |
| `ocr_text` | 26 | 22 | 31.8% | 4 | 0.0% |
| `pdf` | 20 | 10 | 70.0% | 10 | 0.0% |
| `source_code` | 18 | 10 | 60.0% | 8 | 12.5% |
| `user_message` | 65 | 46 | 58.7% | 19 | 0.0% |
| `web_page` | 16 | 14 | 85.7% | 2 | 0.0% |

---

## 4. Attack Category x Technique Heat-map

| Attack Category | Carrier Technique | Samples | Flagged | Recall |
|---|---|---|---|---|
| `CONTEXT_POISONING` | `confusable_chars` | 6 | 0 | 0.0% |
| `CONTEXT_POISONING` | `exif_comment` | 3 | 2 | 66.7% |
| `CONTEXT_POISONING` | `faint_text` | 3 | 0 | 0.0% |
| `CONTEXT_POISONING` | `noisy_visible` | 6 | 2 | 33.3% |
| `CONTEXT_POISONING` | `small_text` | 3 | 0 | 0.0% |
| `CONTEXT_POISONING` | `visible_text` | 3 | 0 | 0.0% |
| `CREDENTIAL_THEFT` | `attachment` | 2 | 1 | 50.0% |
| `CREDENTIAL_THEFT` | `body_visible` | 2 | 1 | 50.0% |
| `CREDENTIAL_THEFT` | `comment` | 3 | 1 | 33.3% |
| `CREDENTIAL_THEFT` | `header_field` | 2 | 0 | 0.0% |
| `CREDENTIAL_THEFT` | `hidden_run` | 3 | 2 | 66.7% |
| `CREDENTIAL_THEFT` | `html_hidden` | 3 | 1 | 33.3% |
| `CREDENTIAL_THEFT` | `quoted_thread` | 3 | 2 | 66.7% |
| `CREDENTIAL_THEFT` | `visible` | 3 | 1 | 33.3% |
| `CREDENTIAL_THEFT` | `white_text` | 3 | 1 | 33.3% |
| `ENCODED_INSTRUCTIONS` | `annotation` | 2 | 1 | 50.0% |
| `ENCODED_INSTRUCTIONS` | `comment` | 3 | 2 | 66.7% |
| `ENCODED_INSTRUCTIONS` | `hidden_run` | 2 | 2 | 100.0% |
| `ENCODED_INSTRUCTIONS` | `metadata` | 2 | 2 | 100.0% |
| `ENCODED_INSTRUCTIONS` | `tiny_text` | 2 | 1 | 50.0% |
| `ENCODED_INSTRUCTIONS` | `visible` | 2 | 1 | 50.0% |
| `ENCODED_INSTRUCTIONS` | `visible_paragraph` | 2 | 2 | 100.0% |
| `ENCODED_INSTRUCTIONS` | `white_text` | 5 | 4 | 80.0% |
| `INDIRECT_PROMPT_INJECTION` | `annotation` | 2 | 1 | 50.0% |
| `INDIRECT_PROMPT_INJECTION` | `attachment` | 5 | 2 | 40.0% |
| `INDIRECT_PROMPT_INJECTION` | `body_visible` | 5 | 2 | 40.0% |
| `INDIRECT_PROMPT_INJECTION` | `comment` | 19 | 13 | 68.4% |
| `INDIRECT_PROMPT_INJECTION` | `confusable_chars` | 11 | 1 | 9.1% |
| `INDIRECT_PROMPT_INJECTION` | `docstring` | 4 | 4 | 100.0% |
| `INDIRECT_PROMPT_INJECTION` | `exif_comment` | 6 | 5 | 83.3% |
| `INDIRECT_PROMPT_INJECTION` | `faint_text` | 7 | 0 | 0.0% |
| `INDIRECT_PROMPT_INJECTION` | `header_field` | 4 | 0 | 0.0% |
| `INDIRECT_PROMPT_INJECTION` | `hidden_div` | 3 | 3 | 100.0% |
| `INDIRECT_PROMPT_INJECTION` | `hidden_run` | 5 | 4 | 80.0% |
| `INDIRECT_PROMPT_INJECTION` | `html_hidden` | 6 | 2 | 33.3% |
| `INDIRECT_PROMPT_INJECTION` | `image_alt` | 8 | 4 | 50.0% |
| `INDIRECT_PROMPT_INJECTION` | `inline_html` | 8 | 5 | 62.5% |
| `INDIRECT_PROMPT_INJECTION` | `key_name` | 5 | 4 | 80.0% |
| `INDIRECT_PROMPT_INJECTION` | `link_title` | 7 | 5 | 71.4% |
| `INDIRECT_PROMPT_INJECTION` | `metadata` | 2 | 2 | 100.0% |
| `INDIRECT_PROMPT_INJECTION` | `metadata_field` | 6 | 5 | 83.3% |
| `INDIRECT_PROMPT_INJECTION` | `nested_value` | 5 | 5 | 100.0% |
| `INDIRECT_PROMPT_INJECTION` | `noisy_visible` | 11 | 6 | 54.5% |
| `INDIRECT_PROMPT_INJECTION` | `offscreen` | 4 | 3 | 75.0% |
| `INDIRECT_PROMPT_INJECTION` | `quoted_thread` | 6 | 5 | 83.3% |
| `INDIRECT_PROMPT_INJECTION` | `small_text` | 7 | 0 | 0.0% |
| `INDIRECT_PROMPT_INJECTION` | `string_literal` | 3 | 1 | 33.3% |
| `INDIRECT_PROMPT_INJECTION` | `tiny_font` | 4 | 3 | 75.0% |
| `INDIRECT_PROMPT_INJECTION` | `tiny_text` | 2 | 1 | 50.0% |
| `INDIRECT_PROMPT_INJECTION` | `visible` | 5 | 2 | 40.0% |
| `INDIRECT_PROMPT_INJECTION` | `visible_paragraph` | 2 | 2 | 100.0% |
| `INDIRECT_PROMPT_INJECTION` | `visible_text` | 6 | 0 | 0.0% |
| `INDIRECT_PROMPT_INJECTION` | `white_text` | 8 | 5 | 62.5% |
| `INSTRUCTION_OVERRIDE` | `comment` | 4 | 4 | 100.0% |
| `INSTRUCTION_OVERRIDE` | `image_alt` | 4 | 3 | 75.0% |
| `INSTRUCTION_OVERRIDE` | `inline_html` | 4 | 3 | 75.0% |
| `INSTRUCTION_OVERRIDE` | `key_name` | 5 | 4 | 80.0% |
| `INSTRUCTION_OVERRIDE` | `link_title` | 4 | 4 | 100.0% |
| `INSTRUCTION_OVERRIDE` | `metadata_field` | 6 | 5 | 83.3% |
| `INSTRUCTION_OVERRIDE` | `nested_value` | 5 | 5 | 100.0% |
| `MULTI_STEP_JAILBREAK` | `multi_turn_split` | 18 | 10 | 55.6% |
| `ROLE_CHANGE` | `base64` | 2 | 2 | 100.0% |
| `ROLE_CHANGE` | `comment` | 3 | 3 | 100.0% |
| `ROLE_CHANGE` | `direct` | 1 | 1 | 100.0% |
| `ROLE_CHANGE` | `hex` | 2 | 2 | 100.0% |
| `ROLE_CHANGE` | `hidden_div` | 3 | 3 | 100.0% |
| `ROLE_CHANGE` | `homoglyph` | 2 | 1 | 50.0% |
| `ROLE_CHANGE` | `leet` | 2 | 2 | 100.0% |
| `ROLE_CHANGE` | `offscreen` | 4 | 3 | 75.0% |
| `ROLE_CHANGE` | `rot13` | 2 | 2 | 100.0% |
| `ROLE_CHANGE` | `spaced` | 2 | 0 | 0.0% |
| `ROLE_CHANGE` | `tiny_font` | 4 | 3 | 75.0% |
| `ROLE_CHANGE` | `zero_width` | 1 | 1 | 100.0% |
| `SECRET_EXTRACTION` | `attachment` | 3 | 1 | 33.3% |
| `SECRET_EXTRACTION` | `body_visible` | 3 | 1 | 33.3% |
| `SECRET_EXTRACTION` | `comment` | 3 | 2 | 66.7% |
| `SECRET_EXTRACTION` | `header_field` | 2 | 0 | 0.0% |
| `SECRET_EXTRACTION` | `html_hidden` | 3 | 1 | 33.3% |
| `SECRET_EXTRACTION` | `image_alt` | 4 | 1 | 25.0% |
| `SECRET_EXTRACTION` | `inline_html` | 4 | 2 | 50.0% |
| `SECRET_EXTRACTION` | `link_title` | 3 | 1 | 33.3% |
| `SECRET_EXTRACTION` | `quoted_thread` | 3 | 3 | 100.0% |
| `TOOL_ABUSE` | `base64` | 1 | 1 | 100.0% |
| `TOOL_ABUSE` | `direct` | 1 | 1 | 100.0% |
| `TOOL_ABUSE` | `exif_comment` | 3 | 3 | 100.0% |
| `TOOL_ABUSE` | `faint_text` | 4 | 0 | 0.0% |
| `TOOL_ABUSE` | `hex` | 2 | 1 | 50.0% |
| `TOOL_ABUSE` | `homoglyph` | 2 | 0 | 0.0% |
| `TOOL_ABUSE` | `leet` | 2 | 2 | 100.0% |
| `TOOL_ABUSE` | `rot13` | 2 | 1 | 50.0% |
| `TOOL_ABUSE` | `small_text` | 4 | 0 | 0.0% |
| `TOOL_ABUSE` | `spaced` | 2 | 0 | 0.0% |
| `TOOL_ABUSE` | `visible_text` | 3 | 0 | 0.0% |
| `TOOL_ABUSE` | `zero_width` | 2 | 0 | 0.0% |

---

## 5. Sanitization Quality

- **Sanitized Attack Items:** 101
- **Residual Attacks Flagged on Re-scan:** 0
- **Residual Attack Rate:** **0.00%**
- **Average Text Retention Ratio:** **72.35%**

---

## 6. Latency Profile

- **End-to-End Latency:** p50 = 12.72 ms, p95 = 19.62 ms

### Per-Layer Latency Percentiles

| Pipeline Layer | p50 (ms) | p95 (ms) |
|---|---|---|
| `l1_ingestion_ms` | 0.31 ms | 3.45 ms |
| `l2_normalize_ms` | 1.23 ms | 3.12 ms |
| `l3_detection_ms` | 10.55 ms | 15.7 ms |
| `l4_fusion_policy_ms` | 0.03 ms | 0.05 ms |
| `l5_neutralize_ms` | 0.01 ms | 0.06 ms |
| `total_ms` | 12.72 ms | 19.62 ms |
| `total_pipeline_ms` | 12.72 ms | 19.62 ms |

---

## 7. Ablation Note
Current evaluation reflects **Rules-Only Baseline** (L1 Ingestion + L2 Normalization + L3 Rules & Session + L4 Policy + L5 Neutralization).
Phase 5 will add Machine Learning Classifier (L3b) and LLM Judge (L3c) with measured ablation deltas.
