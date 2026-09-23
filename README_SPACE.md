---
title: AegisAgent - Prompt Injection Firewall
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# AegisAgent: Prompt Injection Firewall

> **ET AI Hackathon — Problem 2: Agentic Cybersecurity**  
> An industrial-grade Prompt Injection Firewall for AI Agents featuring format-aware ingestion, character-mapped span sanitization, spotlighting nonce envelopes, AI cascade classification, and runtime tool/egress guards.

[![Tests](https://img.shields.io/badge/pytest-95%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)]()
[![Defense Depth](https://img.shields.io/badge/Grid%20Position-F3%20%2F%20D2-purple.svg)]()
[![ASR Reduction](https://img.shields.io/badge/Agent%20ASR-88.9%25%20%E2%86%92%200.0%25-success.svg)]()

---

## Key Features

1. **Format-Aware Ingestion Across 11 Sources (L1):** Ingests raw text, HTML, Markdown, PDF, DOCX, Email (.eml), API JSON, OCR text, Source Code, and Images. Extracts hidden text (white font, `<w:vanish/>`, off-screen CSS, metadata, comments).
2. **Character-Mapped Deobfuscation (L2):** `MappedText` tracks character-level coordinate transformations across decoders (Base64, Hex, ROT13, Leet, Spaced, Homoglyphs, Zero-Width, Unicode tags) back to exact raw file offsets.
3. **Multi-Layer Detection Cascade (L3):**
   - **L3a Rules + Instruction-in-Data:** 9 attack categories with ReDoS-safe patterns, distinguishing benign business language from imperative injections.
   - **L3b ML Classifier:** Sliding-window TF-IDF char n-grams + Logistic Regression providing measured **+25.68% recall lift**.
   - **L3c Hardened LLM Judge:** Nonce-delimited arbitration on grey-zone scores with circuit breakers.
   - **L3d Session Tracker:** Stateful detection of multi-turn staged jailbreaks.
4. **Spotlighting Neutralizer (L5):** Redacts identified hostile spans on the **original text** without breaking file structure, packaging safe content in cryptographically unique nonce envelopes (`<<<UNTRUSTED_CONTENT id=...>>>`).
5. **Runtime Blast Radius Guards (G1–G3):**
   - **G1 Tool Guard:** 5 risk tiers, taint enforcement, SQL validation, shell blocking.
   - **G2 Egress Guard:** Canary token exfiltration detection, credential masking, markdown image exfiltration blocking.
   - **G3 Memory Guard:** Prevents persistent context poisoning and authority spoofing.
6. **SOC Dashboard & Operations:** Plain HTML/CSS/JS dark-mode dashboard covering all 5 tabs, real-time audit trail, human review queue, and continuous model retraining.

---

## Quick Start

### 1. Installation
```bash
# Clone and setup environment
git clone https://github.com/hackathon/AegisAgent.git
cd AegisAgent

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Firewall & Dashboard
```bash
uvicorn server.main:app --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser to access the 5-tab SOC Dashboard.

### 3. Run Automated Tests
```bash
python -m pytest
```
*Runs all unit and integration tests across the ingestion adapters, normalization, rules, classifier, judge, guards, victim agent, ops, and dashboard endpoints.*

### 4. Run Benchmark Evaluation & Verify Claims
```bash
# Run evaluation on frozen test split
python -m eval.run_eval --split test

# Generate pre-registered claims verification document
python -m eval.claims
```

### 5. Run Adversarial Red-Team Generator
```bash
python -m eval.redteam --variants 3 --out data/redteam_bypasses.jsonl
```

---

## Integrate with Your Agent

Protect any LLM agent pipeline in three lines of Python:

```python
from aegis.pipeline import get_pipeline
from aegis.models import InputSource

firewall = get_pipeline()

# Intercept and neutralize untrusted input (e.g. from an inbound email or web page)
verdict = firewall.process(untrusted_content, source=InputSource.EMAIL)

if verdict.action in ("ALLOW", "SANITIZE"):
    # Pass safe, spotlighted text to your LLM agent
    safe_prompt = verdict.envelope_text or verdict.sanitized_text
    response = agent.run(safe_prompt)
else:
    # Safely reject or escalate blocked attacks
    log_security_alert(verdict.request_id, verdict.category_scores)
```

---

## Project Structure

```
Codebase/
├── aegis/
│   ├── ingestion/       # L1: 11 format adapters (pdf, docx, html, email, etc.)
│   ├── normalize/       # L2: MappedText coordinate tracker & decoders
│   ├── detection/       # L3: Rules cascade, ML classifier, LLM judge, session tracker
│   ├── policy/          # L4: Noisy-OR fusion & policy engine
│   ├── neutralize/      # L5: Offset span redaction & nonce spotlighting envelope
│   ├── guard/           # G1-G3: Tool guard, egress guard, memory guard
│   ├── observability/   # Audit logger & continuous metrics tracker
│   ├── resilience.py    # Timeouts, circuit breakers, and degraded fail-closed mode
│   └── train.py         # Human-in-the-loop review queue and model retraining
├── agent/
│   ├── scenarios/       # Scenarios S1-S9 (attacks) and B1-B3 (benign tasks)
│   └── victim.py        # ReAct victim agent with non-destructive sandboxed tools
├── eval/
│   ├── fixture_factory.py # Bit-exact reproducible attack carrier synthesis
│   ├── build_dataset.py   # Dataset compiler for dev and held-out test splits
│   ├── run_eval.py        # Benchmark evaluation CLI runner
│   ├── claims.py          # Pre-registered claims verification generator
│   └── redteam.py         # Automated adversarial evasion generator
├── server/
│   ├── main.py          # FastAPI application entrypoint
│   ├── routes_health.py # /api/health capabilities status
│   ├── routes_inspect.py# /api/inspect and /api/neutralize
│   └── routes_ops.py    # /api/audit, /api/metrics, /api/policy, /api/agent/run
├── static/              # Dark SOC Single-Page Application (HTML/CSS/JS)
├── docs/
│   ├── ARCHITECTURE.md  # Detailed technical architecture & layer specifications
│   ├── CLAIMS.md        # Empirically measured claims generated by eval/claims.py
│   ├── DECISIONS.md     # Architecture Decision Records (DEC-001 to DEC-011)
│   ├── DEMO_SCRIPT.md   # Step-by-step presentation demonstration guide
│   └── EVAL_REPORT.md   # Latest benchmark evaluation report
├── data/
│   ├── test.frozen.sha256 # Frozen test split integrity verification hash
│   ├── models/            # Trained ML classifier models
│   └── audit.sqlite       # Local SQLite audit log and review queue
└── tests/               # Unit and integration tests
```

---

## Known Limitations (§15)

In compliance with Section 0 Rule 2 and Section 15 of the implementation plan:
- **No Silver Bullet:** Prompt injection is fundamentally non-lexical. Novel semantic paraphrases may bypass text pattern filters; this is why runtime ToolGuard and EgressGuard exist as defense-in-depth.
- **OCR Constraints:** Stylized typography, extreme noise, or steganographic instructions embedded in images may be missed by OCR preprocessing.
- **Judge Target Risk:** The LLM judge is itself an LLM; while protected by nonce spotlighting and strict JSON schema validation, it is kept exclusively in the grey zone to minimize attack surface and latency.
- **Environment Parity:** If host dependencies (Tesseract or Anthropic API key) are absent, AegisAgent degrades gracefully to offline modes without crashing or faking benchmarks.
