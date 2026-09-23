# AegisAgent – Prompt Injection Firewall
**ET AI Hackathon: Agentic Edition Presented by Accenture**  
*Agentic Cybersecurity – Prompt Injection Firewall*

---

## 🌐 Live Web Access (Accessible From Any Device)

- **Primary Web App**: [https://tumor-page-acc-agent.trycloudflare.com](https://tumor-page-acc-agent.trycloudflare.com)
- **Local Machine**: `http://127.0.0.1:8000`

---

## 🛡️ Key Features

- **Depth D3 (Heterogeneous Multimodal Ingestion)**: Ingests and sanitizes content across 11 formats: User Messages, Web Pages, PDFs, Emails, Markdown, HTML, Word (`.docx`), API Responses, OCR Text, Source Code, and Images (via OCR).
- **Feature F3+ (All 9 Attack Vectors Detected & Neutralized)**:
  1. Instruction Override & Delimiter Breakout (`<|im_start|>`, `[INST]`, `### System`)
  2. Role Change (`DAN`, `EvilGPT`, `Developer Mode`)
  3. Secret Extraction (System prompt leaks, API keys, `.env` vars)
  4. Tool Abuse (Dangerous shell commands, SQL injection, unauthorized emails)
  5. Credential Theft (Phishing lures, 2FA/OTP harvesting)
  6. Context Poisoning (RAG sleeper triggers, fake executive memos)
  7. Multi-Step Jailbreaks (Stateful turn history tracking)
  8. Encoded Instructions (Base64, Hex, Leetspeak, ROT13, zero-width chars)
  9. Indirect Prompt Injection (Cross-boundary taint detection)
- **Surgical Neutralization**: Excises the exact malicious injection span while preserving benign text, and wraps external third-party inputs in an immutable delimiter quarantine container.
- **Autonomous Agent Tool Sandbox**: Interactive simulation with toggleable **FIREWALL ON/OFF** showing real-time protection against unauthorized tool abuse.
- **Automated Benchmark Suite**: 29 multi-source test cases with **100% Precision (0 False Positives)**, **100% Recall**, and **~1.1 ms latency**.

---

## 🚀 Quick Start (Local & Cloud)

### 1. Local Run
```bash
# Install dependencies
pip install -r requirements.txt

# Run server
python -m uvicorn server:app --host 0.0.0.0 --port 8000
```
Open `http://127.0.0.1:8000` in your browser.

### 2. Run Tests
```bash
# Run Unit Tests
python -m unittest tests/test_firewall.py

# Run Live API Benchmark
python tests/test_live_api.py
```

### 3. Docker Deployment
```bash
docker build -t aegis-firewall .
docker run -p 8000:8000 aegis-firewall
```

### 4. 1-Click Cloud Deployment (Render / Railway / Hugging Face)
- Connect this repository to **Render.com** (blueprint configured in `render.yaml`).
- Or deploy to **Hugging Face Spaces** (Docker SDK).
- Or deploy to **Railway.app** (using `Procfile` / `Dockerfile`).
