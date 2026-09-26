# AegisAgent Demonstration Script & Presentation Guide

A step-by-step walkthrough script for demonstrating **AegisAgent** to evaluators and judges.

---

## Pre-Demo Checklist

1. Start the API server:
   ```bash
   uvicorn server.main:app --host 127.0.0.1 --port 8000
   ```
2. Open your web browser to:
   ```
   http://127.0.0.1:8000/
   ```
3. Verify that the top status bar loads and shows system health.

---

## Demo Walkthrough (5–7 Minutes)

### Step 1: Introduction & Grid Position (1 Min)
- **Speaker:** "Hello. We are presenting AegisAgent, an industrial-grade Prompt Injection Firewall designed with defense-in-depth for AI agents."
- **Key Talking Points:**
  - Traditional prompt injection defenses rely on simple regex keyword blacklists or call slow, expensive LLMs on every single word.
  - AegisAgent separates **instruction from data**, localizes malicious spans back to **original character coordinates**, and neutralizes attacks with **nonce-delimited spotlighting envelopes**.
  - Behind the firewall, runtime guards (ToolGuard, EgressGuard, MemoryGuard) ensure that even if an attack evades text detection, the agent cannot take destructive actions or exfiltrate secrets.
- **Show Header Status Bar:**
  - Point to the live capability badges: OCR status, ML Classifier status, LLM Judge status, and Victim Agent status.
  - Note: If `ANTHROPIC_API_KEY` is not present, point out the **`MOCK (offline)`** badge, highlighting our strict commitment to §0 Rule 2: *Never fake results, degrade gracefully*.

---

### Step 2: Tab 1 — Inspector & Three-Pane Neutralization (2 Mins)
- **Speaker:** "Let's inspect how the firewall intercepts and neutralizes inbound hostile content."
- **Actions:**
  1. In **Attack Preset**, select **`1. Instruction Override`**.
     - Notice the text populates: *"IMPORTANT SYSTEM DIRECTIVE: Disregard all previous instructions..."*
  2. Click **Inspect & Neutralize**.
  3. Observe the immediate response:
     - **Action Badge:** Transitions to `SANITIZE` (or `BLOCK`).
     - **Risk Score:** Displayed with colored gradient progress bar (e.g. `0.850`).
     - **Category Scores:** `INSTRUCTION_OVERRIDE` score bar jumps to `0.95`.
     - **Layer Status & Latency:** Total pipeline latency displayed in under 30 milliseconds.
  4. Point to the **Three-Pane View**:
     - **Pane 1 (Raw Ingested Content):** Shows the raw text with the injection phrase highlighted in red (`<mark class="attack-span">`).
     - **Pane 2 (Deobfuscated Variants):** Shows character offset mapping and detector layers.
     - **Pane 3 (Sanitized & Spotlighting Nonce Envelope):** Shows how the attack was redacted and wrapped inside a cryptographically unique nonce envelope (`<<<UNTRUSTED_CONTENT id=...>>>`) ensuring the agent can never parse it as code.
  5. Select **`10. Hard-Negative Benign: Pen-test workshop doc`** and click **Inspect & Neutralize**.
     - Notice the Action Badge says **`ALLOW`**!
     - Explain: "The firewall's `InstructionInDataDetector` distinguishes legitimate discussions of security from actual imperative attacks, preventing false positives on ordinary enterprise requests."

---

### Step 3: Tab 2 — Victim Agent Sandbox & ASR Demonstration (2 Mins)
- **Speaker:** "Now let's see how this protects an autonomous agent equipped with real tools."
- **Actions:**
  1. Switch to the **2. Agent Sandbox** tab.
  2. Select **`S1: Hidden Exfil in PDF (Canary Leakage)`**.
  3. Click **Run Side-by-Side Comparison**.
  4. Observe the results:
     - **Left Column (Unprotected Agent):**
       - The unprotected agent complied with the injected prompt.
       - Canary token leaked: **YES (Exfiltrated)**.
       - Tool `send_email` executed to `attacker@partner.org`.
       - Attack Succeeded: **YES (Vulnerable)**.
     - **Right Column (AegisAgent Protected):**
       - The firewall detected the hidden injection.
       - The ToolGuard blocked unauthorized egress.
       - Canary token leaked: **NO**.
       - Attack Succeeded: **NO (Protected)**.
  5. Select **`B1 (Benign): Sustainability Report Summary`** and click **Run Side-by-Side Comparison**.
     - Observe: Benign utility task succeeds with **100% utility**, proving zero disruption to benign operations.
  6. Point out the summary metrics:
     - **Unprotected ASR:** 88.9%
     - **Protected ASR:** 0.0% (100% attack reduction)

---

### Step 4: Tab 3 — Benchmark Evaluation & Pre-Registered Claims (1 Min)
- **Speaker:** "Every metric in AegisAgent is derived from rigorous empirical measurements on a frozen test split."
- **Actions:**
  1. Switch to the **3. Evaluation & Claims** tab.
  2. Point out the **Pre-Registered Claims Checklist**:
     - Pre-registered criteria for F3, D2, and D3 (§9.5).
     - Show the honest pass/pending breakdown.
  3. Review the **Cascade Ablation Study**:
     - Rules baseline: 54.95% recall.
     - Rules + ML Classifier: **80.63% recall (+25.68% lift, +0.1432 F1 lift)**.
     - This demonstrates our **Effective Use of AI** judging criterion.

---

### Step 5: Tab 4 & 5 — Operational Observability & Policy (1 Min)
- **Speaker:** "For SOC teams, AegisAgent includes audit logging, continuous feedback retraining, and hot-reloadable policies."
- **Actions:**
  1. Switch to **4. Audit & Feedback**:
     - View the real-time SQLite audit trail. Note that raw text is privacy-masked with SHA-256 hashes and redacted excerpts.
     - Click an audit row to copy its Request ID into the feedback form.
     - Show the **Pending Review Queue** and click **Retrain Model** to show how user feedback updates the classifier.
  2. Switch to **5. Policy Configuration**:
     - Show the sliders for `allow_below`, `block_at`, and source risk multipliers.
     - Adjust a slider and click **Save & Apply Policy**.
     - Show the toast notification confirming live hot-reloading via `PUT /api/policy`.

---

## Conclusion & Summary
"AegisAgent delivers end-to-end prompt injection security: format-aware ingestion across 11 sources, sub-character offset sanitization, spotlighting nonce envelopes, AI-driven cascade classification, and runtime guardrails that reduce agent attack success rate to 0.0%. Thank you."
