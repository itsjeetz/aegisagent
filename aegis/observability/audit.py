"""Audit logging for AegisAgent with hash storage and redactions (§8.1)."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Optional

from aegis.models import AttackType, Verdict

AUDIT_DB_PATH = Path("data/audit.sqlite")


class AuditLogger:
    """Stores structured firewall inspection records with privacy protection (§8.1)."""

    def __init__(self, db_path: Path | str = AUDIT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create audit_log table if not exists."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    request_id TEXT NOT NULL,
                    session_id TEXT,
                    source TEXT NOT NULL,
                    trust TEXT NOT NULL,
                    action TEXT NOT NULL,
                    risk REAL NOT NULL,
                    categories_json TEXT,
                    findings_json TEXT,
                    layer_status_json TEXT,
                    latency_ms REAL NOT NULL,
                    degraded INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    excerpt_redacted TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_req ON audit_log (request_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action);")
            conn.commit()

    def log_verdict(
        self,
        verdict: Verdict,
        content: bytes | str,
        session_id: Optional[str] = None,
    ) -> int:
        """Log a pipeline verdict to audit_log table (§8.1)."""
        # Excerpt preparation: do not store raw content unless STORE_CONTENT=1, and never in DEMO_MODE
        is_demo = os.environ.get("DEMO_MODE", "0").strip() == "1"
        store_raw = (os.environ.get("STORE_CONTENT", "0").strip() == "1") and not is_demo

        if store_raw:
            if isinstance(content, bytes):
                excerpt = content[:200].decode("utf-8", errors="replace")
            else:
                excerpt = content[:200]
        else:
            # Redacted excerpt: show sanitized text excerpt if available, else first 60 chars masked
            if verdict.sanitized_text:
                excerpt = verdict.sanitized_text[:150]
            else:
                raw_str = content if isinstance(content, str) else content[:60].decode("utf-8", errors="ignore")
                excerpt = raw_str[:20] + "... [REDACTED FOR PRIVACY]"

        cats_list = [c.value for c in verdict.category_scores.keys()]
        findings_summary = [
            {
                "attack_type": f.attack_type.value,
                "score": f.score,
                "detector": f.detector,
                "layer": f.layer,
                "evidence": f.evidence[:80],
            }
            for f in verdict.findings
        ]

        total_latency = verdict.timings_ms.get("total_ms", verdict.timings_ms.get("total_pipeline_ms", 0.0))

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_log (
                    request_id, session_id, source, trust, action, risk,
                    categories_json, findings_json, layer_status_json,
                    latency_ms, degraded, content_sha256, excerpt_redacted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    verdict.request_id,
                    session_id,
                    verdict.source.value,
                    verdict.trust.value,
                    verdict.action,
                    verdict.risk,
                    json.dumps(cats_list),
                    json.dumps(findings_summary),
                    json.dumps(verdict.layer_status),
                    total_latency,
                    1 if verdict.degraded else 0,
                    verdict.content_sha256,
                    excerpt,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def query(
        self,
        limit: int = 50,
        offset: int = 0,
        source: Optional[str] = None,
        action: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Query audit log entries with filtering (§8.1, §10)."""
        query_sql = "SELECT id, ts, request_id, session_id, source, trust, action, risk, categories_json, findings_json, layer_status_json, latency_ms, degraded, content_sha256, excerpt_redacted FROM audit_log WHERE 1=1"
        params: list[Any] = []

        if source:
            query_sql += " AND source = ?"
            params.append(source)
        if action:
            query_sql += " AND action = ?"
            params.append(action)

        query_sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query_sql, params)
            for r in cursor.fetchall():
                rows.append({
                    "id": r["id"],
                    "ts": r["ts"],
                    "request_id": r["request_id"],
                    "session_id": r["session_id"],
                    "source": r["source"],
                    "trust": r["trust"],
                    "action": r["action"],
                    "risk": r["risk"],
                    "categories": json.loads(r["categories_json"] or "[]"),
                    "findings": json.loads(r["findings_json"] or "[]"),
                    "layer_status": json.loads(r["layer_status_json"] or "{}"),
                    "latency_ms": r["latency_ms"],
                    "degraded": bool(r["degraded"]),
                    "content_sha256": r["content_sha256"],
                    "excerpt_redacted": r["excerpt_redacted"],
                })

        return rows


_AUDIT_LOGGER = None


def get_audit_logger() -> AuditLogger:
    global _AUDIT_LOGGER
    if _AUDIT_LOGGER is None:
        _AUDIT_LOGGER = AuditLogger()
    return _AUDIT_LOGGER
