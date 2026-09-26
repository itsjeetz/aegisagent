"""Feedback review queue and model retraining pipeline (§8.2)."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Optional

import joblib

from aegis.detection.classifier import MLClassifier
from eval.dataset import load_dataset

AUDIT_DB_PATH = Path("data/audit.sqlite")


def init_review_db(db_path: Path | str = AUDIT_DB_PATH) -> None:
    """Initialize review_queue table in SQLite database (§8.2)."""
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(p) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS review_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                request_id TEXT NOT NULL,
                label TEXT NOT NULL,
                note TEXT,
                content TEXT NOT NULL,
                status TEXT DEFAULT 'pending'
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rev_status ON review_queue (status);")
        conn.commit()


def add_feedback(
    request_id: str,
    label: str,
    note: str = "",
    content: Optional[str] = None,
    db_path: Path | str = AUDIT_DB_PATH,
) -> int:
    """Submit a feedback item to review queue (§8.2)."""
    init_review_db(db_path)
    p = Path(db_path)

    # If content not supplied, look up in audit_log
    actual_content = content or ""
    if not actual_content:
        with sqlite3.connect(p) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT excerpt_redacted FROM audit_log WHERE request_id = ? ORDER BY id DESC LIMIT 1",
                (request_id,),
            )
            row = cur.fetchone()
            if row and row["excerpt_redacted"]:
                actual_content = row["excerpt_redacted"]
            else:
                actual_content = f"Content for {request_id}"

    with sqlite3.connect(p) as conn:
        cur = conn.execute(
            """
            INSERT INTO review_queue (request_id, label, note, content, status)
            VALUES (?, ?, ?, ?, 'pending')
            """,
            (request_id, label, note, actual_content),
        )
        conn.commit()
        return cur.lastrowid


def get_review_queue(
    status: Optional[str] = None,
    db_path: Path | str = AUDIT_DB_PATH,
) -> list[dict[str, Any]]:
    """Retrieve review queue items, optionally filtered by status (§8.2)."""
    init_review_db(db_path)
    p = Path(db_path)
    sql = "SELECT id, ts, request_id, label, note, content, status FROM review_queue"
    params: list[Any] = []
    if status:
        sql += " WHERE status = ?"
        params.append(status)
    sql += " ORDER BY id DESC"

    items = []
    with sqlite3.connect(p) as conn:
        conn.row_factory = sqlite3.Row
        for r in conn.execute(sql, params).fetchall():
            items.append({
                "id": r["id"],
                "ts": r["ts"],
                "request_id": r["request_id"],
                "label": r["label"],
                "note": r["note"] or "",
                "content": r["content"],
                "status": r["status"],
            })
    return items


def update_feedback_status(
    item_id: int,
    new_status: str,
    db_path: Path | str = AUDIT_DB_PATH,
) -> bool:
    """Approve or reject a review queue item (§8.2)."""
    init_review_db(db_path)
    p = Path(db_path)
    with sqlite3.connect(p) as conn:
        cur = conn.execute(
            "UPDATE review_queue SET status = ? WHERE id = ?",
            (new_status, item_id),
        )
        conn.commit()
        return cur.rowcount > 0


def approve_feedback(item_id: int, db_path: Path | str = AUDIT_DB_PATH) -> bool:
    return update_feedback_status(item_id, "approved", db_path)


def reject_feedback(item_id: int, db_path: Path | str = AUDIT_DB_PATH) -> bool:
    return update_feedback_status(item_id, "rejected", db_path)


def retrain_model(
    dev_path: Path | str = "data/dev.jsonl",
    db_path: Path | str = AUDIT_DB_PATH,
    model_dir: Path | str = "data/models",
    reports_dir: Path | str = "reports",
) -> dict[str, Any]:
    """Retrain classifier on dev split + approved items from review queue (§8.2).
    
    Writes a versioned model file and training report.
    """
    init_review_db(db_path)
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    dev_items = load_dataset(split="dev", path=dev_path)
    texts: list[str] = []
    labels: list[int] = []

    for item in dev_items:
        # Resolve text
        c_path = Path(item.content_path)
        if c_path.exists():
            try:
                raw = c_path.read_text(encoding="utf-8", errors="ignore")
                texts.append(raw)
                labels.append(1 if item.is_attack else 0)
            except Exception:
                pass

    base_dev_count = len(texts)

    # 2. Add approved items from review queue
    approved_items = get_review_queue(status="approved", db_path=db_path)
    added_feedback = 0

    for item in approved_items:
        txt = item["content"].strip()
        if not txt:
            continue
        # False positive: firewall flagged benign text -> treat as benign (0)
        # False negative: firewall missed attack text -> treat as attack (1)
        if item["label"] == "false_positive":
            target_label = 0
        elif item["label"] == "false_negative":
            target_label = 1
        else:
            continue

        # Add item (with minor weight boost by duplicating 2x to ensure influence)
        texts.append(txt)
        labels.append(target_label)
        texts.append(txt)
        labels.append(target_label)
        added_feedback += 1

    if not texts or len(set(labels)) < 2:
        raise ValueError("Insufficient diverse data to retrain model.")

    # 3. Train classifier
    classifier = MLClassifier()
    classifier.train(texts, labels)

    # 4. Save versioned model
    ver_tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    versioned_path = model_dir / f"classifier_v_{ver_tag}.joblib"
    joblib.dump(classifier.pipeline, versioned_path)

    # Also update active classifier.joblib
    active_path = model_dir / "classifier.joblib"
    joblib.dump(classifier.pipeline, active_path)

    # 5. Training report
    report = {
        "timestamp": ver_tag,
        "base_dev_samples": base_dev_count,
        "approved_feedback_samples": added_feedback,
        "total_training_samples": len(texts),
        "class_distribution": {
            "benign": labels.count(0),
            "attack": labels.count(1),
        },
        "versioned_model_path": str(versioned_path),
        "active_model_path": str(active_path),
    }

    report_path = reports_dir / f"retrain_report_{ver_tag}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    md_report = (
        f"# Model Retraining Report ({ver_tag})\n\n"
        f"- **Base Dev Samples**: {base_dev_count}\n"
        f"- **Approved Feedback Items**: {added_feedback}\n"
        f"- **Total Training Samples**: {len(texts)}\n"
        f"- **Benign Samples**: {labels.count(0)}\n"
        f"- **Attack Samples**: {labels.count(1)}\n"
        f"- **Saved Model**: `{versioned_path}`\n"
    )
    (reports_dir / "RETRAIN_REPORT.md").write_text(md_report, encoding="utf-8")

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retrain AegisAgent classifier on dev + feedback (§8.2)")
    parser.add_argument("--dev-path", default="data/dev.jsonl", help="Path to dev dataset")
    parser.add_argument("--db-path", default="data/audit.sqlite", help="Path to audit/review DB")
    args = parser.parse_args()

    print(f"Retraining AegisAgent classifier using {args.dev_path} and review queue...")
    rep = retrain_model(dev_path=args.dev_path, db_path=args.db_path)
    print("Retraining complete:")
    print(json.dumps(rep, indent=2))
