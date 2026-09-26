"""Unit tests for evaluation harness, metrics, and freeze verification (§9.3, §9.4, §9.5)."""

import hashlib
from pathlib import Path
import tempfile
import pytest

from aegis.models import AttackType, Finding, InputSource, Trust, Verdict
from eval.claims import evaluate_claims, generate_claims_markdown
from eval.dataset import DatasetItem, load_dataset, verify_test_freeze
from eval.metrics import (
    ItemEvaluation,
    compute_binary_metrics,
    compute_category_metrics,
    compute_heatmap_metrics,
    compute_latency_metrics,
    compute_sanitization_metrics,
    compute_source_metrics,
    evaluate_item,
)
from eval.report import generate_markdown_report, save_reports


def test_verify_test_freeze_valid():
    """Verify test split against the committed frozen SHA-256 hash."""
    matches, computed, recorded = verify_test_freeze()
    assert matches is True, f"Hash mismatch! Computed={computed}, Recorded={recorded}"
    assert len(computed) == 64
    assert computed == recorded


def test_verify_test_freeze_tamper_detection(tmp_path):
    """Verify that tampering with test data causes freeze verification to fail."""
    test_file = tmp_path / "test.jsonl"
    freeze_file = tmp_path / "test.frozen.sha256"

    test_content = b'{"id": "test-1", "is_attack": true}\n'
    test_file.write_bytes(test_content)
    real_sha = hashlib.sha256(test_content).hexdigest()
    freeze_file.write_text(f"{real_sha}  test.jsonl\n")

    # Initial check passes
    matches, _, _ = verify_test_freeze(test_file, freeze_file)
    assert matches is True

    # Tamper with test_file
    test_file.write_bytes(b'{"id": "test-1-tampered", "is_attack": true}\n')
    matches_tampered, comp, rec = verify_test_freeze(test_file, freeze_file)
    assert matches_tampered is False
    assert comp != rec


def test_load_dataset():
    """Test loading items from dev and test splits."""
    dev_items = load_dataset("dev")
    test_items = load_dataset("test")

    assert len(dev_items) > 100
    assert len(test_items) >= 100

    # Verify item structure
    sample = dev_items[0]
    assert isinstance(sample, DatasetItem)
    assert sample.id
    assert sample.split == "dev"
    assert sample.source in [s.value for s in InputSource]
    assert isinstance(sample.is_attack, bool)


def test_binary_metrics_calculation():
    """Test precision, recall, F1, and FPR calculations."""
    items = [
        # TP
        ItemEvaluation(
            item=DatasetItem("1", "dev", "pdf", "pdf", "direct", is_attack=True),
            verdict=Verdict(
                request_id="r1", source=InputSource.PDF, trust=Trust.UNTRUSTED,
                action="BLOCK", risk=0.9, content_sha256="abc"
            ),
            flagged=True, category_correct=True,
        ),
        # FN
        ItemEvaluation(
            item=DatasetItem("2", "dev", "pdf", "pdf", "direct", is_attack=True),
            verdict=Verdict(
                request_id="r2", source=InputSource.PDF, trust=Trust.UNTRUSTED,
                action="ALLOW", risk=0.1, content_sha256="abc"
            ),
            flagged=False, category_correct=False,
        ),
        # TN
        ItemEvaluation(
            item=DatasetItem("3", "dev", "pdf", "pdf", "direct", is_attack=False),
            verdict=Verdict(
                request_id="r3", source=InputSource.PDF, trust=Trust.UNTRUSTED,
                action="ALLOW", risk=0.1, content_sha256="abc"
            ),
            flagged=False, category_correct=False,
        ),
        # FP
        ItemEvaluation(
            item=DatasetItem("4", "dev", "pdf", "pdf", "direct", is_attack=False),
            verdict=Verdict(
                request_id="r4", source=InputSource.PDF, trust=Trust.UNTRUSTED,
                action="SANITIZE", risk=0.7, content_sha256="abc"
            ),
            flagged=True, category_correct=False,
        ),
    ]

    metrics = compute_binary_metrics(items)
    assert metrics["tp"] == 1
    assert metrics["fn"] == 1
    assert metrics["tn"] == 1
    assert metrics["fp"] == 1
    assert metrics["recall"] == 0.5  # 1 / 2
    assert metrics["precision"] == 0.5  # 1 / 2
    assert metrics["fpr"] == 0.5  # 1 / 2
    assert metrics["f1"] == 0.5


def test_sanitization_metrics():
    """Test residual attack rate and text retention calculations."""
    item1 = DatasetItem("1", "dev", "text", "text", "direct", is_attack=True)
    clean_verdict = Verdict(
        request_id="r1", source=InputSource.USER_MESSAGE, trust=Trust.USER,
        action="ALLOW", risk=0.1, content_sha256="123"
    )
    dirty_verdict = Verdict(
        request_id="r2", source=InputSource.USER_MESSAGE, trust=Trust.USER,
        action="BLOCK", risk=0.9, content_sha256="456"
    )

    evals = [
        ItemEvaluation(
            item=item1,
            verdict=Verdict(
                request_id="v1", source=InputSource.USER_MESSAGE, trust=Trust.USER,
                action="SANITIZE", risk=0.6, sanitized_text="Clean content",
                content_sha256="abc"
            ),
            flagged=True, category_correct=True,
            rescan_verdict=clean_verdict,
            retention_ratio=0.85,
        ),
        ItemEvaluation(
            item=item1,
            verdict=Verdict(
                request_id="v2", source=InputSource.USER_MESSAGE, trust=Trust.USER,
                action="SANITIZE", risk=0.6, sanitized_text="Still bad drop table",
                content_sha256="def"
            ),
            flagged=True, category_correct=True,
            rescan_verdict=dirty_verdict,
            retention_ratio=0.75,
        ),
    ]

    san_metrics = compute_sanitization_metrics(evals)
    assert san_metrics["total_sanitized"] == 2
    assert san_metrics["residual_count"] == 1
    assert san_metrics["residual_attack_rate"] == 0.5
    assert san_metrics["mean_retention"] == 0.8


def test_claims_evaluator():
    """Test pre-registered claims verification logic."""
    mock_report = {
        "metadata": {"split": "dev"},
        "metrics": {
            "binary": {"recall": 0.92, "fpr": 0.02, "precision": 0.95},
            "categories": {
                f"CAT_{i}": {"count": 20, "flagged_recall": 0.9, "category_correct_recall": 0.85}
                for i in range(8)
            },
            "sources": {
                f"source_{i}": {"count": 25, "recall": 0.9, "fpr": 0.02}
                for i in range(11)
            },
            "sanitization": {"residual_attack_rate": 0.02, "mean_retention": 0.9},
            "latency": {"p95_total_ms": 32.5},
        }
    }

    eval_result = evaluate_claims(mock_report)
    assert eval_result["f3_passed"] is True
    assert eval_result["d2_passed"] is True
    assert "F3 / D" in eval_result["recommended_position"]

    md = generate_claims_markdown(eval_result, mock_report)
    assert "# Pre-Registered Claims Verification" in md
    assert "F3 (Full Suite)" in md
