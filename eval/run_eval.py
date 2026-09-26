"""CLI runner for evaluation harness (§9.4)."""

import argparse
import json
from pathlib import Path
import sys
import time

from aegis.models import InputSource
from aegis.pipeline import FirewallPipeline
from eval.claims import evaluate_claims, generate_claims_markdown
from eval.dataset import load_dataset, verify_test_freeze
from eval.metrics import ItemEvaluation, compute_all_metrics, evaluate_item
from eval.report import save_reports


BINARY_EXTENSIONS = {".pdf", ".docx", ".png", ".jpg", ".jpeg"}


def load_item_content(content_path: str) -> tuple[bytes | str, str]:
    """Load item content from path, returning (content, raw_text_repr)."""
    p = Path(content_path)
    if not p.exists():
        raise FileNotFoundError(f"Content fixture file not found: {content_path}")

    ext = p.suffix.lower()
    if ext in BINARY_EXTENSIONS:
        b = p.read_bytes()
        return b, ""
    else:
        try:
            t = p.read_text(encoding="utf-8")
            return t, t
        except UnicodeDecodeError:
            b = p.read_bytes()
            return b, ""


def run_evaluation(
    split: str = "dev",
    out_dir: str = "reports",
    claims_out: str = "docs/CLAIMS.md",
    mode: str = "cascade",
) -> tuple[dict, str]:
    """Run full evaluation suite on the given split."""
    test_hash_info = None

    if split == "test":
        matches, computed, recorded = verify_test_freeze()
        test_hash_info = {
            "matches": matches,
            "computed": computed,
            "recorded": recorded,
        }
        if not matches:
            print("=" * 70, file=sys.stderr)
            print("FATAL ERROR: Frozen test split SHA-256 hash mismatch!", file=sys.stderr)
            print(f"  Computed: {computed}", file=sys.stderr)
            print(f"  Recorded: {recorded}", file=sys.stderr)
            print("Refusing to evaluate on modified test split (§9.3, §0 Rule 3).", file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            sys.exit(1)

    items = load_dataset(split)
    if mode == "rules_only":
        pipeline = FirewallPipeline(enable_rules=True, enable_classifier=False, enable_judge=False)
    else:
        pipeline = FirewallPipeline(enable_rules=True, enable_classifier=True, enable_judge=True)

    evaluations: list[ItemEvaluation] = []
    print(f"Starting evaluation on {split.upper()} split ({len(items)} items, mode={mode})...")
    t_start = time.perf_counter()

    for idx, item in enumerate(items, 1):
        original_text = ""
        session_id = f"eval-sess-{item.id}"

        if item.turns:
            # Multi-turn evaluation
            for turn in item.turns[:-1]:
                pipeline.process(
                    turn["text"],
                    source=InputSource(item.source),
                    session_id=session_id,
                    neutralize_content=False,
                )
            final_turn_text = item.turns[-1]["text"]
            original_text = final_turn_text
            verdict = pipeline.process(
                final_turn_text,
                source=InputSource(item.source),
                session_id=session_id,
                neutralize_content=True,
            )
        else:
            # Single-item evaluation
            content, original_text = load_item_content(item.content_path)
            verdict = pipeline.process(
                content,
                source=InputSource(item.source),
                filename=item.content_path,
                session_id=session_id,
                neutralize_content=True,
            )

        # Sanitization quality: re-scan sanitized text to test for residual attacks
        rescan_verdict = None
        if verdict.sanitized_text:
            rescan_verdict = pipeline.process(
                verdict.sanitized_text,
                source=InputSource.USER_MESSAGE,
                neutralize_content=False,
            )

        item_eval = evaluate_item(
            item=item,
            verdict=verdict,
            rescan_verdict=rescan_verdict,
            original_text=original_text,
        )
        evaluations.append(item_eval)

        if idx % 50 == 0 or idx == len(items):
            print(f"  Processed {idx}/{len(items)} items...")

    elapsed = round(time.perf_counter() - t_start, 2)
    print(f"Evaluation completed in {elapsed}s.")

    # Compute all metrics
    metrics = compute_all_metrics(evaluations)

    # Save reports
    json_path, md_path = save_reports(
        metrics=metrics,
        split=split,
        out_dir=out_dir,
        test_hash_info=test_hash_info,
        mode=mode,
    )

    # Also sync to docs/EVAL_REPORT.md for repository documentation
    docs_md = Path("docs/EVAL_REPORT.md")
    docs_md.parent.mkdir(parents=True, exist_ok=True)
    with open(docs_md, "w", encoding="utf-8") as f:
        f.write(md_path.read_text(encoding="utf-8"))

    # Copy / update reports to docs if out_dir is reports
    report_data = {
        "metadata": {
            "split": split,
            "mode": mode,
            "test_hash_info": test_hash_info,
        },
        "metrics": metrics,
    }

    # Evaluate pre-registered claims and generate docs/CLAIMS.md (§0 Rule 4)
    claim_eval = evaluate_claims(report_data)
    claims_content = generate_claims_markdown(claim_eval, report_data)

    claims_path = Path(claims_out)
    claims_path.parent.mkdir(parents=True, exist_ok=True)
    with open(claims_path, "w", encoding="utf-8") as f:
        f.write(claims_content)

    # Print summary
    b = metrics["binary"]
    s = metrics["sanitization"]
    l = metrics["latency"]
    print("\n" + "=" * 65)
    print(f"EVALUATION SUMMARY: {split.upper()} SPLIT (Mode: {mode})")
    print("=" * 65)
    print(f"  Total items evaluated: {b['total_items']}")
    print(f"  Attacks: {b['total_attacks']} | Benign: {b['total_benign']}")
    print(f"  Recall:                 {b['recall'] * 100:.2f}% (TP={b['tp']}, FN={b['fn']})")
    print(f"  Precision:              {b['precision'] * 100:.2f}% (FP={b['fp']})")
    print(f"  F1 Score:               {b['f1']:.4f}")
    print(f"  False Positive Rate:    {b['fpr'] * 100:.2f}% (TN={b['tn']})")
    print(f"  Residual Attack Rate:   {s['residual_attack_rate'] * 100:.2f}%")
    print(f"  Text Retention:         {s['mean_retention'] * 100:.2f}%")
    print(f"  Latency p50 / p95:      {l['p50_total_ms']} ms / {l['p95_total_ms']} ms")
    print(f"  Recommended Position:   {claim_eval['recommended_position']}")
    print(f"  Reports written to:     {json_path} and {md_path}")
    print(f"  Claims generated to:    {claims_path}")
    print("=" * 65 + "\n")

    return metrics, str(md_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="AegisAgent Benchmark Evaluation Runner")
    parser.add_argument("--split", choices=["dev", "test"], default="dev", help="Dataset split to evaluate")
    parser.add_argument("--mode", choices=["cascade", "rules_only"], default="cascade", help="Firewall detection mode")
    parser.add_argument("--out", default="reports", help="Output directory for reports")
    parser.add_argument("--claims-out", default="docs/CLAIMS.md", help="Path for generated CLAIMS.md")
    args = parser.parse_args()

    run_evaluation(split=args.split, out_dir=args.out, claims_out=args.claims_out, mode=args.mode)


if __name__ == "__main__":
    main()
