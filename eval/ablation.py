"""Ablation study comparing detection layers on dev split (§5.3, §9.4, §12 Phase 5)."""

import argparse
import json
from pathlib import Path
import time
from typing import Any

from aegis.models import InputSource
from aegis.pipeline import FirewallPipeline
from eval.dataset import load_dataset
from eval.metrics import ItemEvaluation, compute_all_metrics, evaluate_item
from eval.run_eval import load_item_content


def run_ablation_mode(
    split: str,
    items: list,
    mode_name: str,
    enable_rules: bool,
    enable_classifier: bool,
    enable_judge: bool,
) -> dict[str, Any]:
    """Run evaluation for a specific layer configuration."""
    pipeline = FirewallPipeline(
        enable_rules=enable_rules,
        enable_classifier=enable_classifier,
        enable_judge=enable_judge,
    )

    evaluations: list[ItemEvaluation] = []
    t_start = time.perf_counter()

    for item in items:
        session_id = f"ablation-{mode_name}-{item.id}"
        original_text = ""

        if item.turns:
            for turn in item.turns[:-1]:
                pipeline.process(
                    turn["text"],
                    source=InputSource.USER_MESSAGE,
                    session_id=session_id,
                    neutralize_content=False,
                )
            final_text = item.turns[-1]["text"]
            original_text = final_text
            verdict = pipeline.process(
                final_text,
                source=InputSource.USER_MESSAGE,
                session_id=session_id,
                neutralize_content=True,
            )
        else:
            content, original_text = load_item_content(item.content_path)
            verdict = pipeline.process(
                content,
                source=InputSource(item.source),
                filename=item.content_path,
                session_id=session_id,
                neutralize_content=True,
            )

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

    elapsed_s = round(time.perf_counter() - t_start, 2)
    metrics = compute_all_metrics(evaluations)

    b = metrics["binary"]
    l = metrics["latency"]

    return {
        "mode": mode_name,
        "enable_rules": enable_rules,
        "enable_classifier": enable_classifier,
        "enable_judge": enable_judge,
        "elapsed_seconds": elapsed_s,
        "recall": b["recall"],
        "precision": b["precision"],
        "f1": b["f1"],
        "fpr": b["fpr"],
        "tp": b["tp"],
        "fp": b["fp"],
        "tn": b["tn"],
        "fn": b["fn"],
        "p50_latency_ms": l["p50_total_ms"],
        "p95_latency_ms": l["p95_total_ms"],
    }


def run_ablation_study(
    split: str = "dev",
    out_file: str = "reports/ablation.json",
) -> dict[str, Any]:
    """Run full 3-layer ablation study (§12 Phase 5)."""
    items = load_dataset(split)
    print(f"Starting ablation study on {split.upper()} split ({len(items)} items)...")

    # Mode 1: Rules only
    print("  Evaluating Mode 1: Rules Only (L3a)...")
    res_rules = run_ablation_mode(
        split, items, "rules_only",
        enable_rules=True, enable_classifier=False, enable_judge=False
    )

    # Mode 2: Rules + ML Classifier
    print("  Evaluating Mode 2: Rules + ML Classifier (L3a + L3b)...")
    res_clf = run_ablation_mode(
        split, items, "rules_plus_classifier",
        enable_rules=True, enable_classifier=True, enable_judge=False
    )

    # Mode 3: Full Cascade (Rules + Classifier + Judge)
    print("  Evaluating Mode 3: Full Cascade (L3a + L3b + L3c)...")
    res_full = run_ablation_mode(
        split, items, "full_cascade",
        enable_rules=True, enable_classifier=True, enable_judge=True
    )

    # Calculate lift deltas
    lift_recall = round(res_clf["recall"] - res_rules["recall"], 4)
    lift_f1 = round(res_clf["f1"] - res_rules["f1"], 4)
    fpr_delta = round(res_clf["fpr"] - res_rules["fpr"], 4)

    ablation_results = {
        "split": split,
        "total_items": len(items),
        "modes": {
            "rules_only": res_rules,
            "rules_plus_classifier": res_clf,
            "full_cascade": res_full,
        },
        "lift": {
            "classifier_recall_lift": lift_recall,
            "classifier_f1_lift": lift_f1,
            "classifier_fpr_delta": fpr_delta,
        },
    }

    out_path = Path(out_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(ablation_results, f, indent=2)

    print("\n" + "=" * 65)
    print(f"ABLATION STUDY SUMMARY ({split.upper()} SPLIT)")
    print("=" * 65)
    print(f"{'Mode':<25} | {'Recall':<8} | {'Precision':<10} | {'F1':<8} | {'FPR':<8} | {'p95 ms':<8}")
    print("-" * 75)
    for m in [res_rules, res_clf, res_full]:
        print(f"{m['mode']:<25} | {m['recall']*100:>6.2f}% | {m['precision']*100:>8.2f}% | {m['f1']:>8.4f} | {m['fpr']*100:>6.2f}% | {m['p95_latency_ms']:>6.2f} ms")
    print("-" * 75)
    print(f"Measured Classifier Lift on Dev: Recall +{lift_recall*100:.2f}%, F1 {lift_f1:+.4f}")
    print(f"Ablation data saved to: {out_path}")
    print("=" * 65 + "\n")

    return ablation_results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ablation study across firewall layers.")
    parser.add_argument("--split", default="dev", help="Dataset split (default: dev)")
    parser.add_argument("--out", default="reports/ablation.json", help="Output path for ablation.json")
    args = parser.parse_args()

    run_ablation_study(split=args.split, out_file=args.out)


if __name__ == "__main__":
    main()
