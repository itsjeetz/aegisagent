"""Metrics collection and aggregation for AegisAgent (§8.1)."""

from collections import defaultdict, deque
import json
import math
from pathlib import Path
import sqlite3
import threading
from typing import Any, Optional

from aegis.models import AttackType, Verdict


class MetricsTracker:
    """In-memory and historical metrics tracker for firewall performance (§8.1)."""

    def __init__(self, max_samples: int = 2000, db_path: str = "data/audit.sqlite"):
        self._lock = threading.Lock()
        self.max_samples = max_samples
        self.db_path = Path(db_path)

        self.total_requests: int = 0
        self.degraded_count: int = 0
        self.judge_invocations: int = 0

        self.action_counts: dict[str, int] = defaultdict(int)
        self.source_counts: dict[str, int] = defaultdict(int)
        self.category_counts: dict[str, int] = defaultdict(int)

        # Latency samples per layer: {"l1_ingestion": deque(), ...}
        self.latencies: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=self.max_samples))

    def record(self, verdict: Verdict) -> None:
        """Record a pipeline verdict into metrics (§8.1)."""
        with self._lock:
            self.total_requests += 1

            if verdict.degraded:
                self.degraded_count += 1

            # Check if judge was invoked
            judge_st = verdict.layer_status.get("judge", {})
            if judge_st.get("status") in ("ok", "degraded_error"):
                if judge_st.get("status") != "disabled":
                    self.judge_invocations += 1

            self.action_counts[verdict.action] += 1
            self.source_counts[verdict.source.value] += 1

            for cat in verdict.category_scores.keys():
                cat_val = cat.value if isinstance(cat, AttackType) else str(cat)
                self.category_counts[cat_val] += 1

            for layer_name, ms in verdict.timings_ms.items():
                self.latencies[layer_name].append(ms)

    def _calc_percentile(self, values: list[float], pct: float) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        k = (len(sorted_vals) - 1) * pct
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return round(sorted_vals[int(k)], 2)
        d0 = sorted_vals[int(f)] * (c - k)
        d1 = sorted_vals[int(c)] * (k - f)
        return round(d0 + d1, 2)

    def get_metrics(self) -> dict[str, Any]:
        """Return aggregated summary metrics (§8.1, §10)."""
        with self._lock:
            # If in-memory is empty but database exists, populate from audit_log
            if self.total_requests == 0 and self.db_path.exists():
                try:
                    with sqlite3.connect(self.db_path) as conn:
                        conn.row_factory = sqlite3.Row
                        cur = conn.execute("SELECT action, source, degraded, latency_ms, categories_json FROM audit_log")
                        rows = cur.fetchall()
                        for r in rows:
                            self.total_requests += 1
                            if r["degraded"]:
                                self.degraded_count += 1
                            self.action_counts[r["action"]] += 1
                            self.source_counts[r["source"]] += 1
                            self.latencies["total_pipeline_ms"].append(float(r["latency_ms"]))
                            cats = json.loads(r["categories_json"] or "[]")
                            for c in cats:
                                self.category_counts[c] += 1
                except Exception:
                    pass

            p50 = {}
            p95 = {}
            for layer, dq in self.latencies.items():
                vals = list(dq)
                p50[layer] = self._calc_percentile(vals, 0.50)
                p95[layer] = self._calc_percentile(vals, 0.95)

            judge_rate = (
                round(self.judge_invocations / self.total_requests, 4)
                if self.total_requests > 0
                else 0.0
            )

            return {
                "total_requests": self.total_requests,
                "degraded_count": self.degraded_count,
                "judge_invocations": self.judge_invocations,
                "judge_invocation_rate": judge_rate,
                "actions": dict(self.action_counts),
                "sources": dict(self.source_counts),
                "categories": dict(self.category_counts),
                "latency_p50_ms": p50,
                "latency_p95_ms": p95,
            }

    def reset(self) -> None:
        """Reset all in-memory counters (useful in testing)."""
        with self._lock:
            self.total_requests = 0
            self.degraded_count = 0
            self.judge_invocations = 0
            self.action_counts.clear()
            self.source_counts.clear()
            self.category_counts.clear()
            self.latencies.clear()


_TRACKER: Optional[MetricsTracker] = None


def get_metrics_tracker() -> MetricsTracker:
    global _TRACKER
    if _TRACKER is None:
        _TRACKER = MetricsTracker()
    return _TRACKER
