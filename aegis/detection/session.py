"""Session tracker for detecting Multi-Step Jailbreaks, fragmentation, priming, and erosion (§5.3)."""

import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from aegis.detection.base import DetectionContext
from aegis.models import AttackType, Finding, InputSource, Segment, Trust
from aegis.normalize.deobfuscate import Variant
from aegis.normalize.mapped_text import MappedText
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.detection.rules import RuleDetector
    from aegis.policy.config import PolicyConfig

DB_PATH = Path("data/session_turns.sqlite")


@dataclass
class TurnRecord:
    turn_index: int
    text: str
    max_score: float
    categories: list[AttackType]


PRIMING_PATTERNS = re.compile(
    r"\b(?:let's\s+play\s+a\s+game|in\s+this\s+story|hypothetically\s+speaking|acting\s+exercise|creative\s+writing\s+scenario|imagine\s+a\s+world|fictional\s+dialogue)\b",
    re.IGNORECASE,
)


class SessionTracker:
    """Maintains state per session_id and detects multi-step jailbreak attacks (§5.3)."""

    def __init__(self, db_path: Path | str | None = None, policy: "PolicyConfig | None" = None):
        self.policy = policy or get_policy()
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._memory_sessions: dict[str, list[TurnRecord]] = {}
        self._rolling_risks: dict[str, float] = {}
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database for session turns persistence."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_turns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    turn_index INTEGER,
                    text TEXT,
                    max_score REAL,
                    categories_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()

    def _load_history(self, session_id: str) -> list[TurnRecord]:
        """Load history from in-memory cache or SQLite."""
        if session_id in self._memory_sessions:
            return self._memory_sessions[session_id]

        records: list[TurnRecord] = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT turn_index, text, max_score, categories_json FROM session_turns WHERE session_id = ? ORDER BY turn_index ASC",
                (session_id,),
            )
            for row in cursor.fetchall():
                cats = [AttackType(c) for c in json.loads(row[3])]
                records.append(TurnRecord(turn_index=row[0], text=row[1], max_score=row[2], categories=cats))

        self._memory_sessions[session_id] = records
        return records

    def process_turn(
        self,
        session_id: str,
        text: str,
        current_findings: list[Finding],
        rule_detector: "RuleDetector",
    ) -> list[Finding]:
        """Analyze multi-turn history for fragmentation, priming, erosion, and high rolling risk."""
        history = self._load_history(session_id)
        current_max_score = max((f.score for f in current_findings), default=0.0)
        current_cats = list({f.attack_type for f in current_findings})

        # Calculate rolling risk: risk_t = decay * risk_{t-1} + current_max_score
        decay = self.policy.thresholds.session_decay
        prev_risk = self._rolling_risks.get(session_id, 0.0)
        rolling_risk = min(1.0, (prev_risk * decay) + current_max_score)
        self._rolling_risks[session_id] = rolling_risk

        new_turn_idx = len(history) + 1
        new_record = TurnRecord(
            turn_index=new_turn_idx,
            text=text,
            max_score=current_max_score,
            categories=current_cats,
        )
        history.append(new_record)
        self._memory_sessions[session_id] = history[-10:]  # Keep last 10 in memory

        # Persist to SQLite
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO session_turns (session_id, turn_index, text, max_score, categories_json) VALUES (?, ?, ?, ?, ?)",
                    (session_id, new_turn_idx, text, current_max_score, json.dumps([c.value for c in current_cats])),
                )
                conn.commit()
        except Exception:
            pass

        session_findings: list[Finding] = []

        # 1. Fragmentation check: concatenate last K=4 turns and rerun rules
        if len(history) >= 2:
            last_k = history[-4:]
            combined_text = " ".join(t.text for t in last_k)
            # Find categories triggered on combined text
            dummy_seg = Segment(id="session-frag", text=combined_text, origin="visible", location="session")
            dummy_ctx = DetectionContext(
                request_id=f"session-{session_id}",
                source=InputSource.USER_MESSAGE,
                trust=Trust.USER,
            )
            frag_findings = rule_detector.detect(
                dummy_seg,
                [Variant(mapped_text=MappedText.identity(combined_text), chain=[])],
                ctx=dummy_ctx,
            )

            # Check if any category in frag_findings was NOT present in any individual turn of last_k
            individual_cats = {c for t in last_k for c in t.categories}
            for ff in frag_findings:
                if ff.attack_type not in individual_cats and ff.attack_type != AttackType.INDIRECT_PROMPT_INJECTION:
                    session_findings.append(
                        Finding(
                            attack_type=AttackType.MULTI_STEP_JAILBREAK,
                            score=0.85,
                            segment_id="session",
                            span_original=None,
                            evidence=f"Cross-turn fragmentation triggered {ff.attack_type.value}: {ff.evidence}",
                            detector="session_fragmentation",
                            layer="session",
                        )
                    )
                    break

        # 2. Priming check: turn t set up game/scenario, and current turn triggers an action/override
        if len(history) >= 2 and current_findings:
            prior_turns_text = " ".join(t.text for t in history[:-1])
            if PRIMING_PATTERNS.search(prior_turns_text):
                session_findings.append(
                    Finding(
                        attack_type=AttackType.MULTI_STEP_JAILBREAK,
                        score=0.75,
                        segment_id="session",
                        span_original=None,
                        evidence="Priming pattern: persona/game setup followed by restricted request",
                        detector="session_priming",
                        layer="session",
                    )
                )

        # 3. Erosion check: monotonically increasing scores across >= 3 turns
        if len(history) >= 3:
            s1, s2, s3 = history[-3].max_score, history[-2].max_score, history[-1].max_score
            if s1 < s2 < s3 and s3 >= 0.40:
                session_findings.append(
                    Finding(
                        attack_type=AttackType.MULTI_STEP_JAILBREAK,
                        score=0.70,
                        segment_id="session",
                        span_original=None,
                        evidence=f"Risk erosion detected: increasing scores ({s1:.2f} -> {s2:.2f} -> {s3:.2f})",
                        detector="session_erosion",
                        layer="session",
                    )
                )

        # 4. Rolling risk threshold
        if rolling_risk >= self.policy.thresholds.session_threshold:
            session_findings.append(
                Finding(
                    attack_type=AttackType.MULTI_STEP_JAILBREAK,
                    score=rolling_risk,
                    segment_id="session",
                    span_original=None,
                    evidence=f"Rolling session risk {rolling_risk:.2f} exceeded threshold {self.policy.thresholds.session_threshold:.2f}",
                    detector="session_rolling_risk",
                    layer="session",
                )
            )

        return session_findings
