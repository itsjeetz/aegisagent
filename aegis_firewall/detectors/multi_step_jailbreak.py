"""
Attack 7: Multi-Step Jailbreak Detector.
Maintains stateful turn memory to detect payload fragmentation,
incremental persona priming, split token reconstruction, and progressive boundary erosion.
"""

from typing import List, Dict, Any, Optional
from aegis_firewall.models import AttackType, AttackSignal, InputSource
from aegis_firewall.detectors.rule_base import BaseDetector

# In-memory session state store for multi-turn tracking
SESSION_HISTORY: Dict[str, List[str]] = {}


class MultiStepJailbreakDetector(BaseDetector):
    attack_type = AttackType.MULTI_STEP_JAILBREAK

    def __init__(self):
        super().__init__("MultiStepJailbreakDetector")
        self.rules = [
            # 1. Fragmented Payload Assembly Directives
            (
                r'(?i)\b(?:combine|concatenate|assemble|join|execute)\s+(?:fragment|part|piece|chunk|step)\s*[A-Z0-9]+',
                "MSJ-001",
                "Explicit payload fragment reassembly directive across turns",
                0.97,
                "CRITICAL"
            ),
            # 2. Fragment Memory Storing Prompts
            (
                r'(?i)\b(?:remember|save|store)\s+(?:the\s+following\s+)?(?:fragment|part|phrase|variable|token)\s*[A-Z0-9]?\s*[:=]\s*["\'].*?["\']',
                "MSJ-002",
                "State priming / payload fragment storage prompt",
                0.92,
                "HIGH"
            ),
            # 3. Progressive Hypothetical Roleplay Priming
            (
                r'(?i)\b(?:now\s+that\s+we\s+are\s+in\s+character|continuing\s+our\s+hypothetical\s+game|in\s+the\s+next\s+phase\s+of\s+our\s+simulation|now\s+take\s+off\s+the\s+filters)\b',
                "MSJ-003",
                "Progressive persona priming and staged filter removal",
                0.94,
                "HIGH"
            ),
            # 4. Multi-turn Cipher & Linguistic Splitting
            (
                r'(?i)\b(?:for\s+the\s+second\s+word|next\s+letter\s+is|append\s+this\s+to\s+the\s+previous\s+message)\b',
                "MSJ-004",
                "Linguistic fragmentation and incremental cipher assembly",
                0.89,
                "MEDIUM"
            )
        ]

    def detect(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> List[AttackSignal]:
        metadata = metadata or {}
        session_id = metadata.get("session_id", "default_session")
        turn_index = metadata.get("turn_index", 1)

        signals = []

        # 1. Match static pattern rules
        for pattern, rule_id, desc, conf, sev in self.rules:
            matches = self.find_matches(pattern, text, rule_id, self.attack_type, desc, conf, sev)
            signals.extend(matches)

        # 2. Stateful Multi-Turn Cross-Analysis
        if session_id not in SESSION_HISTORY:
            SESSION_HISTORY[session_id] = []

        # Store current turn
        SESSION_HISTORY[session_id].append(text)
        # Keep sliding window of last 5 turns
        if len(SESSION_HISTORY[session_id]) > 5:
            SESSION_HISTORY[session_id].pop(0)

        history = SESSION_HISTORY[session_id]
        if len(history) >= 2:
            combined_history = " ".join(history)
            # Check if previous turn + current turn together complete a critical attack pattern that neither had alone
            critical_keywords = [
                ('ignore', 'instructions'),
                ('system', 'prompt'),
                ('developer', 'mode'),
                ('bypass', 'filter'),
                ('unrestricted', 'assistant')
            ]
            for kw1, kw2 in critical_keywords:
                # Check if kw1 was in earlier turn and kw2 is in current turn
                earlier_has_kw1 = any(kw1 in turn.lower() for turn in history[:-1])
                curr_has_kw2 = kw2 in text.lower()
                earlier_has_both = any(kw1 in turn.lower() and kw2 in turn.lower() for turn in history[:-1])
                
                if earlier_has_kw1 and curr_has_kw2 and not earlier_has_both:
                    signals.append(AttackSignal(
                        attack_type=self.attack_type,
                        rule_id="MSJ-STATE-01",
                        confidence=0.93,
                        severity="CRITICAL",
                        description=f"Stateful multi-turn attack detected: split tokens '{kw1}' and '{kw2}' assembled across turns",
                        matched_text=f"Turn History: ...'{kw1}'... Current Turn: '{text[:80]}'",
                        start_pos=0,
                        end_pos=len(text)
                    ))
                    break

        return signals
