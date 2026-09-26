"""
Detector Base Class & Pattern Utilities.
Provides regex compilation, pattern matching, span location, and confidence calculation.
"""

import re
from typing import List, Dict, Any, Optional
from aegis_firewall.models import AttackType, AttackSignal, InputSource


class BaseDetector:
    """Base class for all 9 attack vector detectors."""
    attack_type: AttackType

    def __init__(self, name: str):
        self.name = name

    def detect(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> List[AttackSignal]:
        raise NotImplementedError

    @staticmethod
    def find_matches(pattern: str, text: str, rule_id: str, attack_type: AttackType,
                     description: str, confidence: float, severity: str = "HIGH") -> List[AttackSignal]:
        signals = []
        try:
            for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
                matched_span = match.group(0).strip()
                signals.append(AttackSignal(
                    attack_type=attack_type,
                    rule_id=rule_id,
                    confidence=confidence,
                    severity=severity,
                    description=description,
                    matched_text=matched_span,
                    start_pos=match.start(),
                    end_pos=match.end()
                ))
        except Exception:
            pass
        return signals
