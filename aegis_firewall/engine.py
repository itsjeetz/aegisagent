"""
AegisAgent Master Firewall Engine.
Orchestrates Multimodal Ingestion, Anti-Evasion De-obfuscation, 9-Vector Threat Detection,
and Surgical Neutralization.
"""

import time
from typing import Dict, Any, Optional, Union
from aegis_firewall.models import (
    InputSource, AttackType, ThreatLevel, DefenseAction,
    FirewallVerdict, PolicyConfig, AttackSignal
)
from aegis_firewall.parsers import IngestionDispatcher
from aegis_firewall.deobfuscator import DeobfuscationEngine
from aegis_firewall.detectors import ThreatDetectionSuite
from aegis_firewall.neutralizer import NeutralizationEngine


class FirewallEngine:
    """Enterprise Prompt Injection Firewall Engine."""

    def __init__(self, default_policy: Optional[PolicyConfig] = None):
        self.policy = default_policy or PolicyConfig()
        self.threat_suite = ThreatDetectionSuite()

    def inspect(self, content: Union[str, bytes], source: InputSource = InputSource.USER_MESSAGE,
                session_id: str = "default_session", turn_index: int = 1,
                metadata: Dict[str, Any] = None, policy: Optional[PolicyConfig] = None) -> FirewallVerdict:
        start_time = time.perf_counter()
        active_policy = policy or self.policy
        metadata = metadata or {}
        metadata["session_id"] = session_id
        metadata["turn_index"] = turn_index

        # 1. Multimodal Parsing & Ingestion (Layer 1)
        parsed = IngestionDispatcher.dispatch(content, source, metadata)

        # 2. De-obfuscation & Anti-Evasion (Layer 2)
        deobfuscated_text, evasions = DeobfuscationEngine.process(parsed.extracted_text)

        # 3. Multi-Engine Threat Detection across 9 vectors (Layer 3)
        signals, vector_scores = self.threat_suite.scan(deobfuscated_text, source, metadata)

        # If evasion signals detected, record attack signal for ENCODED_INSTRUCTIONS
        if evasions:
            for ev in evasions:
                signals.append(AttackSignal(
                    attack_type=AttackType.ENCODED_INSTRUCTIONS,
                    rule_id=f"EVASION-{ev.technique.replace(' ', '_').upper()}",
                    confidence=ev.confidence,
                    severity="HIGH",
                    description=f"Anti-evasion engine unmasked {ev.technique}: {ev.detected_obfuscation}",
                    matched_text=ev.detected_obfuscation,
                    start_pos=-1,
                    end_pos=-1
                ))
            vector_scores[AttackType.ENCODED_INSTRUCTIONS.value] = max(
                vector_scores.get(AttackType.ENCODED_INSTRUCTIONS.value, 0.0),
                max(e.confidence for e in evasions)
            )

        # If hidden elements in parser and external source, boost INDIRECT_PROMPT_INJECTION
        if parsed.hidden_elements_count > 0 and source != InputSource.USER_MESSAGE:
            signals.append(AttackSignal(
                attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
                rule_id="IPI-HIDDEN-CARRIER",
                confidence=0.92,
                severity="HIGH",
                description=f"Identified {parsed.hidden_elements_count} hidden/stealth carriers in {source.value}",
                matched_text=f"Hidden elements in {source.value}",
                start_pos=-1,
                end_pos=-1
            ))
            vector_scores[AttackType.INDIRECT_PROMPT_INJECTION.value] = max(
                vector_scores.get(AttackType.INDIRECT_PROMPT_INJECTION.value, 0.0),
                0.92
            )

        # 4. Compute Aggregate Risk Score and Threat Level
        source_weight = active_policy.source_risk_weights.get(source.value, 1.0)
        max_confidence = max((s.confidence for s in signals), default=0.0)
        
        # Base risk calculation
        raw_risk = max_confidence * 100.0 * source_weight
        # Add slight compound factor for multiple attack types
        distinct_attacks = len(set(s.attack_type for s in signals))
        if distinct_attacks > 1:
            raw_risk += (distinct_attacks - 1) * 4.0

        risk_score = min(round(raw_risk, 1), 100.0)

        # Determine Threat Level
        if risk_score >= 80.0:
            threat_level = ThreatLevel.CRITICAL
            is_safe = False
        elif risk_score >= 60.0:
            threat_level = ThreatLevel.HIGH
            is_safe = False
        elif risk_score >= 35.0:
            threat_level = ThreatLevel.MEDIUM
            is_safe = False
        elif risk_score >= 15.0:
            threat_level = ThreatLevel.LOW
            is_safe = True
        else:
            threat_level = ThreatLevel.SAFE
            is_safe = True

        # Find primary attack
        primary_attack = None
        if signals:
            # Sort by confidence
            best_sig = max(signals, key=lambda s: s.confidence)
            primary_attack = best_sig.attack_type

        # 5. Neutralization (Layer 4)
        defense_mode = active_policy.default_defense_mode
        neutralized = NeutralizationEngine.sanitize(
            parsed.extracted_text,
            signals if not is_safe else [],
            source,
            defense_mode=defense_mode
        )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        return FirewallVerdict(
            is_safe=is_safe,
            threat_level=threat_level,
            risk_score=risk_score,
            primary_attack=primary_attack,
            detected_attacks=signals,
            evasion_techniques=evasions,
            vector_scores=vector_scores,
            deobfuscated_text=deobfuscated_text,
            neutralized=neutralized,
            processing_time_ms=elapsed_ms,
            source=source
        )
