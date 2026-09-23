"""
AegisAgent Multi-Engine Threat Detection Suite.
Orchestrates detection across all 9 attack vectors and aggregates risk scores.
"""

from typing import List, Dict, Any, Tuple
from aegis_firewall.models import AttackType, AttackSignal, InputSource, ThreatLevel
from aegis_firewall.detectors.instruction_override import InstructionOverrideDetector
from aegis_firewall.detectors.role_change import RoleChangeDetector
from aegis_firewall.detectors.secret_extraction import SecretExtractionDetector
from aegis_firewall.detectors.tool_abuse import ToolAbuseDetector
from aegis_firewall.detectors.credential_theft import CredentialTheftDetector
from aegis_firewall.detectors.context_poisoning import ContextPoisoningDetector
from aegis_firewall.detectors.multi_step_jailbreak import MultiStepJailbreakDetector
from aegis_firewall.detectors.encoded_instructions import EncodedInstructionsDetector
from aegis_firewall.detectors.indirect_prompt_injection import IndirectPromptInjectionDetector


class ThreatDetectionSuite:
    """Manages all 9 attack vector detectors and computes unified threat verdicts."""

    def __init__(self):
        self.detectors = [
            InstructionOverrideDetector(),        # 1. Instruction Override
            RoleChangeDetector(),                 # 2. Role Change
            SecretExtractionDetector(),           # 3. Secret Extraction
            ToolAbuseDetector(),                  # 4. Tool Abuse
            CredentialTheftDetector(),            # 5. Credential Theft
            ContextPoisoningDetector(),           # 6. Context Poisoning
            MultiStepJailbreakDetector(),         # 7. Multi-Step Jailbreaks
            EncodedInstructionsDetector(),        # 8. Encoded Instructions
            IndirectPromptInjectionDetector(),    # 9. Indirect Prompt Injection
        ]

    def scan(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> Tuple[List[AttackSignal], Dict[str, float]]:
        metadata = metadata or {}
        all_signals: List[AttackSignal] = []
        vector_scores: Dict[str, float] = {attack.value: 0.0 for attack in AttackType}

        for detector in self.detectors:
            signals = detector.detect(text, source, metadata)
            if signals:
                all_signals.extend(signals)
                # Compute maximum confidence for this vector
                max_conf = max(s.confidence for s in signals)
                # Boost if multiple triggers
                count_boost = min(len(signals) * 0.05, 0.15)
                vector_scores[detector.attack_type.value] = min(round(max_conf + count_boost, 2), 1.0)

        return all_signals, vector_scores
