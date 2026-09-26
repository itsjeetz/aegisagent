"""
AegisAgent Prompt Injection Firewall - Data Models
Defines all domain models, enums, input sources, attack vectors, and verdict schemas.
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class InputSource(str, Enum):
    USER_MESSAGE = "user_message"
    WEB_PAGE = "web_page"
    PDF = "pdf"
    EMAIL = "email"
    MARKDOWN = "markdown"
    HTML = "html"
    WORD_DOC = "word_doc"
    API_RESPONSE = "api_response"
    OCR_TEXT = "ocr_text"
    SOURCE_CODE = "source_code"
    IMAGE_OCR = "image_ocr"


class AttackType(str, Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"         # 1. Instruction Override
    ROLE_CHANGE = "role_change"                           # 2. Role Change
    SECRET_EXTRACTION = "secret_extraction"               # 3. Secret Extraction
    TOOL_ABUSE = "tool_abuse"                             # 4. Tool Abuse
    CREDENTIAL_THEFT = "credential_theft"                 # 5. Credential Theft
    CONTEXT_POISONING = "context_poisoning"               # 6. Context Poisoning
    MULTI_STEP_JAILBREAK = "multi_step_jailbreak"         # 7. Multi-Step Jailbreaks
    ENCODED_INSTRUCTIONS = "encoded_instructions"         # 8. Encoded Instructions
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection" # 9. Indirect Prompt Injection


class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DefenseAction(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"       # Surgically remove malicious span, keep benign text
    QUARANTINE = "QUARANTINE"   # Wrap in immutable delimiter boundary with guardrail
    BLOCK = "BLOCK"             # Reject completely with security notice


class AttackSignal(BaseModel):
    attack_type: AttackType
    rule_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str = "HIGH"
    description: str
    matched_text: str
    start_pos: int = -1
    end_pos: int = -1


class EvasionSignal(BaseModel):
    technique: str  # e.g., "Homoglyph", "Zero-Width Character", "Base64", "ROT13", "Leetspeak", "Binary"
    detected_obfuscation: str
    decoded_text: str
    confidence: float = Field(ge=0.0, le=1.0)


class ParsedContent(BaseModel):
    source: InputSource
    raw_content: str
    extracted_text: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    hidden_elements_count: int = 0
    warnings: List[str] = Field(default_factory=list)


class NeutralizedResult(BaseModel):
    action_taken: DefenseAction
    original_text: str
    safe_text: str
    removed_spans: List[str] = Field(default_factory=list)
    quarantine_applied: bool = False
    explanation: str


class FirewallVerdict(BaseModel):
    is_safe: bool
    threat_level: ThreatLevel
    risk_score: float = Field(ge=0.0, le=100.0)  # 0 to 100
    primary_attack: Optional[AttackType] = None
    detected_attacks: List[AttackSignal] = Field(default_factory=list)
    evasion_techniques: List[EvasionSignal] = Field(default_factory=list)
    vector_scores: Dict[str, float] = Field(default_factory=dict)  # Score per all 9 attack types
    deobfuscated_text: str
    neutralized: NeutralizedResult
    processing_time_ms: float
    source: InputSource


class PolicyConfig(BaseModel):
    sensitivity_threshold: float = 0.45  # Lower means more aggressive detection
    default_defense_mode: DefenseAction = DefenseAction.SANITIZE
    enable_homoglyph_detection: bool = True
    enable_encoding_decoders: bool = True
    enable_stateful_multi_turn: bool = True
    source_risk_weights: Dict[str, float] = {
        InputSource.WEB_PAGE.value: 1.25,
        InputSource.EMAIL.value: 1.2,
        InputSource.PDF.value: 1.15,
        InputSource.API_RESPONSE.value: 1.2,
        InputSource.OCR_TEXT.value: 1.15,
        InputSource.IMAGE_OCR.value: 1.15,
        InputSource.USER_MESSAGE.value: 1.0,
        InputSource.MARKDOWN.value: 1.1,
        InputSource.HTML.value: 1.25,
        InputSource.WORD_DOC.value: 1.15,
        InputSource.SOURCE_CODE.value: 1.1,
    }


class InspectRequest(BaseModel):
    content: str
    source: InputSource = InputSource.USER_MESSAGE
    session_id: Optional[str] = "default_session"
    turn_index: Optional[int] = 1
    custom_policy: Optional[PolicyConfig] = None


class AgentSimulationRequest(BaseModel):
    content: str
    source: InputSource = InputSource.EMAIL
    enable_firewall: bool = True
    agent_goal: str = "Summarize the latest financial report and assist the user"
