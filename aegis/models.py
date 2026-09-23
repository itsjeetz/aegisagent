"""Core data models for AegisAgent (§4)."""

from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field


class InputSource(str, Enum):
    USER_MESSAGE = "user_message"
    WEB_PAGE = "web_page"
    PDF = "pdf"
    EMAIL = "email"
    MARKDOWN = "markdown"
    HTML = "html"
    DOCX = "docx"
    API_RESPONSE = "api_response"
    OCR_TEXT = "ocr_text"
    SOURCE_CODE = "source_code"
    IMAGE = "image"


class AttackType(str, Enum):
    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
    ROLE_CHANGE = "ROLE_CHANGE"
    SECRET_EXTRACTION = "SECRET_EXTRACTION"
    TOOL_ABUSE = "TOOL_ABUSE"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    CONTEXT_POISONING = "CONTEXT_POISONING"
    MULTI_STEP_JAILBREAK = "MULTI_STEP_JAILBREAK"
    ENCODED_INSTRUCTIONS = "ENCODED_INSTRUCTIONS"
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"


class Trust(str, Enum):
    USER = "user"
    UNTRUSTED = "untrusted"  # everything except direct user chat


OriginType = Literal[
    "visible",
    "hidden",
    "metadata",
    "comment",
    "alt_text",
    "ocr",
    "exif",
    "header",
    "code_comment",
    "string_literal",
    "json_value",
    "json_key",
]

DetectorLayer = Literal["rules", "classifier", "judge", "session", "guard"]
FirewallAction = Literal["ALLOW", "SANITIZE", "BLOCK", "ESCALATE"]


class Segment(BaseModel):
    """One extractable piece of a document (§4)."""

    id: str
    text: str
    origin: OriginType
    location: str  # e.g. "page 3", "div#x", "$.items[2].note"
    hidden_reason: str | None = None  # "white_text","display_none","vanish","tiny_font","offscreen","faint_ocr",...


class Finding(BaseModel):
    """Detection finding on a segment (§4)."""

    attack_type: AttackType
    score: float = Field(ge=0.0, le=1.0)
    segment_id: str
    span_original: tuple[int, int] | None = None  # offsets in ORIGINAL segment text
    evidence: str = Field(max_length=200)  # short excerpt
    detector: str
    layer: DetectorLayer
    variant_chain: list[str] = Field(default_factory=list)


class Verdict(BaseModel):
    """Verdict returned by the firewall pipeline (§4)."""

    request_id: str
    source: InputSource
    trust: Trust
    action: FirewallAction
    risk: float = Field(ge=0.0, le=1.0)
    category_scores: dict[AttackType, float] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    degraded: bool = False
    layer_status: dict[str, dict[str, Any]] = Field(default_factory=dict)
    sanitized_text: str | None = None
    envelope_text: str | None = None
    timings_ms: dict[str, float] = Field(default_factory=dict)
    content_sha256: str


class HealthResponse(BaseModel):
    """System health and capability status (§10, §8.4)."""

    status: str
    version: str
    ocr_available: bool
    classifier_backend: str
    judge_available: bool
    anthropic_key_set: bool
    judge_model: str
    agent_model: str
    hf_classifier_id: str | None = None
    degraded_mode: bool
