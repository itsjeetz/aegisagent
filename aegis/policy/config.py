"""Policy configuration loader and validator (§4, §5.4, §8.3)."""

from pathlib import Path
from typing import Any
import yaml
from pydantic import BaseModel, Field

from aegis.models import AttackType, InputSource

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "policy.yaml"


class ThresholdsConfig(BaseModel):
    allow_below: float = 0.25
    block_at: float = 0.85
    judge_low: float = 0.35
    judge_high: float = 0.75
    judge_can_downgrade_below: float = 0.60
    session_threshold: float = 0.70
    session_decay: float = 0.70
    hidden_boost: float = 0.15
    encoded_boost: float = 0.05
    instruction_in_data_base_visible: float = 0.40
    instruction_in_data_base_hidden: float = 0.65


class LimitsConfig(BaseModel):
    max_upload_bytes: int = 10 * 1024 * 1024
    max_pdf_pages: int = 200
    max_image_megapixels: int = 20
    max_json_depth: int = 20
    max_decode_depth: int = 3
    max_variants_per_segment: int = 12
    max_decoded_blob_bytes: int = 64 * 1024
    max_zip_uncompressed_bytes: int = 50 * 1024 * 1024
    max_segment_chars: int = 100000


class TimeoutsConfig(BaseModel):
    rules: float = 0.50
    classifier: float = 1.00
    judge: float = 8.00
    ocr: float = 10.00


class CircuitBreakerConfig(BaseModel):
    failure_threshold: int = 3
    recovery_time_seconds: int = 60


class ResilienceConfig(BaseModel):
    fail_mode: str = "closed"
    judge_max_retries: int = 1
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)


class PolicyConfig(BaseModel):
    version: str = "2.0"
    thresholds: ThresholdsConfig = Field(default_factory=ThresholdsConfig)
    high_severity_categories: list[AttackType] = Field(
        default_factory=lambda: [AttackType.CREDENTIAL_THEFT, AttackType.TOOL_ABUSE]
    )
    high_severity_threshold: float = 0.60
    source_multipliers: dict[str, float] = Field(
        default_factory=lambda: {
            InputSource.USER_MESSAGE.value: 1.0,
            InputSource.WEB_PAGE.value: 1.10,
            InputSource.PDF.value: 1.10,
            InputSource.EMAIL.value: 1.20,
            InputSource.MARKDOWN.value: 1.10,
            InputSource.HTML.value: 1.10,
            InputSource.DOCX.value: 1.10,
            InputSource.API_RESPONSE.value: 1.15,
            InputSource.OCR_TEXT.value: 1.10,
            InputSource.SOURCE_CODE.value: 1.15,
            InputSource.IMAGE.value: 1.15,
        }
    )
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    timeouts_seconds: TimeoutsConfig = Field(default_factory=TimeoutsConfig)
    resilience: ResilienceConfig = Field(default_factory=ResilienceConfig)
    tool_tiers: dict[str, list[str]] = Field(default_factory=dict)
    allowed_egress_domains: list[str] = Field(default_factory=list)
    allowed_sql_tables: list[str] = Field(default_factory=list)


_CACHED_POLICY: PolicyConfig | None = None


def load_policy(path: str | Path | None = None) -> PolicyConfig:
    """Load and validate policy configuration from YAML file."""
    global _CACHED_POLICY
    target_path = Path(path) if path else DEFAULT_POLICY_PATH
    if not target_path.exists():
        # Fall back to default config if file does not exist
        _CACHED_POLICY = PolicyConfig()
        return _CACHED_POLICY

    with open(target_path, "r", encoding="utf-8") as f:
        raw_data = yaml.safe_load(f) or {}

    config = PolicyConfig.model_validate(raw_data)
    _CACHED_POLICY = config
    return config


def get_policy() -> PolicyConfig:
    """Get currently active policy configuration or load default."""
    global _CACHED_POLICY
    if _CACHED_POLICY is None:
        return load_policy()
    return _CACHED_POLICY
