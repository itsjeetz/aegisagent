"""Base classes and context for detection layer (§5.3)."""

from dataclasses import dataclass, field
from typing import Any
from aegis.models import Finding, InputSource, Segment, Trust
from aegis.normalize.deobfuscate import Variant


@dataclass
class DetectionContext:
    """Contextual metadata passed to all detectors in the cascade."""

    request_id: str
    source: InputSource
    trust: Trust
    session_id: str | None = None
    is_hidden: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
