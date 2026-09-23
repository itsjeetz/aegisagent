"""Base classes and exceptions for ingestion adapters (§5.1)."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from aegis.models import InputSource, Segment

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class IngestionError(Exception):
    """Base exception for ingestion errors."""
    pass


class OversizeContentError(IngestionError):
    """Raised when content exceeds size or complexity limits."""
    pass


class ZipBombError(IngestionError):
    """Raised when an archive exceeds uncompressed expansion limits."""
    pass


class UnsupportedFormatError(IngestionError):
    """Raised when format cannot be parsed or is unrecognized."""
    pass


class BaseAdapter(ABC):
    """Abstract base class for all source ingestion adapters."""

    source: InputSource

    @abstractmethod
    def extract(
        self,
        data: bytes | str,
        *,
        filename: str | None = None,
        policy: "PolicyConfig | None" = None,
    ) -> list[Segment]:
        """Extract Segments from the raw document."""
        pass
