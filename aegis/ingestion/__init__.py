"""Ingestion adapters package for AegisAgent (§5.1)."""

from aegis.ingestion.base import (
    BaseAdapter,
    IngestionError,
    OversizeContentError,
    UnsupportedFormatError,
    ZipBombError,
)
from aegis.ingestion.registry import IngestionRegistry, extract

__all__ = [
    "BaseAdapter",
    "IngestionError",
    "OversizeContentError",
    "ZipBombError",
    "UnsupportedFormatError",
    "IngestionRegistry",
    "extract",
]
