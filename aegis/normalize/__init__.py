"""Normalization and deobfuscation package (§5.2)."""

from aegis.normalize.mapped_text import MappedText
from aegis.normalize.deobfuscate import Variant, deobfuscate

__all__ = ["MappedText", "Variant", "deobfuscate"]
