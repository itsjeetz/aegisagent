"""Variant generation pipeline orchestrating normalization and deobfuscation (§5.2)."""

from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aegis.models import InputSource, Segment
from aegis.normalize.decoders import (
    decode_base64,
    decode_binary,
    decode_despace,
    decode_hex,
    decode_html_entities,
    decode_leet,
    decode_ocr_fix,
    decode_reverse,
    decode_rot13,
    decode_url,
)
from aegis.normalize.mapped_text import MappedText
from aegis.normalize.unicode_clean import (
    clean_nfkc,
    decode_unicode_tags,
    fold_homoglyphs,
    strip_zero_width,
)
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


@dataclass
class Variant:
    """A transformed variant of segment text with its derivation chain (§5.2)."""

    mapped_text: MappedText
    chain: list[str]

    def __iter__(self):
        yield self.mapped_text
        yield self.chain


def _apply_step(mt: MappedText, step: str, is_ocr: bool) -> MappedText | None:
    """Apply a single normalization or decoding step. Returns new MappedText or None if no change."""
    if step == "nfkc":
        res = clean_nfkc(mt)
        return res if res.text != mt.text else None

    elif step == "zw_strip":
        res = strip_zero_width(mt)
        return res if res.text != mt.text else None

    elif step == "unicode_tags":
        return decode_unicode_tags(mt)

    elif step == "homoglyph":
        res = fold_homoglyphs(mt)
        return res if res.text != mt.text else None

    elif step == "html_entities":
        return decode_html_entities(mt)

    elif step == "url_decode":
        return decode_url(mt)

    elif step == "base64":
        return decode_base64(mt)

    elif step == "hex":
        return decode_hex(mt)

    elif step == "rot13":
        return decode_rot13(mt)

    elif step == "reverse":
        return decode_reverse(mt)

    elif step == "leet":
        return decode_leet(mt)

    elif step == "despace":
        return decode_despace(mt)

    elif step == "binary":
        return decode_binary(mt)

    elif step == "ocr_fix":
        if is_ocr:
            return decode_ocr_fix(mt)
        return None

    return None


# Priority ordering of transformation steps
TRANSFORMATION_STEPS = [
    "zw_strip",
    "unicode_tags",
    "nfkc",
    "homoglyph",
    "html_entities",
    "url_decode",
    "base64",
    "hex",
    "binary",
    "despace",
    "leet",
    "rot13",
    "reverse",
    "ocr_fix",
]


def deobfuscate(seg: Segment, policy: "PolicyConfig | None" = None) -> list[Variant]:
    """Generate normalized and deobfuscated variants of a segment text up to policy caps (§5.2).
    Always includes the original text. Caps: recursion depth <= 3, <= 12 variants per segment.
    """
    pol = policy or get_policy()
    max_variants = pol.limits.max_variants_per_segment
    max_depth = pol.limits.max_decode_depth

    # 1. Start with the original text as identity variant
    original_mt = MappedText.identity(seg.text)
    original_variant = Variant(mapped_text=original_mt, chain=[])

    variants: list[Variant] = [original_variant]
    seen_texts: set[str] = {seg.text}

    is_ocr = seg.origin in ("ocr",) or "ocr" in seg.location.lower()

    # Queue holds (MappedText, chain, depth)
    queue: deque[tuple[MappedText, list[str], int]] = deque([(original_mt, [], 0)])

    while queue and len(variants) < max_variants:
        current_mt, current_chain, depth = queue.popleft()
        if depth >= max_depth:
            continue

        for step in TRANSFORMATION_STEPS:
            if len(variants) >= max_variants:
                break

            # Avoid repeating the exact same step immediately
            if current_chain and current_chain[-1] == step:
                continue

            try:
                transformed = _apply_step(current_mt, step, is_ocr)
            except Exception:
                continue

            if transformed is None or not transformed.text:
                continue

            # If transformed text is new, record variant
            if transformed.text not in seen_texts:
                seen_texts.add(transformed.text)
                new_chain = current_chain + [step]
                v = Variant(mapped_text=transformed, chain=new_chain)
                variants.append(v)
                queue.append((transformed, new_chain, depth + 1))

    return variants
