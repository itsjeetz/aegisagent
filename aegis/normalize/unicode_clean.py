"""Unicode normalization, zero-width stripping, tag decoding, and homoglyph folding (§5.2)."""

import unicodedata
from aegis.normalize.mapped_text import MappedText

# Zero-width, directional formatting, word-joiner, and invisible characters
ZERO_WIDTH_CODEPOINTS = {
    0x00AD,  # Soft hyphen
    0x200B,  # Zero-width space
    0x200C,  # Zero-width non-joiner
    0x200D,  # Zero-width joiner
    0x200E,  # Left-to-right mark
    0x200F,  # Right-to-left mark
    0x202A,  # LRE
    0x202B,  # RLE
    0x202C,  # PDF
    0x202D,  # LRO
    0x202E,  # RLO
    0x2060,  # Word joiner
    0x2061,  # Function application
    0x2062,  # Invisible times
    0x2063,  # Invisible separator
    0x2064,  # Invisible plus
    0xFEFF,  # Zero-width no-break space / BOM
}

# Maintained homoglyph table: Cyrillic, Greek, and other visual lookalikes -> ASCII Latin
HOMOGLYPH_TABLE: dict[str, str] = {
    # Cyrillic lookalikes
    "а": "a", "А": "A",
    "в": "b", "В": "B",
    "е": "e", "Е": "E",
    "к": "k", "К": "K",
    "м": "m", "М": "M",
    "н": "h", "Н": "H",
    "о": "o", "О": "O",
    "р": "p", "Р": "P",
    "с": "c", "С": "C",
    "т": "t", "Т": "T",
    "у": "y", "У": "Y",
    "х": "x", "Х": "X",
    "і": "i", "І": "I",
    "ј": "j", "Ј": "J",
    "ѕ": "s", "Ѕ": "S",
    "ԁ": "d", "Ԃ": "D", "ԃ": "d",
    "Ԛ": "Q", "ԛ": "q",
    "ш": "w", "Ш": "W",

    # Greek lookalikes
    "α": "a", "Α": "A",
    "β": "b", "Β": "B",
    "γ": "y", "Γ": "r",
    "ε": "e", "Ε": "E",
    "η": "n", "Η": "H",
    "ι": "i", "Ι": "I",
    "κ": "k", "Κ": "K",
    "ν": "v", "Ν": "N",
    "ο": "o", "Ο": "O",
    "ρ": "p", "Ρ": "P",
    "τ": "t", "Τ": "T",
    "υ": "u", "Υ": "Y",
    "χ": "x", "Χ": "X",
}


def clean_nfkc(mt: MappedText) -> MappedText:
    """Normalize text using Unicode NFKC normalization, mapping resulting characters to the source span."""
    return mt.map_chars(lambda ch: unicodedata.normalize("NFKC", ch))


def strip_zero_width(mt: MappedText) -> MappedText:
    """Remove zero-width spaces, joiners, directional overrides, and BOM characters."""
    return mt.map_chars(lambda ch: "" if ord(ch) in ZERO_WIDTH_CODEPOINTS else ch)


def has_unicode_tags(text: str) -> bool:
    """Check if text contains Unicode Tag characters (U+E0000 to U+E007F)."""
    return any(0xE0000 <= ord(ch) <= 0xE007F for ch in text)


def decode_unicode_tags(mt: MappedText) -> MappedText | None:
    """Decode Unicode Tag characters (U+E0000-E007F) by subtracting 0xE0000 to recover hidden ASCII."""
    if not has_unicode_tags(mt.text):
        return None

    def _convert(ch: str) -> str:
        code = ord(ch)
        if 0xE0000 <= code <= 0xE007F:
            ascii_code = code - 0xE0000
            # Printable ASCII or whitespace
            if 0x20 <= ascii_code <= 0x7E or ascii_code in (0x09, 0x0A, 0x0D):
                return chr(ascii_code)
            return ""
        return ch

    return mt.map_chars(_convert)


def fold_homoglyphs(mt: MappedText) -> MappedText:
    """Fold Cyrillic, Greek, and other visually confusable lookalike characters to standard Latin ASCII."""
    return mt.map_chars(lambda ch: HOMOGLYPH_TABLE.get(ch, ch))
