"""Decoders for Base64, Hex, URL, HTML entities, Rot13, Leet, Despace, Reverse, and Binary (§5.2)."""

import base64
import codecs
import html
import re
import urllib.parse
from aegis.normalize.mapped_text import MappedText
from aegis.normalize.unicode_clean import ZERO_WIDTH_CODEPOINTS

MAX_DECODED_BLOB_BYTES = 64 * 1024  # 64 KB limit
SHORT_SEGMENT_MAX_CHARS = 5120      # 5 KB limit for heavy decoders (rot13, reverse)

LEET_MAP = {
    "4": "a",
    "3": "e",
    "1": "i",
    "0": "o",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
}


def _is_printable_utf8(b: bytes) -> tuple[bool, str]:
    """Check if decoded bytes are >= 80% printable UTF-8 text (including zero-width and tags)."""
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return False, ""
    if not s:
        return False, ""
    printable_count = sum(
        1 for ch in s
        if ch.isprintable()
        or ch in "\n\r\t"
        or ord(ch) in ZERO_WIDTH_CODEPOINTS
        or 0xE0000 <= ord(ch) <= 0xE007F
    )
    is_valid = (printable_count / len(s)) >= 0.80
    return is_valid, s


def decode_html_entities(mt: MappedText) -> MappedText | None:
    """Decode HTML entities (&amp;, &lt;, &#x20;, etc.) mapping characters to entity spans."""
    entity_pat = re.compile(r"&(?:[a-zA-Z0-9]+|#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6});")
    matches = list(entity_pat.finditer(mt.text))
    if not matches:
        return None

    replacements = []
    for m in matches:
        entity_token = m.group(0)
        decoded = html.unescape(entity_token)
        if decoded != entity_token:
            replacements.append((m.start(), m.end(), decoded))

    if not replacements:
        return None
    return mt.replace_spans(replacements)


def decode_url(mt: MappedText) -> MappedText | None:
    """Decode percent-encoded sequences (%20, %2F, etc.) mapping characters to percent token spans."""
    url_pat = re.compile(r"(?:%[0-9a-fA-F]{2})+")
    matches = list(url_pat.finditer(mt.text))
    if not matches:
        return None

    replacements = []
    for m in matches:
        token = m.group(0)
        decoded = urllib.parse.unquote(token)
        if decoded != token:
            replacements.append((m.start(), m.end(), decoded))

    if not replacements:
        return None
    return mt.replace_spans(replacements)


def decode_base64(mt: MappedText, max_blob_bytes: int = MAX_DECODED_BLOB_BYTES) -> MappedText | None:
    """Find and decode Base64 tokens (>= 16 chars) if decoded bytes are >= 80% printable UTF-8."""
    # Look for tokens with valid base64 alphabet (standard or URL-safe), including padding
    b64_pat = re.compile(r"\b[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_-])")
    matches = list(b64_pat.finditer(mt.text))
    if not matches:
        return None

    replacements = []
    for m in matches:
        token = m.group(0)
        # Pad if missing
        pad_len = (4 - len(token) % 4) % 4
        padded = token + "=" * pad_len
        try:
            # Try standard base64 then urlsafe
            try:
                decoded_bytes = base64.b64decode(padded, validate=True)
            except Exception:
                decoded_bytes = base64.urlsafe_b64decode(padded)

            if len(decoded_bytes) > max_blob_bytes:
                continue

            valid, text = _is_printable_utf8(decoded_bytes)
            if valid and text.strip():
                replacements.append((m.start(), m.end(), text))
        except Exception:
            continue

    if not replacements:
        return None
    return mt.replace_spans(replacements)


def decode_hex(mt: MappedText, max_blob_bytes: int = MAX_DECODED_BLOB_BYTES) -> MappedText | None:
    """Find and decode Hex tokens (>= 16 chars) if decoded bytes are >= 80% printable UTF-8."""
    hex_pat = re.compile(r"\b(?:0x)?([0-9a-fA-F]{16,})(?![0-9a-fA-F])")
    matches = list(hex_pat.finditer(mt.text))
    if not matches:
        return None

    replacements = []
    for m in matches:
        hex_str = m.group(1)
        if len(hex_str) % 2 != 0:
            hex_str = hex_str[:-1]  # Even length only
        try:
            decoded_bytes = bytes.fromhex(hex_str)
            if len(decoded_bytes) > max_blob_bytes:
                continue
            valid, text = _is_printable_utf8(decoded_bytes)
            if valid and text.strip():
                replacements.append((m.start(), m.end(), text))
        except Exception:
            continue

    if not replacements:
        return None
    return mt.replace_spans(replacements)


def decode_rot13(mt: MappedText) -> MappedText | None:
    """Apply ROT13 substitution on short segments (< 5 KB)."""
    if len(mt.text) > SHORT_SEGMENT_MAX_CHARS or not mt.text:
        return None
    # Only return variant if there are alphabetic characters changed
    has_letters = any(ch.isalpha() for ch in mt.text)
    if not has_letters:
        return None
    return mt.map_chars(lambda ch: codecs.encode(ch, "rot_13"))


def decode_reverse(mt: MappedText) -> MappedText | None:
    """Reverse text and offset mapping on short segments (< 5 KB)."""
    if len(mt.text) > SHORT_SEGMENT_MAX_CHARS or len(mt.text) < 4:
        return None
    return MappedText(mt.text[::-1], mt.omap[::-1])


def decode_leet(mt: MappedText) -> MappedText | None:
    """Translate 1337-speak characters (4->a, 3->e, 1->i, 0->o, 5->s, 7->t, @->a, $->s)."""
    has_leet = any(ch in LEET_MAP for ch in mt.text)
    if not has_leet:
        return None
    return mt.map_chars(lambda ch: LEET_MAP.get(ch, ch))


def decode_despace(mt: MappedText) -> MappedText | None:
    """Collapse runs of >= 6 single letters separated by spaces, dots, or dashes (e.g. 'd i s r e g a r d')."""
    # Pattern matching single letters separated by a single space, dot, or dash
    despace_pat = re.compile(r"\b([a-zA-Z](?:[ \.\-][a-zA-Z]){5,})\b")
    matches = list(despace_pat.finditer(mt.text))
    if not matches:
        return None

    replacements = []
    for m in matches:
        raw_run = m.group(1)
        # Collapse separators
        collapsed = re.sub(r"[ \.\-]", "", raw_run)
        replacements.append((m.start(), m.end(), collapsed))

    return mt.replace_spans(replacements)


def decode_binary(mt: MappedText, max_blob_bytes: int = MAX_DECODED_BLOB_BYTES) -> MappedText | None:
    """Find and decode runs of 8-bit binary groups into text."""
    # Matches sequences of 8-bit groups (e.g. 01001000 01100101 ...)
    bin_pat = re.compile(r"\b(?:[01]{8}[ \t\r\n,]*){3,}\b")
    matches = list(bin_pat.finditer(mt.text))
    if not matches:
        return None

    replacements = []
    for m in matches:
        token = m.group(0)
        bits = re.findall(r"[01]{8}", token)
        try:
            byte_vals = bytes(int(b, 2) for b in bits)
            if len(byte_vals) > max_blob_bytes:
                continue
            valid, text = _is_printable_utf8(byte_vals)
            if valid and text.strip():
                replacements.append((m.start(), m.end(), text))
        except Exception:
            continue

    if not replacements:
        return None
    return mt.replace_spans(replacements)


def decode_ocr_fix(mt: MappedText) -> MappedText | None:
    """Apply OCR confusion corrections (rn->m, vv->w, cl->d, 0->o, 1->l) in letter contexts."""
    # Find word tokens that might have OCR confusions
    s = mt.text
    replacements = []

    # 'rn' -> 'm' inside letters
    for m in re.finditer(r"(?<=[a-zA-Z])rn(?=[a-zA-Z])", s):
        replacements.append((m.start(), m.end(), "m"))

    # 'vv' -> 'w' inside letters
    for m in re.finditer(r"(?<=[a-zA-Z])vv(?=[a-zA-Z])", s):
        replacements.append((m.start(), m.end(), "w"))

    # 'cl' -> 'd' inside letters
    for m in re.finditer(r"(?<=[a-zA-Z])cl(?=[a-zA-Z])", s):
        replacements.append((m.start(), m.end(), "d"))

    # '0' -> 'o' inside letters
    for m in re.finditer(r"(?<=[a-zA-Z])0(?=[a-zA-Z])", s):
        replacements.append((m.start(), m.end(), "o"))

    # '1' -> 'l' inside letters
    for m in re.finditer(r"(?<=[a-zA-Z])1(?=[a-zA-Z])", s):
        replacements.append((m.start(), m.end(), "l"))

    if not replacements:
        return None
    return mt.replace_spans(replacements)
