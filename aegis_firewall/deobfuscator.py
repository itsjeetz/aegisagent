"""
De-obfuscation & Anti-Evasion Engine.
Detects and canonicalizes Unicode homoglyphs, zero-width characters,
Base64, Hexadecimal, Leetspeak, ROT13, Binary encodings, and token fragmentation.
"""

import base64
import codecs
import re
import unicodedata
from typing import Tuple, List
from aegis_firewall.models import EvasionSignal

# Curated Unicode Homoglyph Map (Cyrillic, Greek, Fullwidth to Latin ASCII)
HOMOGLYPH_MAP = {
    # Cyrillic lower
    'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e', 'ё': 'e',
    'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k', 'л': 'l', 'м': 'm',
    'н': 'n', 'о': 'o', 'п': 'p', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y',
    'ф': 'f', 'х': 'x', 'ц': 'ts', 'ч': 'ch', 'ш': 'sh', 'щ': 'shch', 'ъ': '',
    'ы': 'y', 'ь': '', 'э': 'e', 'ю': 'yu', 'я': 'ya',
    # Cyrillic upper
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
    'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X',
    # Greek
    'α': 'a', 'β': 'b', 'γ': 'g', 'δ': 'd', 'ε': 'e', 'ζ': 'z', 'η': 'h',
    'θ': 'th', 'ι': 'i', 'κ': 'k', 'λ': 'l', 'μ': 'm', 'ν': 'n', 'ξ': 'x',
    'ο': 'o', 'π': 'p', 'ρ': 'r', 'σ': 's', 'τ': 't', 'υ': 'u', 'φ': 'ph',
    'χ': 'ch', 'ψ': 'ps', 'ω': 'o',
    # Fullwidth Latin
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f', 'ｇ': 'g',
    'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n',
    'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't', 'ｕ': 'u',
    'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z',
}

# Zero-width / invisible characters regex
INVISIBLE_CHARS_PATTERN = re.compile(r'[\u200B\u200C\u200D\uFEFF\u2060\u00AD\u200E\u200F\u202A-\u202E]')

# Unicode Tag Smuggling (E0000 series invisible tag characters)
TAG_CHAR_PATTERN = re.compile(r'[\U000E0000-\U000E007F]')

# Leetspeak Map
LEET_MAP = {
    '0': 'o',
    '1': 'i',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '@': 'a',
    '$': 's',
    '!': 'i',
    '|': 'l',
    '+': 't',
}

# Imperative prompt injection trigger words to look for in decoded payloads
TRIGGER_KEYWORDS = [
    'ignore', 'disregard', 'override', 'system', 'prompt', 'assistant',
    'jailbreak', 'dan', 'developer mode', 'exfiltrate', 'secret',
    'bypass', 'credential', 'password', 'token', 'execute', 'eval'
]


class DeobfuscationEngine:
    """Anti-evasion engine that strips obfuscations and decodes hidden directives."""

    @classmethod
    def strip_invisible_characters(cls, text: str) -> Tuple[str, List[EvasionSignal]]:
        signals = []
        # Check Tag Smuggling
        tag_matches = TAG_CHAR_PATTERN.findall(text)
        if tag_matches:
            # Decode ASCII tag characters (offset by 0xE0000)
            decoded_tags = "".join(chr(ord(c) - 0xE0000) for c in tag_matches if 0x20 <= (ord(c) - 0xE0000) <= 0x7E)
            signals.append(EvasionSignal(
                technique="Unicode Tag Smuggling",
                detected_obfuscation=f"{len(tag_matches)} invisible tag codepoints",
                decoded_text=decoded_tags,
                confidence=0.98
            ))

        # Check Zero-width characters
        invis_matches = INVISIBLE_CHARS_PATTERN.findall(text)
        if len(invis_matches) > 1:
            signals.append(EvasionSignal(
                technique="Zero-Width Unicode Characters",
                detected_obfuscation=f"{len(invis_matches)} zero-width characters stripped",
                decoded_text="[Stripped]",
                confidence=0.95
            ))

        cleaned = TAG_CHAR_PATTERN.sub('', text)
        cleaned = INVISIBLE_CHARS_PATTERN.sub('', cleaned)
        return cleaned, signals

    @classmethod
    def normalize_homoglyphs(cls, text: str) -> Tuple[str, List[EvasionSignal]]:
        signals = []
        replaced_chars = []
        result = []

        for ch in text:
            if ch in HOMOGLYPH_MAP:
                rep = HOMOGLYPH_MAP[ch]
                result.append(rep)
                replaced_chars.append(f"{ch} -> {rep}")
            else:
                # Also normalize unicode NFKD
                nfkd = unicodedata.normalize('NFKD', ch)
                result.append(nfkd)

        norm_text = "".join(result)
        if len(replaced_chars) >= 2:
            signals.append(EvasionSignal(
                technique="Homoglyph Substitution",
                detected_obfuscation=f"{len(replaced_chars)} characters: {', '.join(replaced_chars[:5])}...",
                decoded_text=norm_text[:120],
                confidence=0.90
            ))

        return norm_text, signals

    @classmethod
    def decode_base64_payloads(cls, text: str) -> Tuple[str, List[EvasionSignal]]:
        signals = []
        appended_text = text

        # Match base64 tokens of reasonable length (at least 16 chars, handles = padding)
        b64_pattern = re.compile(r'(?:\b|\A)[A-Za-z0-9+/]{16,}={0,2}(?=\s|[\.,;:\)\]]|\Z)')
        for match in b64_pattern.finditer(text):
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                if len(decoded) > 8 and any(k in decoded.lower() for k in TRIGGER_KEYWORDS):
                    signals.append(EvasionSignal(
                        technique="Base64 Encoded Instruction",
                        detected_obfuscation=candidate[:30] + "...",
                        decoded_text=decoded,
                        confidence=0.96
                    ))
                    appended_text += f"\n[DECODED_BASE64: {decoded}]"
            except Exception:
                pass

        return appended_text, signals

    @classmethod
    def decode_hex_payloads(cls, text: str) -> Tuple[str, List[EvasionSignal]]:
        signals = []
        appended_text = text

        # Match hex sequences: \x69\x67... or 69676e6f7265
        hex_pattern = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}|\b(?:[0-9a-fA-F]{2}){8,}\b')
        for match in hex_pattern.finditer(text):
            candidate = match.group(0).replace('\\x', '')
            try:
                decoded = bytes.fromhex(candidate).decode('utf-8', errors='ignore')
                if len(decoded) > 5 and any(k in decoded.lower() for k in TRIGGER_KEYWORDS):
                    signals.append(EvasionSignal(
                        technique="Hexadecimal Encoded Instruction",
                        detected_obfuscation=match.group(0)[:30] + "...",
                        decoded_text=decoded,
                        confidence=0.95
                    ))
                    appended_text += f"\n[DECODED_HEX: {decoded}]"
            except Exception:
                pass

        return appended_text, signals

    @classmethod
    def decode_rot13(cls, text: str) -> Tuple[str, List[EvasionSignal]]:
        signals = []
        # Attempt rot13 decoding
        try:
            rot = codecs.decode(text, 'rot_13')
            # Check if rot13 unlocked hidden trigger words that weren't in the original
            unlocked = [k for k in TRIGGER_KEYWORDS if k in rot.lower() and k not in text.lower()]
            if unlocked:
                signals.append(EvasionSignal(
                    technique="ROT13 Cipher",
                    detected_obfuscation=f"Decoded trigger words: {', '.join(unlocked)}",
                    decoded_text=rot[:120],
                    confidence=0.92
                ))
                return text + f"\n[DECODED_ROT13: {rot}]", signals
        except Exception:
            pass

        return text, signals

    @classmethod
    def decode_leetspeak(cls, text: str) -> Tuple[str, List[EvasionSignal]]:
        signals = []
        # Translate leet characters
        leet_chars = []
        result = []
        for ch in text:
            if ch in LEET_MAP:
                result.append(LEET_MAP[ch])
                leet_chars.append(ch)
            else:
                result.append(ch)

        translated = "".join(result)
        # Check if leetspeak exposed any trigger words
        unlocked = [k for k in TRIGGER_KEYWORDS if k in translated.lower() and k not in text.lower()]
        if unlocked and len(leet_chars) >= 2:
            signals.append(EvasionSignal(
                technique="Leetspeak Obfuscation",
                detected_obfuscation=f"Transformed keywords: {', '.join(unlocked)}",
                decoded_text=translated[:120],
                confidence=0.91
            ))
            return text + f"\n[CANONICAL_LEETSPEAK: {translated}]", signals

        return text, signals

    @classmethod
    def de_space_tokens(cls, text: str) -> Tuple[str, List[EvasionSignal]]:
        signals = []
        # Match spaced words: "i g n o r e" or "d a n"
        despaced = re.sub(r'(?<=\b[a-zA-Z])\s+(?=[a-zA-Z]\b)', '', text)
        unlocked = [k for k in TRIGGER_KEYWORDS if k in despaced.lower() and k not in text.lower()]
        if unlocked:
            signals.append(EvasionSignal(
                technique="Character De-spacing / Token Fragmentation",
                detected_obfuscation=f"Recombined tokens: {', '.join(unlocked)}",
                decoded_text=despaced[:120],
                confidence=0.89
            ))
            return text + f"\n[RECOMBINED_TOKENS: {despaced}]", signals

        return text, signals

    @classmethod
    def process(cls, text: str) -> Tuple[str, List[EvasionSignal]]:
        """Applies the full de-obfuscation pipeline and returns canonicalized text + detected signals."""
        signals: List[EvasionSignal] = []

        # 1. Zero-width and Tag Smuggling
        curr, sigs = cls.strip_invisible_characters(text)
        signals.extend(sigs)

        # 2. Homoglyph normalization
        curr, sigs = cls.normalize_homoglyphs(curr)
        signals.extend(sigs)

        # 3. Base64
        curr, sigs = cls.decode_base64_payloads(curr)
        signals.extend(sigs)

        # 4. Hexadecimal
        curr, sigs = cls.decode_hex_payloads(curr)
        signals.extend(sigs)

        # 5. ROT13
        curr, sigs = cls.decode_rot13(curr)
        signals.extend(sigs)

        # 6. Leetspeak
        curr, sigs = cls.decode_leetspeak(curr)
        signals.extend(sigs)

        # 7. De-spacing
        curr, sigs = cls.de_space_tokens(curr)
        signals.extend(sigs)

        return curr, signals
