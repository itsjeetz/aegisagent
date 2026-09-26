"""MappedText preserving character-level offset tracking to original document text (§5.2)."""

from dataclasses import dataclass
from typing import Callable


@dataclass
class MappedText:
    """Text with per-character offset mapping back to the ORIGINAL segment text."""

    text: str
    omap: list[tuple[int, int]]  # per char in .text: [start, end) span in ORIGINAL segment text

    def __post_init__(self):
        if len(self.text) != len(self.omap):
            raise ValueError(
                f"MappedText length mismatch: len(text)={len(self.text)} vs len(omap)={len(self.omap)}"
            )

    @classmethod
    def identity(cls, s: str) -> "MappedText":
        """Create identity mapping where each character maps to its 1-char offset."""
        return cls(s, [(i, i + 1) for i in range(len(s))])

    def replace(self, start: int, end: int, new: str) -> "MappedText":
        """Replace text[start:end] with `new`. New chars map to the full original span of the replaced region."""
        if start == end:  # Pure insertion: anchor to neighbor
            i = min(start, len(self.omap) - 1) if self.omap else 0
            lo, hi = self.omap[i] if self.omap else (0, 0)
        else:
            sub = self.omap[start:end]
            lo = min(s for s, _ in sub) if sub else 0
            hi = max(e for _, e in sub) if sub else 0

        new_text = self.text[:start] + new + self.text[end:]
        new_omap = self.omap[:start] + [(lo, hi)] * len(new) + self.omap[end:]
        return MappedText(new_text, new_omap)

    def replace_spans(self, replacements: list[tuple[int, int, str]]) -> "MappedText":
        """Perform multiple non-overlapping replacements in a single O(N) pass.
        Each replacement is a tuple of (start, end, replacement_str).
        """
        if not replacements:
            return self

        # Sort replacements by start index
        sorted_reps = sorted(replacements, key=lambda r: r[0])

        out_chars: list[str] = []
        out_omap: list[tuple[int, int]] = []
        curr_idx = 0

        for start, end, new_str in sorted_reps:
            if start < curr_idx:
                continue  # Skip overlapping replacements

            # Copy unchanged span before replacement
            if start > curr_idx:
                out_chars.append(self.text[curr_idx:start])
                out_omap.extend(self.omap[curr_idx:start])

            # Apply replacement
            if start == end:
                i = min(start, len(self.omap) - 1) if self.omap else 0
                lo, hi = self.omap[i] if self.omap else (0, 0)
            else:
                sub = self.omap[start:end]
                lo = min(s for s, _ in sub) if sub else 0
                hi = max(e for _, e in sub) if sub else 0

            out_chars.append(new_str)
            out_omap.extend([(lo, hi)] * len(new_str))
            curr_idx = end

        # Append remainder of text
        if curr_idx < len(self.text):
            out_chars.append(self.text[curr_idx:])
            out_omap.extend(self.omap[curr_idx:])

        return MappedText("".join(out_chars), out_omap)

    def map_chars(self, fn: Callable[[str], str]) -> "MappedText":
        """Transform text character-by-character. fn(ch) can return empty string or multiple characters."""
        out, om = [], []
        for ch, span in zip(self.text, self.omap):
            r = fn(ch)
            out.append(r)
            om.extend([span] * len(r))
        return MappedText("".join(out), om)

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        """Convert a slice [start:end] in transformed text to [orig_start, orig_end] in the ORIGINAL segment."""
        if start >= end or not self.omap:
            return (0, 0)
        clamped_start = max(0, min(start, len(self.omap)))
        clamped_end = max(0, min(end, len(self.omap)))
        seg = self.omap[clamped_start:clamped_end]
        if not seg:
            return (0, 0)
        return (min(s for s, _ in seg), max(e for _, e in seg))

    def slice(self, start: int, end: int) -> "MappedText":
        """Extract a sub-slice of MappedText while retaining original offset mappings."""
        return MappedText(self.text[start:end], self.omap[start:end])
