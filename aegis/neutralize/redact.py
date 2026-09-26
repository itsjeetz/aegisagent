"""Span-level redaction on original segment text (§5.5)."""

from aegis.models import AttackType, Finding, Segment


def merge_spans(spans: list[tuple[int, int, AttackType]]) -> list[tuple[int, int, AttackType]]:
    """Merge overlapping or adjacent intervals, preserving or prioritizing attack types."""
    if not spans:
        return []

    # Sort by start index, then end index
    sorted_spans = sorted(spans, key=lambda s: (s[0], s[1]))
    merged: list[tuple[int, int, AttackType]] = [sorted_spans[0]]

    for curr_start, curr_end, curr_type in sorted_spans[1:]:
        prev_start, prev_end, prev_type = merged[-1]
        if curr_start <= prev_end:  # Overlapping or adjacent
            # Merge intervals
            new_end = max(prev_end, curr_end)
            # Prioritize specific attack types over meta-labels
            if prev_type in (AttackType.INDIRECT_PROMPT_INJECTION, AttackType.ENCODED_INSTRUCTIONS):
                chosen_type = curr_type
            else:
                chosen_type = prev_type
            merged[-1] = (prev_start, new_end, chosen_type)
        else:
            merged.append((curr_start, curr_end, curr_type))

    return merged


def redact_segment(segment: Segment, findings: list[Finding]) -> str:
    """Redact flagged spans on the ORIGINAL segment text (§5.5).
    If findings have localized spans, redacts those exact spans.
    If NO finding has a localized span, redacts the whole segment.
    """
    if not findings:
        return segment.text

    seg_len = len(segment.text)
    localized_findings = [
        f for f in findings
        if f.span_original is not None and (f.span_original[1] - f.span_original[0]) < seg_len
    ]

    # If no localized findings exist at all, fall back to whole-segment redaction
    if not localized_findings:
        chosen_type = findings[0].attack_type
        return f"[REDACTED:{chosen_type.value}]"

    spans_to_redact = []
    for f in localized_findings:
        start, end = f.span_original
        # Clamp bounds
        start = max(0, min(start, seg_len))
        end = max(0, min(end, seg_len))
        if start < end:
            spans_to_redact.append((start, end, f.attack_type))

    if not spans_to_redact:
        return segment.text

    merged_spans = merge_spans(spans_to_redact)

    # Perform replacement from right to left to avoid index shifts
    result_text = segment.text
    for start, end, attack_type in reversed(merged_spans):
        replacement = f"[REDACTED:{attack_type.value}]"
        result_text = result_text[:start] + replacement + result_text[end:]

    return result_text


def redact_all_segments(segments: list[Segment], findings: list[Finding]) -> str:
    """Redact all segments with their respective findings and concatenate into sanitized text."""
    # Group findings by segment_id
    findings_by_seg: dict[str, list[Finding]] = {}
    for f in findings:
        findings_by_seg.setdefault(f.segment_id, []).append(f)

    sanitized_parts: list[str] = []
    for seg in segments:
        seg_findings = findings_by_seg.get(seg.id, [])
        sanitized = redact_segment(seg, seg_findings)
        if sanitized.strip():
            sanitized_parts.append(sanitized)

    return "\n\n".join(sanitized_parts)
