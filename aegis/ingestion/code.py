"""Ingestion adapter for Source Code files (§5.1)."""

import ast
import io
import re
import tokenize
from typing import TYPE_CHECKING

from aegis.ingestion.base import BaseAdapter, OversizeContentError
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class SourceCodeAdapter(BaseAdapter):
    """Adapter for SOURCE_CODE source, extracting comments, docstrings, strings, and code."""

    source = InputSource.SOURCE_CODE

    def _extract_python(self, code_text: str, segments: list[Segment], seg_idx: list[int]):
        """Extract Python comments, docstrings, and string literals using tokenize and ast."""
        # 1. Comments via tokenize
        try:
            tokens = tokenize.tokenize(io.BytesIO(code_text.encode("utf-8")).readline)
            for tok in tokens:
                if tok.type == tokenize.COMMENT:
                    comment_text = tok.string.lstrip("#").strip()
                    if comment_text:
                        segments.append(
                            Segment(
                                id=f"seg-code-{seg_idx[0]}",
                                text=comment_text,
                                origin="code_comment",
                                location=f"line {tok.start[0]}",
                                hidden_reason=None,
                            )
                        )
                        seg_idx[0] += 1
        except Exception:
            # Fallback regex for comments
            for match in re.finditer(r"#\s*(.*)$", code_text, re.MULTILINE):
                val = match.group(1).strip()
                if val:
                    line_no = code_text[: match.start()].count("\n") + 1
                    segments.append(
                        Segment(
                            id=f"seg-code-{seg_idx[0]}",
                            text=val,
                            origin="code_comment",
                            location=f"line {line_no}",
                            hidden_reason=None,
                        )
                    )
                    seg_idx[0] += 1

        # 2. Docstrings and string literals via ast
        try:
            tree = ast.parse(code_text)
            for node in ast.walk(tree):
                # Check for docstrings
                if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    doc = ast.get_docstring(node, clean=True)
                    if doc:
                        segments.append(
                            Segment(
                                id=f"seg-code-{seg_idx[0]}",
                                text=doc,
                                origin="string_literal",
                                location=f"line {getattr(node, 'lineno', 1)} docstring",
                                hidden_reason=None,
                            )
                        )
                        seg_idx[0] += 1

                # String constants
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    s_val = node.value.strip()
                    if s_val and len(s_val) > 3:
                        segments.append(
                            Segment(
                                id=f"seg-code-{seg_idx[0]}",
                                text=s_val,
                                origin="string_literal",
                                location=f"line {getattr(node, 'lineno', 1)} str_literal",
                                hidden_reason=None,
                            )
                        )
                        seg_idx[0] += 1
        except Exception:
            pass

    def _extract_generic_code(self, code_text: str, segments: list[Segment], seg_idx: list[int]):
        """Extract comments and string literals from non-Python source code via regex."""
        # Multi-line comments /* ... */
        for match in re.finditer(r"/\*[\s\S]*?\*/", code_text):
            c_text = match.group(0).strip("/*").strip()
            if c_text:
                line_no = code_text[: match.start()].count("\n") + 1
                segments.append(
                    Segment(
                        id=f"seg-code-{seg_idx[0]}",
                        text=c_text,
                        origin="code_comment",
                        location=f"line {line_no} block_comment",
                        hidden_reason=None,
                    )
                )
                seg_idx[0] += 1

        # Single-line comments // ... or -- ...
        for match in re.finditer(r"(?://|--)\s*(.*)$", code_text, re.MULTILINE):
            c_text = match.group(1).strip()
            if c_text:
                line_no = code_text[: match.start()].count("\n") + 1
                segments.append(
                    Segment(
                        id=f"seg-code-{seg_idx[0]}",
                        text=c_text,
                        origin="code_comment",
                        location=f"line {line_no} line_comment",
                        hidden_reason=None,
                    )
                )
                seg_idx[0] += 1

        # String literals "..." or '...'
        for match in re.finditer(r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"[^"\n]*"|\'[^\'\n]*\')', code_text):
            raw_str = match.group(0)
            cleaned = raw_str.strip('"\'').strip()
            if cleaned and len(cleaned) > 5:
                line_no = code_text[: match.start()].count("\n") + 1
                segments.append(
                    Segment(
                        id=f"seg-code-{seg_idx[0]}",
                        text=cleaned,
                        origin="string_literal",
                        location=f"line {line_no} literal",
                        hidden_reason=None,
                    )
                )
                seg_idx[0] += 1

    def extract(
        self,
        data: bytes | str,
        *,
        filename: str | None = None,
        policy: "PolicyConfig | None" = None,
    ) -> list[Segment]:
        pol = policy or get_policy()

        if isinstance(data, bytes):
            if len(data) > pol.limits.max_upload_bytes:
                raise OversizeContentError(
                    f"Source code size exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            code_text = data.decode("utf-8", errors="replace")
        else:
            if len(data.encode("utf-8")) > pol.limits.max_upload_bytes:
                raise OversizeContentError(
                    f"Source code size exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            code_text = data

        segments: list[Segment] = []
        seg_idx = [0]

        is_python = filename.endswith(".py") if filename else True
        if is_python:
            self._extract_python(code_text, segments, seg_idx)
        else:
            self._extract_generic_code(code_text, segments, seg_idx)

        # Include overall full code text as visible segment
        segments.append(
            Segment(
                id=f"seg-code-{seg_idx[0]}",
                text=code_text,
                origin="visible",
                location="source_file",
                hidden_reason=None,
            )
        )

        return segments
