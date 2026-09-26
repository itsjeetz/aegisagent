"""Ingestion adapter for Markdown documents (§5.1)."""

import re
from typing import TYPE_CHECKING
from markdown_it import MarkdownIt

from aegis.ingestion.base import BaseAdapter, OversizeContentError
from aegis.ingestion.html import HtmlAdapter
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class MarkdownAdapter(BaseAdapter):
    """Adapter for MARKDOWN source using markdown-it-py."""

    source = InputSource.MARKDOWN

    def __init__(self):
        self.md = MarkdownIt("commonmark", {"html": True})
        self.html_adapter = HtmlAdapter()

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
                    f"Markdown size {len(data)} exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            text = data.decode("utf-8", errors="replace")
        else:
            if len(data.encode("utf-8")) > pol.limits.max_upload_bytes:
                raise OversizeContentError(
                    f"Markdown size exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            text = data

        segments: list[Segment] = []
        seg_idx = 0

        # Check for front-matter (--- ... ---) at start of file
        front_matter_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
        if front_matter_match:
            fm_text = front_matter_match.group(1).strip()
            if fm_text:
                segments.append(
                    Segment(
                        id=f"seg-md-{seg_idx}",
                        text=fm_text,
                        origin="metadata",
                        location="front_matter",
                        hidden_reason=None,
                    )
                )
                seg_idx += 1
            body_text = text[front_matter_match.end() :]
        else:
            body_text = text

        tokens = self.md.parse(body_text)

        for token in tokens:
            # 1. HTML Blocks and Inline HTML (comments and raw HTML)
            if token.type in ("html_block", "html_inline"):
                content = token.content.strip()
                if not content:
                    continue
                # Check for HTML comment
                comment_match = re.match(r"^<!--\s*(.*?)\s*-->$", content, re.DOTALL)
                if comment_match:
                    comment_text = comment_match.group(1).strip()
                    segments.append(
                        Segment(
                            id=f"seg-md-{seg_idx}",
                            text=comment_text,
                            origin="comment",
                            location=f"line {token.map[0] + 1 if token.map else 'inline'}",
                            hidden_reason="html_comment",
                        )
                    )
                    seg_idx += 1
                else:
                    # Route raw HTML to HTML adapter
                    html_segs = self.html_adapter.extract(content, policy=pol)
                    for hseg in html_segs:
                        if hseg.text:
                            segments.append(
                                Segment(
                                    id=f"seg-md-{seg_idx}",
                                    text=hseg.text,
                                    origin=hseg.origin,
                                    location=f"inline_html:{hseg.location}",
                                    hidden_reason=hseg.hidden_reason,
                                )
                            )
                            seg_idx += 1

            # 2. Inline elements (text, link title, image alt)
            elif token.type == "inline" and token.children:
                line_no = token.map[0] + 1 if token.map else "inline"
                in_link = False
                current_link_title = None

                for child in token.children:
                    if child.type == "link_open":
                        in_link = True
                        current_link_title = child.attrs.get("title") if child.attrs else None
                        if current_link_title and current_link_title.strip():
                            segments.append(
                                Segment(
                                    id=f"seg-md-{seg_idx}",
                                    text=current_link_title.strip(),
                                    origin="alt_text",
                                    location=f"line {line_no} [link_title]",
                                    hidden_reason="link_title",
                                )
                            )
                            seg_idx += 1
                    elif child.type == "link_close":
                        in_link = False
                        current_link_title = None
                    elif child.type == "image":
                        # Image alt text and title
                        alt_text = child.content.strip()
                        if alt_text:
                            segments.append(
                                Segment(
                                    id=f"seg-md-{seg_idx}",
                                    text=alt_text,
                                    origin="alt_text",
                                    location=f"line {line_no} [image_alt]",
                                    hidden_reason=None,
                                )
                            )
                            seg_idx += 1
                        img_title = child.attrs.get("title") if child.attrs else None
                        if img_title and img_title.strip():
                            segments.append(
                                Segment(
                                    id=f"seg-md-{seg_idx}",
                                    text=img_title.strip(),
                                    origin="alt_text",
                                    location=f"line {line_no} [image_title]",
                                    hidden_reason="image_title",
                                )
                            )
                            seg_idx += 1
                    elif child.type in ("text", "code_inline"):
                        val = child.content.strip()
                        if val:
                            segments.append(
                                Segment(
                                    id=f"seg-md-{seg_idx}",
                                    text=val,
                                    origin="visible",
                                    location=f"line {line_no}",
                                    hidden_reason=None,
                                )
                            )
                            seg_idx += 1
                    elif child.type in ("html_inline",):
                        content = child.content.strip()
                        comment_match = re.match(r"^<!--\s*(.*?)\s*-->$", content, re.DOTALL)
                        if comment_match:
                            segments.append(
                                Segment(
                                    id=f"seg-md-{seg_idx}",
                                    text=comment_match.group(1).strip(),
                                    origin="comment",
                                    location=f"line {line_no}",
                                    hidden_reason="html_comment",
                                )
                            )
                            seg_idx += 1

            # 3. Code fence / block
            elif token.type in ("fence", "code_block"):
                val = token.content.strip()
                if val:
                    line_no = token.map[0] + 1 if token.map else "code"
                    segments.append(
                        Segment(
                            id=f"seg-md-{seg_idx}",
                            text=val,
                            origin="visible",
                            location=f"code block (line {line_no})",
                            hidden_reason=None,
                        )
                    )
                    seg_idx += 1

        if not segments:
            segments.append(
                Segment(
                    id=f"seg-md-{seg_idx}",
                    text="",
                    origin="visible",
                    location="document",
                    hidden_reason=None,
                )
            )

        return segments
