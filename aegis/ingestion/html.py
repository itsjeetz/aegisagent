"""Ingestion adapter for HTML and Web Pages (§5.1)."""

import re
from typing import TYPE_CHECKING
from bs4 import BeautifulSoup, Comment, NavigableString, Tag

from aegis.ingestion.base import BaseAdapter, OversizeContentError
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class HtmlAdapter(BaseAdapter):
    """Adapter for HTML and WEB_PAGE sources."""

    source = InputSource.HTML

    def __init__(self, is_web_page: bool = False):
        if is_web_page:
            self.source = InputSource.WEB_PAGE

    def _parse_css_rules(self, soup: BeautifulSoup) -> dict[str, str]:
        """Best-effort extraction of class-level hidden styling rules from <style> tags."""
        hidden_classes: dict[str, str] = {}
        for style_tag in soup.find_all("style"):
            css_text = style_tag.get_text()
            # Match selectors and rule bodies
            rules = re.findall(r"([.#][\w\-]+)\s*\{([^}]+)\}", css_text)
            for selector, body in rules:
                selector = selector.strip()
                body_clean = body.lower().replace(" ", "")
                reason = self._check_css_string_for_hidden(body_clean)
                if reason:
                    hidden_classes[selector] = reason
        return hidden_classes

    def _check_css_string_for_hidden(self, style_str: str) -> str | None:
        """Check CSS declaration string for common hiding techniques."""
        s = style_str.lower().replace(" ", "")
        if "display:none" in s:
            return "display_none"
        if "visibility:hidden" in s or "visibility:collapse" in s:
            return "visibility_hidden"
        if "opacity:0;" in s or s.endswith("opacity:0") or "opacity:0.0" in s:
            return "opacity_zero"
        if re.search(r"font-size:\s*(0|1|2)px", s) or "font-size:0" in s:
            return "tiny_font"
        if re.search(r"(left|top|margin-left|text-indent):-(999|9999|\d{4,})px", s):
            return "offscreen"
        if (
            "color:#fff" in s
            or "color:white" in s
            or "color:rgb(255,255,255)" in s
            or "color:#ffffff" in s
            or "color:transparent" in s
            or "color:rgba(0,0,0,0)" in s
        ):
            return "white_text"
        return None

    def _get_element_hidden_reason(
        self, tag: Tag, class_hidden_map: dict[str, str]
    ) -> str | None:
        """Determine if an element or its parents are hidden."""
        curr = tag
        while curr and curr.name and curr.name != "[document]":
            if curr.has_attr("hidden"):
                return "hidden_attr"
            if curr.get("aria-hidden") == "true":
                return "aria_hidden"
            if curr.name in ("noscript", "template"):
                return curr.name

            # Check classes against parsed style rules
            classes = curr.get("class", [])
            if isinstance(classes, list):
                for c in classes:
                    if f".{c}" in class_hidden_map:
                        return class_hidden_map[f".{c}"]
            id_attr = curr.get("id")
            if id_attr and f"#{id_attr}" in class_hidden_map:
                return class_hidden_map[f"#{id_attr}"]

            # Check inline style
            style = curr.get("style", "")
            if style:
                reason = self._check_css_string_for_hidden(style)
                if reason:
                    return reason

            curr = curr.parent

        return None

    def _get_selector(self, tag: Tag) -> str:
        """Generate a short CSS selector location for an element."""
        parts = []
        curr = tag
        while curr and curr.name and curr.name != "[document]" and len(parts) < 3:
            name = curr.name
            if curr.get("id"):
                parts.append(f"{name}#{curr['id']}")
                break
            elif curr.get("class"):
                cls = ".".join(curr["class"][:2])
                parts.append(f"{name}.{cls}")
            else:
                parts.append(name)
            curr = curr.parent
        return " > ".join(reversed(parts)) if parts else "document"

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
                    f"HTML size {len(data)} exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            raw_html = data.decode("utf-8", errors="replace")
        else:
            if len(data.encode("utf-8")) > pol.limits.max_upload_bytes:
                raise OversizeContentError(
                    f"HTML size exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            raw_html = data

        soup = BeautifulSoup(raw_html, "lxml")
        class_hidden_map = self._parse_css_rules(soup)

        segments: list[Segment] = []
        seg_idx = 0

        # 1. Meta tags (metadata)
        for meta in soup.find_all("meta"):
            content = meta.get("content", "").strip()
            name = meta.get("name") or meta.get("property") or "meta"
            if content:
                segments.append(
                    Segment(
                        id=f"seg-html-{seg_idx}",
                        text=content,
                        origin="metadata",
                        location=f"meta[{name}]",
                        hidden_reason=None,
                    )
                )
                seg_idx += 1

        # 2. Comments (comment)
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            c_text = comment.strip()
            if c_text:
                segments.append(
                    Segment(
                        id=f"seg-html-{seg_idx}",
                        text=c_text,
                        origin="comment",
                        location="<!-- comment -->",
                        hidden_reason="html_comment",
                    )
                )
                seg_idx += 1

        # 3. Attributes (alt, title, aria-label, data-*, hidden inputs)
        for tag in soup.find_all(True):
            if not isinstance(tag, Tag) or tag.name in ("script", "style"):
                continue

            loc = self._get_selector(tag)
            # Hidden input
            if tag.name == "input" and tag.get("type") == "hidden":
                val = tag.get("value", "").strip()
                if val:
                    segments.append(
                        Segment(
                            id=f"seg-html-{seg_idx}",
                            text=val,
                            origin="hidden",
                            location=f"{loc}[type=hidden]",
                            hidden_reason="hidden_input",
                        )
                    )
                    seg_idx += 1

            # Alt text
            alt = tag.get("alt", "").strip()
            if alt:
                segments.append(
                    Segment(
                        id=f"seg-html-{seg_idx}",
                        text=alt,
                        origin="alt_text",
                        location=f"{loc}[alt]",
                        hidden_reason=None,
                    )
                )
                seg_idx += 1

            # Title
            title = tag.get("title", "").strip()
            if title:
                segments.append(
                    Segment(
                        id=f"seg-html-{seg_idx}",
                        text=title,
                        origin="metadata",
                        location=f"{loc}[title]",
                        hidden_reason=None,
                    )
                )
                seg_idx += 1

            # Aria label
            aria_label = tag.get("aria-label", "").strip()
            if aria_label:
                segments.append(
                    Segment(
                        id=f"seg-html-{seg_idx}",
                        text=aria_label,
                        origin="alt_text",
                        location=f"{loc}[aria-label]",
                        hidden_reason=None,
                    )
                )
                seg_idx += 1

            # Data-* attributes
            for attr_name, attr_val in tag.attrs.items():
                if attr_name.startswith("data-") and isinstance(attr_val, str) and attr_val.strip():
                    segments.append(
                        Segment(
                            id=f"seg-html-{seg_idx}",
                            text=attr_val.strip(),
                            origin="metadata",
                            location=f"{loc}[{attr_name}]",
                            hidden_reason=None,
                        )
                    )
                    seg_idx += 1

        # 4. Text content & hidden elements (skip scripts, styles)
        for tag in soup.find_all(True):
            if not isinstance(tag, Tag):
                continue
            if tag.name in ("script", "style", "meta", "link"):
                continue

            hidden_reason = self._get_element_hidden_reason(tag, class_hidden_map)

            # Extract direct text inside tag to avoid duplicating child text
            direct_texts = [
                c.strip()
                for c in tag.children
                if isinstance(c, NavigableString)
                and not isinstance(c, Comment)
                and c.strip()
            ]
            if direct_texts:
                combined_text = " ".join(direct_texts)
                loc = self._get_selector(tag)
                origin = "hidden" if hidden_reason else "visible"
                segments.append(
                    Segment(
                        id=f"seg-html-{seg_idx}",
                        text=combined_text,
                        origin=origin,
                        location=loc,
                        hidden_reason=hidden_reason,
                    )
                )
                seg_idx += 1

        # If empty document or no text extracted, return an empty visible segment
        if not segments:
            segments.append(
                Segment(
                    id=f"seg-html-{seg_idx}",
                    text="",
                    origin="visible",
                    location="body",
                    hidden_reason=None,
                )
            )

        return segments
