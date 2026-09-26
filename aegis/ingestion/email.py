"""Ingestion adapter for Email messages (.eml / RFC 822) (§5.1)."""

import email
from email import policy as email_policy
import io
import re
from typing import TYPE_CHECKING

from aegis.ingestion.base import BaseAdapter, OversizeContentError
from aegis.ingestion.html import HtmlAdapter
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class EmailAdapter(BaseAdapter):
    """Adapter for EMAIL source using stdlib email with default policy."""

    source = InputSource.EMAIL

    def __init__(self):
        self.html_adapter = HtmlAdapter()

    def _extract_quoted_threads(self, body_text: str) -> list[tuple[str, str, str]]:
        """Separate direct email body from quoted thread lines (> ...)"""
        lines = body_text.splitlines()
        direct_lines = []
        quoted_lines = []

        in_quote = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(">") or re.match(r"^On\s+.+wrote:$", stripped, re.IGNORECASE):
                in_quote = True
                quoted_lines.append(line)
            elif in_quote and not stripped:
                quoted_lines.append(line)
            else:
                in_quote = False
                direct_lines.append(line)

        res = []
        direct = "\n".join(direct_lines).strip()
        quoted = "\n".join(quoted_lines).strip()
        if direct:
            res.append((direct, "body_visible", "visible"))
        if quoted:
            res.append((quoted, "quoted_thread", "comment"))
        return res

    def extract(
        self,
        data: bytes | str,
        *,
        filename: str | None = None,
        policy: "PolicyConfig | None" = None,
        depth: int = 0,
    ) -> list[Segment]:
        pol = policy or get_policy()

        if isinstance(data, str):
            raw_bytes = data.encode("utf-8")
        else:
            raw_bytes = data

        if len(raw_bytes) > pol.limits.max_upload_bytes:
            raise OversizeContentError(
                f"Email size {len(raw_bytes)} exceeds limit of {pol.limits.max_upload_bytes} bytes"
            )

        msg = email.message_from_bytes(raw_bytes, policy=email_policy.default)
        segments: list[Segment] = []
        seg_idx = 0

        # 1. Headers: Subject, From, To, Reply-To, CC, X-*
        interesting_headers = ["subject", "from", "to", "reply-to", "cc"]
        for header_name, header_val in msg.items():
            h_lower = header_name.lower()
            if h_lower in interesting_headers or h_lower.startswith("x-"):
                val_str = str(header_val).strip()
                if val_str:
                    segments.append(
                        Segment(
                            id=f"seg-email-{seg_idx}",
                            text=val_str,
                            origin="header",
                            location=f"header:{header_name}",
                            hidden_reason=None,
                        )
                    )
                    seg_idx += 1

        # 2. Body parts
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = part.get_content_disposition()

                if disposition == "attachment":
                    # Attachment routing (up to depth 2)
                    if depth < 2:
                        att_bytes = part.get_payload(decode=True)
                        att_fname = part.get_filename() or "attachment"
                        if att_bytes:
                            att_segments = self._route_attachment(
                                att_bytes, content_type, att_fname, pol, depth + 1
                            )
                            for aseg in att_segments:
                                segments.append(
                                    Segment(
                                        id=f"seg-email-{seg_idx}",
                                        text=aseg.text,
                                        origin=aseg.origin,
                                        location=f"attachment:{att_fname} > {aseg.location}",
                                        hidden_reason=aseg.hidden_reason,
                                    )
                                )
                                seg_idx += 1
                    continue

                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                        for t_content, loc, orig in self._extract_quoted_threads(text):
                            segments.append(
                                Segment(
                                    id=f"seg-email-{seg_idx}",
                                    text=t_content,
                                    origin=orig,
                                    location=loc,
                                    hidden_reason="quoted_thread" if orig == "comment" else None,
                                )
                            )
                            seg_idx += 1

                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        html_text = payload.decode(
                            part.get_content_charset() or "utf-8", errors="replace"
                        )
                        html_segs = self.html_adapter.extract(html_text, policy=pol)
                        for hseg in html_segs:
                            if hseg.text:
                                segments.append(
                                    Segment(
                                        id=f"seg-email-{seg_idx}",
                                        text=hseg.text,
                                        origin=hseg.origin,
                                        location=f"html_body > {hseg.location}",
                                        hidden_reason=hseg.hidden_reason,
                                    )
                                )
                                seg_idx += 1
        else:
            # Single-part message
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
                if content_type == "text/html":
                    html_segs = self.html_adapter.extract(text, policy=pol)
                    for hseg in html_segs:
                        if hseg.text:
                            segments.append(
                                Segment(
                                    id=f"seg-email-{seg_idx}",
                                    text=hseg.text,
                                    origin=hseg.origin,
                                    location=f"html_body > {hseg.location}",
                                    hidden_reason=hseg.hidden_reason,
                                )
                            )
                            seg_idx += 1
                else:
                    for t_content, loc, orig in self._extract_quoted_threads(text):
                        segments.append(
                            Segment(
                                id=f"seg-email-{seg_idx}",
                                text=t_content,
                                origin=orig,
                                location=loc,
                                hidden_reason="quoted_thread" if orig == "comment" else None,
                            )
                        )
                        seg_idx += 1

        if not segments:
            segments.append(
                Segment(
                    id=f"seg-email-{seg_idx}",
                    text="",
                    origin="visible",
                    location="body",
                    hidden_reason=None,
                )
            )

        return segments

    def _route_attachment(
        self,
        att_bytes: bytes,
        content_type: str,
        filename: str,
        policy: "PolicyConfig",
        depth: int,
    ) -> list[Segment]:
        """Route email attachments to specific format adapters."""
        fname_lower = filename.lower()
        if content_type == "application/pdf" or fname_lower.endswith(".pdf"):
            from aegis.ingestion.pdf import PdfAdapter

            return PdfAdapter().extract(att_bytes, policy=policy)
        elif (
            content_type
            == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            or fname_lower.endswith(".docx")
        ):
            from aegis.ingestion.docx import DocxAdapter

            return DocxAdapter().extract(att_bytes, policy=policy)
        elif content_type in ("image/png", "image/jpeg", "image/gif") or any(
            fname_lower.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif")
        ):
            from aegis.ingestion.image_ocr import ImageOcrAdapter

            return ImageOcrAdapter().extract(att_bytes, policy=policy)
        else:
            # Fall back to text extraction
            text = att_bytes.decode("utf-8", errors="replace")
            return [
                Segment(
                    id="seg-att-0",
                    text=text,
                    origin="visible",
                    location="attachment_text",
                    hidden_reason=None,
                )
            ]
