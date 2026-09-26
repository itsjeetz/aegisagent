"""Ingestion adapter for DOCX documents (§5.1)."""

import io
import zipfile
from typing import TYPE_CHECKING
from lxml import etree

from aegis.ingestion.base import (
    BaseAdapter,
    OversizeContentError,
    ZipBombError,
    IngestionError,
)
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig

# WordprocessingML XML namespaces
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
CP_NS = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
DC_NS = "http://purl.org/dc/elements/1.1/"
NAMESPACES = {
    "w": W_NS,
    "cp": CP_NS,
    "dc": DC_NS,
}


class DocxAdapter(BaseAdapter):
    """Adapter for DOCX source using zipfile and raw XML parsing."""

    source = InputSource.DOCX

    def _check_zip_safety(self, z: zipfile.ZipFile, policy_limit_bytes: int):
        """Guard against zip bombs by checking total uncompressed size."""
        total_size = sum(info.file_size for info in z.infolist())
        if total_size > policy_limit_bytes:
            raise ZipBombError(
                f"Uncompressed DOCX archive size {total_size} exceeds limit of {policy_limit_bytes} bytes"
            )

    def _extract_core_properties(self, z: zipfile.ZipFile) -> list[tuple[str, str]]:
        """Extract metadata from docProps/core.xml."""
        results = []
        if "docProps/core.xml" in z.namelist():
            try:
                xml_data = z.read("docProps/core.xml")
                root = etree.fromstring(xml_data)
                for elem in root:
                    tag = etree.QName(elem.tag).localname
                    val = (elem.text or "").strip()
                    if val and tag in ("title", "creator", "description", "subject", "keywords"):
                        results.append((f"core.xml[{tag}]", val))
            except Exception:
                pass
        return results

    def _extract_comments(self, z: zipfile.ZipFile) -> list[tuple[str, str]]:
        """Extract user comments from word/comments.xml."""
        results = []
        if "word/comments.xml" in z.namelist():
            try:
                xml_data = z.read("word/comments.xml")
                root = etree.fromstring(xml_data)
                for comment in root.findall(".//w:comment", namespaces=NAMESPACES):
                    c_id = comment.get(f"{{{W_NS}}}id", "?")
                    texts = [
                        t.text
                        for t in comment.findall(".//w:t", namespaces=NAMESPACES)
                        if t.text and t.text.strip()
                    ]
                    if texts:
                        results.append((f"comment#{c_id}", " ".join(texts).strip()))
            except Exception:
                pass
        return results

    def _parse_xml_runs(
        self, xml_bytes: bytes, location_prefix: str
    ) -> list[tuple[str, str, str | None, str]]:
        """Parse XML containing Word runs and detect hidden properties.
        Returns list of (text, location, hidden_reason, origin).
        """
        results = []
        try:
            root = etree.fromstring(xml_bytes)
        except Exception:
            return results

        # Iterate over paragraphs
        for p_idx, p in enumerate(root.findall(".//w:p", namespaces=NAMESPACES)):
            p_loc = f"{location_prefix} p[{p_idx}]"
            for r in p.findall(".//w:r", namespaces=NAMESPACES):
                rpr = r.find("w:rPr", namespaces=NAMESPACES)
                hidden_reason = None

                if rpr is not None:
                    # Check <w:vanish/>
                    if rpr.find("w:vanish", namespaces=NAMESPACES) is not None:
                        hidden_reason = "vanish"
                    # Check white font color
                    color_elem = rpr.find("w:color", namespaces=NAMESPACES)
                    if color_elem is not None:
                        val = color_elem.get(f"{{{W_NS}}}val", "").upper()
                        if val in ("FFFFFF", "WHITE"):
                            hidden_reason = "white_text"
                    # Check tiny font size (w:sz in half-points <= 4 -> <= 2pt)
                    sz_elem = rpr.find("w:sz", namespaces=NAMESPACES)
                    if sz_elem is not None:
                        try:
                            sz_val = int(sz_elem.get(f"{{{W_NS}}}val", "24"))
                            if sz_val <= 4:
                                hidden_reason = "tiny_font"
                        except ValueError:
                            pass

                # Extract text
                t_elements = r.findall(".//w:t", namespaces=NAMESPACES)
                run_text = "".join(t.text for t in t_elements if t.text)
                if run_text.strip():
                    origin = "hidden" if hidden_reason else "visible"
                    results.append((run_text.strip(), p_loc, hidden_reason, origin))

        return results

    def extract(
        self,
        data: bytes | str,
        *,
        filename: str | None = None,
        policy: "PolicyConfig | None" = None,
    ) -> list[Segment]:
        pol = policy or get_policy()

        if isinstance(data, str):
            raw_bytes = data.encode("utf-8")
        else:
            raw_bytes = data

        if len(raw_bytes) > pol.limits.max_upload_bytes:
            raise OversizeContentError(
                f"DOCX size {len(raw_bytes)} exceeds limit of {pol.limits.max_upload_bytes} bytes"
            )

        try:
            z = zipfile.ZipFile(io.BytesIO(raw_bytes))
        except zipfile.BadZipFile as e:
            raise IngestionError(f"Invalid DOCX file (not a valid zip archive): {e}") from e

        # Check zip bomb limit
        self._check_zip_safety(z, pol.limits.max_zip_uncompressed_bytes)

        segments: list[Segment] = []
        seg_idx = 0

        # 1. Metadata from docProps/core.xml
        for loc, val in self._extract_core_properties(z):
            segments.append(
                Segment(
                    id=f"seg-docx-{seg_idx}",
                    text=val,
                    origin="metadata",
                    location=loc,
                    hidden_reason=None,
                )
            )
            seg_idx += 1

        # 2. Comments from word/comments.xml
        for loc, val in self._extract_comments(z):
            segments.append(
                Segment(
                    id=f"seg-docx-{seg_idx}",
                    text=val,
                    origin="comment",
                    location=loc,
                    hidden_reason="docx_comment",
                )
            )
            seg_idx += 1

        # 3. Headers and Footers
        for name in z.namelist():
            if name.startswith("word/header") or name.startswith("word/footer"):
                try:
                    xml_bytes = z.read(name)
                    for text, loc, reason, orig in self._parse_xml_runs(xml_bytes, name):
                        segments.append(
                            Segment(
                                id=f"seg-docx-{seg_idx}",
                                text=text,
                                origin=orig,
                                location=loc,
                                hidden_reason=reason,
                            )
                        )
                        seg_idx += 1
                except Exception:
                    pass

        # 4. Footnotes and Endnotes
        for name in ("word/footnotes.xml", "word/endnotes.xml"):
            if name in z.namelist():
                try:
                    xml_bytes = z.read(name)
                    for text, loc, reason, orig in self._parse_xml_runs(xml_bytes, name):
                        segments.append(
                            Segment(
                                id=f"seg-docx-{seg_idx}",
                                text=text,
                                origin=orig,
                                location=loc,
                                hidden_reason=reason,
                            )
                        )
                        seg_idx += 1
                except Exception:
                    pass

        # 5. Body document (word/document.xml)
        if "word/document.xml" in z.namelist():
            try:
                xml_bytes = z.read("word/document.xml")
                for text, loc, reason, orig in self._parse_xml_runs(xml_bytes, "document.xml"):
                    segments.append(
                        Segment(
                            id=f"seg-docx-{seg_idx}",
                            text=text,
                            origin=orig,
                            location=loc,
                            hidden_reason=reason,
                        )
                    )
                    seg_idx += 1
            except Exception as e:
                raise IngestionError(f"Failed to parse word/document.xml: {e}") from e

        if not segments:
            segments.append(
                Segment(
                    id=f"seg-docx-{seg_idx}",
                    text="",
                    origin="visible",
                    location="document",
                    hidden_reason=None,
                )
            )

        return segments
