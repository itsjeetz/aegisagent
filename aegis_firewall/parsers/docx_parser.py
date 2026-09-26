"""
Word Document (.docx) Parser.
Extracts body paragraphs, tables, headers, footers, comments, and core XML properties
using python-docx.
"""

import io
import base64
import re
from typing import Dict, Any, List
from aegis_firewall.models import ParsedContent, InputSource

try:
    import docx
except ImportError:
    docx = None


class DocxParser:
    """Parses Word (.docx) documents from binary bytes, base64 data, or text streams."""

    @staticmethod
    def parse_bytes(docx_bytes: bytes, filename: str = "document.docx") -> ParsedContent:
        metadata_out = {"filename": filename}
        text_sections = []
        hidden_elements = []
        warnings = []

        if docx is None:
            raw_text = docx_bytes.decode('utf-8', errors='ignore')
            return ParsedContent(
                source=InputSource.WORD_DOC,
                raw_content=raw_text,
                extracted_text=raw_text,
                metadata=metadata_out,
                hidden_elements_count=0,
                warnings=["python-docx not available"]
            )

        try:
            doc = docx.Document(io.BytesIO(docx_bytes))
            
            # 1. Core Properties
            core = doc.core_properties
            for prop in ['title', 'author', 'comments', 'keywords', 'category', 'subject']:
                val = getattr(core, prop, None)
                if val:
                    val_str = str(val)
                    metadata_out[f"core_{prop}"] = val_str
                    if any(term in val_str.lower() for term in ['ignore', 'override', 'system', 'admin', 'prompt', 'exec', 'secret']):
                        hidden_elements.append(f"[DOCX Core Property '{prop}': {val_str}]")

            # 2. Headers and Footers (common stealth injection carrier)
            for s_idx, section in enumerate(doc.sections):
                header = section.header
                if header and header.paragraphs:
                    for hp in header.paragraphs:
                        if hp.text.strip():
                            h_text = hp.text.strip()
                            if any(term in h_text.lower() for term in ['ignore', 'override', 'system', 'agent', 'instruction']):
                                hidden_elements.append(f"[DOCX Header Section {s_idx + 1}: {h_text}]")
                            else:
                                text_sections.append(f"[Header: {h_text}]")
                                
                footer = section.footer
                if footer and footer.paragraphs:
                    for fp in footer.paragraphs:
                        if fp.text.strip():
                            f_text = fp.text.strip()
                            if any(term in f_text.lower() for term in ['ignore', 'override', 'system', 'agent', 'instruction']):
                                hidden_elements.append(f"[DOCX Footer Section {s_idx + 1}: {f_text}]")
                            else:
                                text_sections.append(f"[Footer: {f_text}]")

            # 3. Main Paragraphs
            for p in doc.paragraphs:
                if p.text.strip():
                    text_sections.append(p.text.strip())

            # 4. Tables
            for t_idx, table in enumerate(doc.tables):
                for r in table.rows:
                    row_vals = [c.text.strip() for c in r.cells if c.text.strip()]
                    if row_vals:
                        text_sections.append(" | ".join(row_vals))

        except Exception as e:
            warnings.append(f"DOCX extraction partial error: {str(e)}")
            raw_text = docx_bytes.decode('utf-8', errors='ignore')
            text_sections.append(raw_text)

        full_extracted = "\n".join(text_sections)
        if hidden_elements:
            warnings.append(f"Found {len(hidden_elements)} latent DOCX metadata/header/footer injection vectors")
            full_extracted += "\n\n--- [INSPECTED DOCX HEADERS/FOOTERS/METADATA] ---\n" + "\n".join(hidden_elements)

        return ParsedContent(
            source=InputSource.WORD_DOC,
            raw_content=full_extracted,
            extracted_text=full_extracted.strip(),
            metadata=metadata_out,
            hidden_elements_count=len(hidden_elements),
            warnings=warnings
        )

    @classmethod
    def parse(cls, content: str, metadata: Dict[str, Any] = None) -> ParsedContent:
        metadata = metadata or {}
        if content.startswith("data:application/vnd.openxmlformats") or "base64," in content[:60]:
            try:
                b64_data = content.split("base64,", 1)[1]
                raw_bytes = base64.b64decode(b64_data)
                return cls.parse_bytes(raw_bytes, metadata.get("filename", "document.docx"))
            except Exception:
                pass

        # Textual DOCX representation
        hidden_elements = []
        warnings = []
        
        header_matches = re.findall(r'\[(?:DOCX\s+)?Header:\s*(.*?)\]', content, re.IGNORECASE)
        for h in header_matches:
            if any(term in h.lower() for term in ['ignore', 'system', 'override', 'instruction', 'admin']):
                hidden_elements.append(f"[DOCX Header: {h}]")

        footer_matches = re.findall(r'\[(?:DOCX\s+)?Footer:\s*(.*?)\]', content, re.IGNORECASE)
        for f in footer_matches:
            if any(term in f.lower() for term in ['ignore', 'system', 'override', 'instruction', 'admin']):
                hidden_elements.append(f"[DOCX Footer: {f}]")

        combined = content
        if hidden_elements:
            warnings.append(f"Found {len(hidden_elements)} DOCX header/footer carriers")
            combined += "\n\n--- [INSPECTED DOCX HEADERS/FOOTERS] ---\n" + "\n".join(hidden_elements)

        return ParsedContent(
            source=InputSource.WORD_DOC,
            raw_content=content,
            extracted_text=combined.strip(),
            metadata=metadata,
            hidden_elements_count=len(hidden_elements),
            warnings=warnings
        )
