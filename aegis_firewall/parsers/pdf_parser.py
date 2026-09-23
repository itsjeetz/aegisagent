"""
PDF Parser for document streams and binary files.
Extracts visible page contents, PDF document metadata (/Title, /Author, /Subject, /Keywords),
and document annotations using pypdf.
"""

import io
import base64
import re
from typing import Dict, Any, List
from aegis_firewall.models import ParsedContent, InputSource

try:
    import pypdf
except ImportError:
    pypdf = None


class PDFParser:
    """Parses PDF documents from raw bytes, base64 strings, or text representations."""

    @staticmethod
    def parse_bytes(pdf_bytes: bytes, filename: str = "document.pdf") -> ParsedContent:
        metadata_out = {"filename": filename}
        text_pages = []
        hidden_elements = []
        warnings = []

        if pypdf is None:
            raw_text = pdf_bytes.decode('utf-8', errors='ignore')
            return ParsedContent(
                source=InputSource.PDF,
                raw_content=raw_text,
                extracted_text=raw_text,
                metadata=metadata_out,
                hidden_elements_count=0,
                warnings=["pypdf not available, parsed as raw text"]
            )

        try:
            reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
            metadata_out["page_count"] = len(reader.pages)
            
            # Inspect Document Info Metadata
            doc_info = reader.metadata
            if doc_info:
                for k, v in doc_info.items():
                    key_str = str(k).lstrip('/')
                    val_str = str(v)
                    metadata_out[f"meta_{key_str}"] = val_str
                    # Check for prompt injection in metadata fields
                    if any(term in val_str.lower() for term in ['ignore', 'override', 'system', 'admin', 'prompt', 'assistant', 'exec', 'bearer', 'secret']):
                        hidden_elements.append(f"[PDF Metadata Injection in '{key_str}': {val_str}]")

            # Extract pages and inspect annotations
            for idx, page in enumerate(reader.pages):
                page_text = page.extract_text() or ""
                text_pages.append(f"--- Page {idx + 1} ---\n{page_text}")
                
                # Check annotations
                if "/Annots" in page:
                    annots = page["/Annots"]
                    if isinstance(annots, list):
                        for a in annots:
                            annot_obj = a.get_object() if hasattr(a, 'get_object') else a
                            contents = annot_obj.get("/Contents")
                            if contents:
                                contents_str = str(contents)
                                if any(term in contents_str.lower() for term in ['ignore', 'system', 'override', 'eval']):
                                    hidden_elements.append(f"[PDF Annotation on Page {idx + 1}: {contents_str}]")

        except Exception as e:
            warnings.append(f"PDF extraction partial error: {str(e)}")
            raw_text = pdf_bytes.decode('utf-8', errors='ignore')
            text_pages.append(raw_text)

        full_extracted = "\n\n".join(text_pages)
        if hidden_elements:
            warnings.append(f"Found {len(hidden_elements)} latent PDF metadata/annotation payloads")
            full_extracted += "\n\n--- [INSPECTED PDF METADATA & HIDDEN LAYERS] ---\n" + "\n".join(hidden_elements)

        return ParsedContent(
            source=InputSource.PDF,
            raw_content=full_extracted,
            extracted_text=full_extracted.strip(),
            metadata=metadata_out,
            hidden_elements_count=len(hidden_elements),
            warnings=warnings
        )

    @classmethod
    def parse(cls, content: str, metadata: Dict[str, Any] = None) -> ParsedContent:
        metadata = metadata or {}
        # Check if content is base64 encoded PDF
        if content.startswith("data:application/pdf;base64,"):
            b64_data = content.split(",", 1)[1]
            try:
                raw_bytes = base64.b64decode(b64_data)
                return cls.parse_bytes(raw_bytes, metadata.get("filename", "upload.pdf"))
            except Exception:
                pass
        elif content.startswith("%PDF-"):
            raw_bytes = content.encode('latin1', errors='ignore')
            return cls.parse_bytes(raw_bytes, metadata.get("filename", "stream.pdf"))

        # If it's a simulated or textual PDF representation
        hidden_elements = []
        warnings = []
        
        # Check for simulated metadata tags
        meta_matches = re.findall(r'\[PDF\s+Metadata:\s*(.*?)\]', content, re.IGNORECASE)
        for m in meta_matches:
            hidden_elements.append(f"[PDF Metadata: {m}]")

        annot_matches = re.findall(r'\[PDF\s+Annotation:\s*(.*?)\]', content, re.IGNORECASE)
        for a in annot_matches:
            hidden_elements.append(f"[PDF Annotation: {a}]")

        combined = content
        if hidden_elements:
            warnings.append(f"Identified {len(hidden_elements)} simulated PDF metadata vectors")
            combined += "\n\n--- [INSPECTED PDF METADATA & HIDDEN LAYERS] ---\n" + "\n".join(hidden_elements)

        return ParsedContent(
            source=InputSource.PDF,
            raw_content=content,
            extracted_text=combined.strip(),
            metadata=metadata,
            hidden_elements_count=len(hidden_elements),
            warnings=warnings
        )
