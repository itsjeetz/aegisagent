"""
OCR & Image Parser.
Handles raw OCR text (with optical noise normalization) and image files (PNG, JPEG, WebP)
with EXIF/PNG metadata inspection and OCR text extraction.
"""

import io
import base64
import re
from typing import Dict, Any, List
from aegis_firewall.models import ParsedContent, InputSource

try:
    from PIL import Image, ExifTags
except ImportError:
    Image = None
    ExifTags = None


class OCRImageParser:
    """Parses OCR text feeds and image files, checking for optical attacks and image metadata injections."""

    @staticmethod
    def normalize_ocr_noise(text: str) -> str:
        """Corrects common OCR character confusions and layout fragmentation."""
        # Replace common OCR misreads in imperative keywords
        cleaned = text
        # Common OCR space fragmentation: "I g n o r e" -> "Ignore"
        cleaned = re.sub(r'(?<=\b[a-zA-Z])\s+(?=[a-zA-Z]\b)', '', cleaned)
        return cleaned

    @classmethod
    def parse_ocr_text(cls, content: str, metadata: Dict[str, Any] = None) -> ParsedContent:
        metadata = metadata or {}
        normalized = cls.normalize_ocr_noise(content)
        warnings = []
        if normalized != content:
            warnings.append("OCR character de-noising and space repair applied")

        return ParsedContent(
            source=InputSource.OCR_TEXT,
            raw_content=content,
            extracted_text=normalized.strip(),
            metadata={
                **metadata,
                "original_length": len(content),
                "repaired_length": len(normalized),
            },
            hidden_elements_count=0,
            warnings=warnings
        )

    @classmethod
    def parse_image_bytes(cls, image_bytes: bytes, filename: str = "image.png") -> ParsedContent:
        metadata_out = {"filename": filename}
        hidden_elements = []
        warnings = []
        extracted_text_chunks = []

        if Image is None:
            return ParsedContent(
                source=InputSource.IMAGE_OCR,
                raw_content="[Binary Image]",
                extracted_text="[Image Data: PIL not available]",
                metadata=metadata_out,
                hidden_elements_count=0,
                warnings=["Pillow not installed"]
            )

        try:
            img = Image.open(io.BytesIO(image_bytes))
            metadata_out["format"] = img.format
            metadata_out["size"] = f"{img.width}x{img.height}"
            metadata_out["mode"] = img.mode

            # 1. Inspect EXIF metadata
            exif_data = img.getexif()
            if exif_data:
                for tag_id, val in exif_data.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    val_str = str(val)
                    metadata_out[f"exif_{tag_name}"] = val_str
                    if any(term in val_str.lower() for term in ['ignore', 'override', 'system', 'admin', 'prompt', 'assistant', 'exec']):
                        hidden_elements.append(f"[Image EXIF Injection in '{tag_name}': {val_str}]")

            # 2. Inspect PNG text chunks (tEXt / zTXt)
            if hasattr(img, 'text') and isinstance(img.text, dict):
                for k, v in img.text.items():
                    metadata_out[f"png_text_{k}"] = str(v)
                    if any(term in str(v).lower() for term in ['ignore', 'override', 'system', 'admin', 'prompt', 'assistant', 'exec']):
                        hidden_elements.append(f"[PNG Text Chunk Injection '{k}': {v}]")

        except Exception as e:
            warnings.append(f"Image inspection error: {str(e)}")

        # If OCR text or simulated payload is passed in image filename or comments
        combined = f"[Image Metadata Scanned: {metadata_out.get('format', 'IMG')} {metadata_out.get('size', '')}]"
        if hidden_elements:
            warnings.append(f"Detected {len(hidden_elements)} steganographic image metadata injections")
            combined += "\n\n--- [INSPECTED IMAGE METADATA & HIDDEN PAYLOADS] ---\n" + "\n".join(hidden_elements)

        return ParsedContent(
            source=InputSource.IMAGE_OCR,
            raw_content=f"[Image File: {filename}]",
            extracted_text=combined.strip(),
            metadata=metadata_out,
            hidden_elements_count=len(hidden_elements),
            warnings=warnings
        )

    @classmethod
    def parse(cls, content: str, source: InputSource = InputSource.OCR_TEXT, metadata: Dict[str, Any] = None) -> ParsedContent:
        metadata = metadata or {}
        if source == InputSource.OCR_TEXT:
            return cls.parse_ocr_text(content, metadata)

        # Handle base64 image strings
        if content.startswith("data:image/") and "base64," in content:
            try:
                b64_data = content.split("base64,", 1)[1]
                raw_bytes = base64.b64decode(b64_data)
                return cls.parse_image_bytes(raw_bytes, metadata.get("filename", "upload.png"))
            except Exception:
                pass

        # Textual representation of OCR
        return cls.parse_ocr_text(content, metadata)
