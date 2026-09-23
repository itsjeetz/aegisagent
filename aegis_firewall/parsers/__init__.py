"""
AegisAgent Ingestion & Parser Dispatcher.
Routes content across all 11 input sources to the appropriate specialized parser.
"""

from typing import Dict, Any, Union
from aegis_firewall.models import InputSource, ParsedContent
from aegis_firewall.parsers.text_parser import TextParser
from aegis_firewall.parsers.html_parser import HTMLParserExtractor
from aegis_firewall.parsers.markdown_parser import MarkdownParser
from aegis_firewall.parsers.pdf_parser import PDFParser
from aegis_firewall.parsers.docx_parser import DocxParser
from aegis_firewall.parsers.email_parser import EmailParser
from aegis_firewall.parsers.api_parser import APIParser
from aegis_firewall.parsers.code_parser import CodeParser
from aegis_firewall.parsers.ocr_image_parser import OCRImageParser


class IngestionDispatcher:
    """Dispatches heterogeneous inputs across 11 supported formats."""

    @classmethod
    def dispatch(cls, content: Union[str, bytes], source: InputSource, metadata: Dict[str, Any] = None) -> ParsedContent:
        metadata = metadata or {}
        
        # Binary byte dispatch
        if isinstance(content, bytes):
            filename = metadata.get("filename", "input.bin")
            if source == InputSource.PDF or filename.lower().endswith(".pdf"):
                return PDFParser.parse_bytes(content, filename)
            elif source == InputSource.WORD_DOC or filename.lower().endswith((".docx", ".doc")):
                return DocxParser.parse_bytes(content, filename)
            elif source in (InputSource.IMAGE_OCR, InputSource.OCR_TEXT) or filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                return OCRImageParser.parse_image_bytes(content, filename)
            else:
                # Decode to string
                content_str = content.decode('utf-8', errors='ignore')
                return cls.dispatch(content_str, source, metadata)

        # String dispatch
        content_str = str(content)
        if source == InputSource.USER_MESSAGE:
            return TextParser.parse(content_str, metadata)
        elif source == InputSource.WEB_PAGE:
            return HTMLParserExtractor.parse(content_str, source=InputSource.WEB_PAGE, metadata=metadata)
        elif source == InputSource.HTML:
            return HTMLParserExtractor.parse(content_str, source=InputSource.HTML, metadata=metadata)
        elif source == InputSource.MARKDOWN:
            return MarkdownParser.parse(content_str, metadata)
        elif source == InputSource.PDF:
            return PDFParser.parse(content_str, metadata)
        elif source == InputSource.WORD_DOC:
            return DocxParser.parse(content_str, metadata)
        elif source == InputSource.EMAIL:
            return EmailParser.parse(content_str, metadata)
        elif source == InputSource.API_RESPONSE:
            return APIParser.parse(content_str, metadata)
        elif source == InputSource.SOURCE_CODE:
            return CodeParser.parse(content_str, metadata)
        elif source == InputSource.OCR_TEXT:
            return OCRImageParser.parse(content_str, source=InputSource.OCR_TEXT, metadata=metadata)
        elif source == InputSource.IMAGE_OCR:
            return OCRImageParser.parse(content_str, source=InputSource.IMAGE_OCR, metadata=metadata)
        else:
            return TextParser.parse(content_str, metadata)
