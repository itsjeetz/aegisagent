"""
HTML & Web Page Parser.
Extracts visible text, isolates HTML comments, detects hidden CSS/DOM nodes
(e.g., display:none, opacity:0, font-size:0, aria-hidden, hidden input fields, data-* instructions).
"""

import re
from html.parser import HTMLParser
from typing import Dict, Any, List
from aegis_firewall.models import ParsedContent, InputSource


class DOMInspector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text_chunks = []
        self.hidden_chunks = []
        self.comments = []
        self.meta_tags = []
        self.current_tags = []
        self.is_hidden_stack = []

    def handle_starttag(self, tag, attrs):
        self.current_tags.append(tag)
        attr_dict = dict(attrs)
        
        # Check for hidden indicators
        style = attr_dict.get('style', '').lower()
        is_hidden = False
        
        if 'display:none' in style or 'display: none' in style:
            is_hidden = True
        elif 'visibility:hidden' in style or 'visibility: hidden' in style:
            is_hidden = True
        elif 'opacity:0' in style or 'opacity: 0' in style:
            is_hidden = True
        elif 'font-size:0' in style or 'font-size: 0' in style:
            is_hidden = True
        elif 'color:white' in style or 'color:#fff' in style or 'color:transparent' in style:
            is_hidden = True
            
        if 'hidden' in attr_dict:
            is_hidden = True
        if attr_dict.get('aria-hidden') == 'true':
            is_hidden = True
        if tag == 'input' and attr_dict.get('type') == 'hidden':
            val = attr_dict.get('value', '')
            if val:
                self.hidden_chunks.append(f"[Hidden Input: {val}]")
                
        # Check meta tags
        if tag == 'meta':
            content = attr_dict.get('content', '')
            if content:
                self.meta_tags.append(content)

        # Check data attributes
        for k, v in attr_dict.items():
            if k.startswith('data-') and any(term in k.lower() or term in v.lower() for term in ['prompt', 'inst', 'eval', 'cmd', 'inject']):
                self.hidden_chunks.append(f"[Data Attribute {k}: {v}]")

        self.is_hidden_stack.append(is_hidden)

    def handle_endtag(self, tag):
        if self.current_tags:
            self.current_tags.pop()
        if self.is_hidden_stack:
            self.is_hidden_stack.pop()

    def handle_data(self, data):
        cleaned = data.strip()
        if not cleaned:
            return
            
        # Ignore script and style content as visible text
        if self.current_tags and self.current_tags[-1] in ('script', 'style'):
            # But inspect script strings for prompt injections!
            if any(term in cleaned.lower() for term in ['ignore previous', 'system prompt', 'developer mode', 'jailbreak']):
                self.hidden_chunks.append(f"[Script Payload: {cleaned}]")
            return

        if any(self.is_hidden_stack):
            self.hidden_chunks.append(cleaned)
        else:
            self.text_chunks.append(cleaned)

    def handle_comment(self, data):
        cleaned = data.strip()
        if cleaned:
            self.comments.append(cleaned)


class HTMLParserExtractor:
    """Parses HTML documents and scraped web pages with deep DOM inspection."""

    @staticmethod
    def parse(content: str, source: InputSource = InputSource.HTML, metadata: Dict[str, Any] = None) -> ParsedContent:
        metadata = metadata or {}
        inspector = DOMInspector()
        try:
            inspector.feed(content)
        except Exception:
            # Fallback regex extraction if malformed HTML
            pass

        visible_text = "\n".join(inspector.text_chunks)
        hidden_elements = inspector.hidden_chunks + [f"[HTML Comment: {c}]" for c in inspector.comments]
        
        combined_text = visible_text
        warnings = []
        if hidden_elements:
            warnings.append(f"Detected {len(hidden_elements)} hidden HTML elements / comments")
            combined_text += "\n\n--- [INSPECTED HIDDEN DOM CONTENT] ---\n" + "\n".join(hidden_elements)

        return ParsedContent(
            source=source,
            raw_content=content,
            extracted_text=combined_text.strip() if combined_text.strip() else content.strip(),
            metadata={
                **metadata,
                "visible_text_length": len(visible_text),
                "hidden_items_count": len(hidden_elements),
                "comments_count": len(inspector.comments),
                "meta_tags_count": len(inspector.meta_tags),
            },
            hidden_elements_count=len(hidden_elements),
            warnings=warnings
        )
