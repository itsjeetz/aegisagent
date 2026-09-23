"""
Markdown Content Parser.
Extracts visible text, analyzes embedded link titles, image alt texts, hidden markdown comments,
and inline HTML tags.
"""

import re
from typing import Dict, Any, List
from aegis_firewall.models import ParsedContent, InputSource
from aegis_firewall.parsers.html_parser import HTMLParserExtractor


class MarkdownParser:
    """Parses markdown content and extracts latent injection vectors in markdown syntax."""

    @staticmethod
    def parse(content: str, metadata: Dict[str, Any] = None) -> ParsedContent:
        metadata = metadata or {}
        warnings = []
        hidden_elements = []

        # 1. Inspect image alt texts: ![alt text](url "optional title")
        img_matches = re.findall(r'!\[(.*?)\]\((.*?)(?:\s+"(.*?)")?\)', content)
        for alt, url, title in img_matches:
            if any(term in (alt + title).lower() for term in ['ignore', 'override', 'system', 'admin', 'prompt', 'assistant', 'exec']):
                hidden_elements.append(f"[Markdown Image Injection: alt='{alt}', title='{title}']")

        # 2. Inspect link titles: [text](url "title")
        link_matches = re.findall(r'\[(.*?)\]\((.*?)\s+"(.*?)"\)', content)
        for text, url, title in link_matches:
            if any(term in title.lower() for term in ['ignore', 'system', 'override', 'secret', 'dan', 'jailbreak']):
                hidden_elements.append(f"[Markdown Link Title Injection: '{title}']")

        # 3. Inspect Markdown comments: [//]: # (comment) or [comment]: <> (text)
        md_comments = re.findall(r'\[//\]:\s*#\s*\((.*?)\)', content)
        md_comments += re.findall(r'\[.*?\]:\s*<>\s*\((.*?)\)', content)
        for comment in md_comments:
            hidden_elements.append(f"[Markdown Hidden Comment: {comment}]")

        # 4. Strip inline HTML tags using HTMLParserExtractor if present
        if '<' in content and '>' in content:
            html_parsed = HTMLParserExtractor.parse(content, source=InputSource.MARKDOWN)
            if html_parsed.hidden_elements_count > 0:
                hidden_elements.extend([f"[Embedded HTML: {w}]" for w in html_parsed.warnings])

        # Clean visible markdown formatting for text analysis
        text_without_links = re.sub(r'\[(.*?)\]\(.*?\)', r'\1', content)
        text_clean = re.sub(r'[#*`_~>]', ' ', text_without_links)

        combined_text = text_clean
        if hidden_elements:
            warnings.append(f"Found {len(hidden_elements)} latent markdown injection carriers")
            combined_text += "\n\n--- [INSPECTED MARKDOWN METADATA & HIDDEN PAYLOADS] ---\n" + "\n".join(hidden_elements)

        return ParsedContent(
            source=InputSource.MARKDOWN,
            raw_content=content,
            extracted_text=combined_text.strip(),
            metadata={
                **metadata,
                "image_tags_count": len(img_matches),
                "link_tags_count": len(link_matches),
                "hidden_md_comments_count": len(md_comments),
            },
            hidden_elements_count=len(hidden_elements),
            warnings=warnings
        )
