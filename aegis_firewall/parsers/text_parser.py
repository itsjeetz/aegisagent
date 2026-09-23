"""
Text Parser for User Messages & conversational inputs.
Normalizes text, strips carriage returns, and checks for direct prompt delimiters.
"""

import re
from typing import Dict, Any
from aegis_firewall.models import ParsedContent, InputSource


class TextParser:
    """Parses plain user messages and raw chat inputs."""

    @staticmethod
    def parse(content: str, metadata: Dict[str, Any] = None) -> ParsedContent:
        metadata = metadata or {}
        # Count formatting cues
        lines = content.splitlines()
        delimiter_matches = re.findall(r'(?i)(system:|assistant:|user:|human:|###|\<\|im_start\|\>|\[inst\])', content)
        
        return ParsedContent(
            source=InputSource.USER_MESSAGE,
            raw_content=content,
            extracted_text=content.strip(),
            metadata={
                **metadata,
                "line_count": len(lines),
                "character_count": len(content),
                "delimiter_cue_count": len(delimiter_matches),
            },
            hidden_elements_count=0,
            warnings=[]
        )
