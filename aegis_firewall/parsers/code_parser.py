"""
Source Code Parser.
Tokenizes code across languages (Python, JavaScript, C/C++, Go, Java, Bash),
extracts comments (#, //, /* */), docstrings, and string literals,
detecting prompt injections disguised inside codebases.
"""

import re
from typing import Dict, Any, List
from aegis_firewall.models import ParsedContent, InputSource


class CodeParser:
    """Parses source code files and isolates commentary/literals from executable instructions."""

    @staticmethod
    def parse(content: str, metadata: Dict[str, Any] = None) -> ParsedContent:
        metadata = metadata or {}
        hidden_elements = []
        warnings = []
        comments = []
        string_literals = []

        # 1. Extract Python / Bash style single-line comments (# ...)
        py_comments = re.findall(r'#.*', content)
        comments.extend(py_comments)

        # 2. Extract C / JS style single-line comments (// ...)
        c_comments = re.findall(r'//.*', content)
        comments.extend(c_comments)

        # 3. Extract multiline comments (/* ... */)
        multi_comments = re.findall(r'/\*.*?\*/', content, re.DOTALL)
        comments.extend(multi_comments)

        # 4. Extract Python docstrings / multiline strings ("""...""" or '''...''')
        docstrings = re.findall(r'(""".*?"""|\'\'\'.*?\'\'\')', content, re.DOTALL)
        comments.extend(docstrings)

        # 5. Extract normal string literals ("..." or '...')
        strings = re.findall(r'["\']([^"\'\n]{15,})["\']', content)
        string_literals.extend(strings)

        # Inspect comments for prompt injection
        for c in comments:
            c_clean = c.strip('#/* \'\t\n')
            if any(term in c_clean.lower() for term in ['ignore previous', 'system prompt', 'you are now', 'developer mode', 'jailbreak', 'override', 'exfiltrate', 'run_command']):
                hidden_elements.append(f"[Code Comment Injection: '{c_clean}']")

        # Inspect string literals
        for s in string_literals:
            if any(term in s.lower() for term in ['ignore previous', 'system prompt', 'you are now', 'developer mode', 'jailbreak', 'override']):
                hidden_elements.append(f"[Code String Literal Injection: '{s}']")

        combined = content
        if hidden_elements:
            warnings.append(f"Found {len(hidden_elements)} malicious code comments / string payloads")
            combined += "\n\n--- [INSPECTED CODE COMMENTS & SUSPICIOUS LITERALS] ---\n" + "\n".join(hidden_elements)

        return ParsedContent(
            source=InputSource.SOURCE_CODE,
            raw_content=content,
            extracted_text=combined.strip(),
            metadata={
                **metadata,
                "comments_count": len(comments),
                "string_literals_count": len(string_literals),
                "detected_code_payloads": len(hidden_elements),
            },
            hidden_elements_count=len(hidden_elements),
            warnings=warnings
        )
