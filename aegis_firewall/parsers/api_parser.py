"""
API Response Parser.
Recursively traverses JSON / XML payloads, inspecting keys, string values,
nested arrays, headers, and error codes for embedded injections.
"""

import json
import re
from typing import Dict, Any, List
from aegis_firewall.models import ParsedContent, InputSource


class APIParser:
    """Parses API responses (JSON, XML, Key-Value) and flags payload injections in fields."""

    @classmethod
    def _extract_strings_recursive(cls, data: Any, prefix: str = "", collected: List[str] = None, tainted: List[str] = None):
        if collected is None:
            collected = []
        if tainted is None:
            tainted = []

        if isinstance(data, dict):
            for k, v in data.items():
                curr_path = f"{prefix}.{k}" if prefix else str(k)
                # Check key name itself
                if any(term in str(k).lower() for term in ['override', 'system', 'prompt', 'inject']):
                    tainted.append(f"[Suspicious API Key '{curr_path}': {v}]")
                cls._extract_strings_recursive(v, curr_path, collected, tainted)
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                cls._extract_strings_recursive(item, f"{prefix}[{idx}]", collected, tainted)
        elif isinstance(data, str):
            clean_str = data.strip()
            collected.append(f"{prefix}: {clean_str}")
            if any(term in clean_str.lower() for term in ['ignore previous', 'system prompt', 'you are now', 'developer mode', 'exfiltrate', 'run_command']):
                tainted.append(f"[Tainted API Field '{prefix}': {clean_str}]")
        elif data is not None:
            collected.append(f"{prefix}: {str(data)}")

        return collected, tainted

    @classmethod
    def parse(cls, content: str, metadata: Dict[str, Any] = None) -> ParsedContent:
        metadata = metadata or {}
        warnings = []
        collected = []
        tainted = []

        # Attempt JSON parse
        parsed_json = None
        try:
            parsed_json = json.loads(content)
        except Exception:
            # Check if JSON wrapped in markdown or partial
            json_match = re.search(r'\{.*\}|\[.*\]', content, re.DOTALL)
            if json_match:
                try:
                    parsed_json = json.loads(json_match.group(0))
                except Exception:
                    pass

        if parsed_json is not None:
            collected, tainted = cls._extract_strings_recursive(parsed_json)
            extracted_text = "\n".join(collected)
            format_type = "JSON"
        else:
            extracted_text = content
            format_type = "Raw API Text"
            # Regex for key-value pairs
            kv_matches = re.findall(r'(\w+)\s*[:=]\s*(.+)', content)
            for k, v in kv_matches:
                if any(term in v.lower() for term in ['ignore previous', 'system prompt', 'override', 'jailbreak']):
                    tainted.append(f"[Tainted API Key-Value '{k}': {v}]")

        if tainted:
            warnings.append(f"Identified {len(tainted)} tainted API response fields")
            extracted_text += "\n\n--- [INSPECTED API TAINTED FIELDS] ---\n" + "\n".join(tainted)

        return ParsedContent(
            source=InputSource.API_RESPONSE,
            raw_content=content,
            extracted_text=extracted_text.strip(),
            metadata={
                **metadata,
                "api_format": format_type,
                "fields_parsed_count": len(collected),
                "tainted_fields_count": len(tainted),
            },
            hidden_elements_count=len(tainted),
            warnings=warnings
        )
