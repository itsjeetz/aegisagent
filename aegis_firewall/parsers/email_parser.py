"""
Email Parser.
Inspects email headers (From, To, Subject, Reply-To, X-Headers),
parses multipart plaintext and HTML bodies, detects injected signatures and quoted replies.
"""

import email
import re
from email import policy
from typing import Dict, Any, List
from aegis_firewall.models import ParsedContent, InputSource
from aegis_firewall.parsers.html_parser import HTMLParserExtractor


class EmailParser:
    """Parses RFC822 / MIME emails and email-formatted strings."""

    @staticmethod
    def parse(content: str, metadata: Dict[str, Any] = None) -> ParsedContent:
        metadata = metadata or {}
        hidden_elements = []
        warnings = []
        body_text = ""
        headers_found = {}

        # Check if content looks like an RFC822 raw message
        if any(h in content[:300] for h in ["From:", "Subject:", "To:", "Date:"]):
            try:
                msg = email.message_from_string(content, policy=policy.default)
                for header_key in ['From', 'To', 'Cc', 'Subject', 'Reply-To']:
                    if msg[header_key]:
                        headers_found[header_key.lower()] = str(msg[header_key])

                # Check for prompt injection inside headers
                for hk, hv in headers_found.items():
                    if any(term in hv.lower() for term in ['ignore', 'override', 'system', 'admin', 'eval', 'exfil']):
                        hidden_elements.append(f"[Email Header Injection in '{hk}': {hv}]")

                # Extract body
                if msg.is_multipart():
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        cdispo = str(part.get('Content-Disposition', ''))
                        if 'attachment' in cdispo:
                            continue
                        if ctype == 'text/plain':
                            body_text += part.get_content() + "\n"
                        elif ctype == 'text/html':
                            html_content = part.get_content()
                            html_parsed = HTMLParserExtractor.parse(html_content, source=InputSource.EMAIL)
                            body_text += html_parsed.extracted_text + "\n"
                            if html_parsed.hidden_elements_count > 0:
                                hidden_elements.extend(html_parsed.warnings)
                else:
                    ctype = msg.get_content_type()
                    payload = msg.get_content()
                    if ctype == 'text/html':
                        html_parsed = HTMLParserExtractor.parse(payload, source=InputSource.EMAIL)
                        body_text = html_parsed.extracted_text
                        if html_parsed.hidden_elements_count > 0:
                            hidden_elements.extend(html_parsed.warnings)
                    else:
                        body_text = str(payload)

            except Exception:
                body_text = content
        else:
            body_text = content

        # Inspect typical email signature injections
        sig_match = re.search(r'(--\s*\n|Best regards,?|Sincerely,?|Thanks,?)(.*)', body_text, re.DOTALL | re.IGNORECASE)
        if sig_match:
            signature_content = sig_match.group(2)
            if any(term in signature_content.lower() for term in ['ignore', 'assistant', 'forward', 'system', 'override', 'prompt', 'exfiltrate']):
                hidden_elements.append(f"[Email Signature Prompt Injection: '{signature_content.strip()}']")

        # Inspect quoted reply chains
        quote_matches = re.findall(r'On\s+.*?\s+wrote:(.*?)(?=\n\n|\Z)', body_text, re.DOTALL | re.IGNORECASE)
        for q in quote_matches:
            if any(term in q.lower() for term in ['ignore', 'system prompt', 'override', 'admin mode']):
                hidden_elements.append(f"[Email Quoted History Injection: '{q.strip()}']")

        combined = f"Subject: {headers_found.get('subject', 'N/A')}\nFrom: {headers_found.get('from', 'N/A')}\n\n{body_text}"
        if hidden_elements:
            warnings.append(f"Identified {len(hidden_elements)} email-borne injection vectors")
            combined += "\n\n--- [INSPECTED EMAIL VECTORS & TAINTED METADATA] ---\n" + "\n".join(hidden_elements)

        return ParsedContent(
            source=InputSource.EMAIL,
            raw_content=content,
            extracted_text=combined.strip(),
            metadata={
                **metadata,
                **headers_found,
                "has_signature": bool(sig_match),
                "quotes_count": len(quote_matches),
            },
            hidden_elements_count=len(hidden_elements),
            warnings=warnings
        )
