"""
Attack 4: Tool Abuse Detector.
Detects attempts to hijack agent tools, trigger unauthorized commands, execute arbitrary shell scripts,
poison database queries, exfiltrate data via email, or invoke dangerous APIs.
"""

from typing import List, Dict, Any
import re
from aegis_firewall.models import AttackType, AttackSignal, InputSource
from aegis_firewall.detectors.rule_base import BaseDetector


class ToolAbuseDetector(BaseDetector):
    attack_type = AttackType.TOOL_ABUSE

    def __init__(self):
        super().__init__("ToolAbuseDetector")
        self.rules = [
            # 1. Shell & Arbitrary Code Execution invocations
            (
                r'(?i)\b(?:call\s+tool|execute_code|run_command|run_bash|bash_tool|exec_cmd|powershell|terminal)\s*[\(\{].*?(?:rm\s+-rf|curl|wget|chmod|cat\s+/etc/passwd|del\s+/f|Invoke-WebRequest).*?[\)\}]',
                "TA-001",
                "Dangerous tool execution with system destruction / remote fetch parameters",
                0.99,
                "CRITICAL"
            ),
            # 2. Command Injection Syntax in Agent Tool Prompts
            (
                r'(?i)\b(?:call|trigger|execute|use)\s+(?:the\s+)?(?:bash|terminal|shell|code_runner|command_line)\s+(?:tool|function)\s+(?:to\s+)?(?:run|execute)\s+["\'].*?(?:curl|wget|python|sh|bash|cat|netcat|nc)\b',
                "TA-002",
                "Direct instruction forcing agent tool to execute shell payloads",
                0.97,
                "CRITICAL"
            ),
            # 3. Unauthorized Exfiltration Tool Calls (e.g. send_email, post_data)
            (
                r'(?i)\b(?:send_email|forward_mail|http_post|webhook_post|exfiltrate_data)\s*[\(\{].*?(?:to|url|recipient)\s*[:=]\s*["\'].*?(?:attacker|evil|webhook|pastebin|ngrok|pipedream).*?[\)\}]',
                "TA-003",
                "Agent tool invocation weaponized for data exfiltration",
                0.98,
                "CRITICAL"
            ),
            # 4. Database Manipulation via Agent Tools (SQL Injection via Agent)
            (
                r'(?i)\b(?:sql_query|execute_sql|database_query|db_tool)\s*[\(\{].*?(?:DROP\s+TABLE|DELETE\s+FROM|UNION\s+SELECT|ALTER\s+TABLE|TRUNCATE).*?[\)\}]',
                "TA-004",
                "Agent database tool weaponized for data destruction or SQL injection",
                0.98,
                "CRITICAL"
            ),
            # 5. Financial / Authorization Tool Abuse
            (
                r'(?i)\b(?:transfer_funds|execute_payment|make_transfer|authorize_transaction)\s*[\(\{].*?(?:amount|recipient|to).*?[\)\}]',
                "TA-005",
                "Agent financial transfer tool abuse attempt",
                0.95,
                "CRITICAL"
            ),
            # 6. Imperative Directive commanding tool execution without user authorization
            (
                r'(?i)\b(?:you\s+must|immediately|secretly|silently)\s+(?:call|invoke|trigger)\s+(?:the\s+)?(?:tool|function|plugin)\s+(?:without\s+(?:asking|confirming|alerting)|in\s+the\s+background)\b',
                "TA-006",
                "Autonomous unconfirmed tool invocation mandate",
                0.94,
                "HIGH"
            ),
            # 7. Generalized Destructive Database DDL/DML Directives
            (
                r'(?i)(?:'
                r'\b(?:run|execute|call|apply|perform)\s+(?:(?:the|this|a|an)\s+)?(?:sql(?:\s+query)?|query|command|script|statement)?.*?\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|USER|ROLE|VIEW|FUNCTION|PROCEDURE)|TRUNCATE\s+(?:TABLE\s+)?|DELETE\s+FROM|ALTER\s+(?:TABLE|DATABASE|USER|ROLE))\b'
                r'|'
                r'\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|USER|ROLE|VIEW|FUNCTION|PROCEDURE)|TRUNCATE\s+(?:TABLE\s+)?|ALTER\s+(?:TABLE|DATABASE|USER|ROLE))\s+(?:IF\s+EXISTS\s+)?[`"\'\w]+(?:\s+(?:CASCADE|RESTRICT))?(?:\s*;\s*(?:--)?|\s*;|\b)'
                r')',
                "TA-007",
                "Imperative destructive SQL database command execution attempt",
                0.98,
                "CRITICAL"
            ),
            # 8. Database Privilege Escalation & Grant/Revoke Signals
            (
                r'(?i)\b(?:GRANT\s+(?:ALL(?:\s+PRIVILEGES)?|[A-Z_]+(?:\s*,\s*[A-Z_]+)*)(?:(?!\.\s|[;?!]|\n\s*\n)[\s\S])*?\s+TO\s+[`"\'\w]+|REVOKE\s+(?:(?!\.\s|[;?!]|\n\s*\n)[\s\S])*?\s+FROM\s+[`"\'\w]+)\b',
                "TA-008",
                "Unauthorized privilege escalation or permission modification attempt",
                0.97,
                "CRITICAL"
            ),
            # 9. Service Disruption & System Shutdown Commands
            (
                r'(?i)\b(?:shutdown|kill|terminate|stop|halt|restart)\s+(?:the\s+)?(?:database|db|server|service|daemon|process|system)(?:\s+(?:server|service|daemon|process))?\b',
                "TA-009",
                "Direct attempt to disrupt, terminate, or shut down core database/server services",
                0.98,
                "CRITICAL"
            ),
            # 10. Standalone Destructive Shell and Operating System Commands
            (
                r'(?i)\b(?:rm\s+-(?:r[fF]|f[rR]|rf|fr)\s+[\/\*~A-Za-z0-9_.]+|del\s+\/[fF]\s+\/[sS]|format\s+[a-zA-Z]:|mkfs(?:\.\w+)?\s+/dev/[a-z0-9]+)',
                "TA-010",
                "Dangerous standalone destructive system command execution",
                0.99,
                "CRITICAL"
            )
        ]

    @staticmethod
    def _is_interrogative_match(text: str, start_pos: int, matched_text: str = "") -> bool:
        """
        Suppresses match when the sentence/clause opens with an interrogative pattern
        (what/how/why/can you/could you + is/do/does/etc.) before the SQL keyword,
        unless the match itself or prefix contains an imperative execution directive (run, execute, etc.).
        """
        if start_pos < 0:
            return False

        # If the match itself begins with an imperative execution verb, do not suppress
        if re.search(r'(?i)^\s*(?:run|execute|apply|perform|call)\b', matched_text):
            return False

        # Find start of sentence/clause
        delims = [text.rfind(d, 0, start_pos) for d in ['.', '?', '!', '\n', ';']]
        sent_start = max(delims)
        sent_start = 0 if sent_start == -1 else sent_start + 1
        prefix = text[sent_start:start_pos].strip()

        # Interrogative opening check (what/how/why/can you/could you + is/do/does/etc.)
        interrogative_pat = r'(?i)^\s*(?:what\s+(?:is|are|was|were|does|do)|how\s+(?:do|does|did|can|could|to|would)|why\s+(?:do|does|did|is|are)|can\s+you|could\s+you|would\s+you)\b'
        if not re.search(interrogative_pat, prefix):
            return False

        # Do NOT suppress if prefix contains an imperative execution directive before the match
        if re.search(r'(?i)\b(?:run|execute|apply|perform|call)\b', prefix):
            return False

        return True

    def detect(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> List[AttackSignal]:
        signals = []
        for pattern, rule_id, desc, conf, sev in self.rules:
            matches = self.find_matches(pattern, text, rule_id, self.attack_type, desc, conf, sev)
            if rule_id in ("TA-007", "TA-008") and matches:
                filtered = [m for m in matches if not self._is_interrogative_match(text, m.start_pos, m.matched_text)]
                signals.extend(filtered)
            else:
                signals.extend(matches)
        return signals
