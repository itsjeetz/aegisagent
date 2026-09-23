"""
Attack 4: Tool Abuse Detector.
Detects attempts to hijack agent tools, trigger unauthorized commands, execute arbitrary shell scripts,
poison database queries, exfiltrate data via email, or invoke dangerous APIs.
"""

from typing import List, Dict, Any
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
            )
        ]

    def detect(self, text: str, source: InputSource, metadata: Dict[str, Any] = None) -> List[AttackSignal]:
        signals = []
        for pattern, rule_id, desc, conf, sev in self.rules:
            matches = self.find_matches(pattern, text, rule_id, self.attack_type, desc, conf, sev)
            signals.extend(matches)
        return signals
