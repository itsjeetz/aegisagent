"""
Agent Middleware & Tool Protection Decorators.
Enables plug-and-play integration with LangChain, LlamaIndex, OpenAI, and custom agent workflows.
"""

from functools import wraps
from typing import Callable, Any, Dict, Optional, Tuple
from aegis_firewall.models import InputSource, FirewallVerdict, DefenseAction
from aegis_firewall.engine import FirewallEngine


class AegisAgentMiddleware:
    """Interceptor middleware positioned between external data/users and AI agents."""

    def __init__(self, firewall: Optional[FirewallEngine] = None):
        self.firewall = firewall or FirewallEngine()

    def intercept(self, content: str, source: InputSource = InputSource.USER_MESSAGE,
                  session_id: str = "agent_session") -> Tuple[str, FirewallVerdict]:
        """Intercepts input, scans, neutralizes threats, and returns safe sanitized prompt for LLM."""
        verdict = self.firewall.inspect(content, source=source, session_id=session_id)
        return verdict.neutralized.safe_text, verdict

    def protect_tool(self, tool_func: Callable) -> Callable:
        """Decorator that inspects tool arguments for injected shell payloads, SQL injection, or exfiltration."""
        @wraps(tool_func)
        def wrapper(*args, **kwargs):
            combined_args = " ".join([str(a) for a in args] + [f"{k}={v}" for k, v in kwargs.items()])
            verdict = self.firewall.inspect(combined_args, source=InputSource.USER_MESSAGE)
            if not verdict.is_safe and verdict.risk_score >= 60.0:
                raise PermissionError(
                    f"[AEGIS FIREWALL TOOL INTERCEPTION] Tool invocation '{tool_func.__name__}' blocked! "
                    f"Threat: {verdict.primary_attack.value if verdict.primary_attack else 'Exploit'} (Risk: {verdict.risk_score}%)"
                )
            return tool_func(*args, **kwargs)
        return wrapper
