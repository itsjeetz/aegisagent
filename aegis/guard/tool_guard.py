"""Tool execution firewall enforcing tiers, taint rules, and argument validation (§6 G1)."""

from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
import re
from typing import Any, Callable, Literal, Optional

from aegis.models import Finding

GuardAction = Literal["ALLOW", "CONFIRM", "DENY"]


class ToolTier(str, Enum):
    """Tool risk classification tiers (§6 G1)."""
    READ_PUBLIC = "READ_PUBLIC"
    READ_SENSITIVE = "READ_SENSITIVE"
    WRITE_LOCAL = "WRITE_LOCAL"
    EGRESS = "EGRESS"
    EXEC_DESTRUCTIVE = "EXEC_DESTRUCTIVE"


@dataclass
class GuardContext:
    """Session guard context tracking taint and authorization state (§6)."""
    session_id: str
    tainted: bool = False
    flagged_findings: list[Finding] = field(default_factory=list)
    user_confirmed_calls: set[str] = field(default_factory=set)
    canary_token: str = ""


@dataclass
class ToolGuardResult:
    """Verdict returned by ToolGuard before tool execution."""
    action: GuardAction
    tool: str
    tier: ToolTier
    reason: str
    tainted: bool = False


# Default domain allow-list for egress
ALLOWED_EMAIL_DOMAINS = {"company.internal", "partner.org", "internal.corp"}
ALLOWED_SQL_TABLES = {"users", "products", "orders", "audit_log", "inventory"}


class ToolGuard:
    """Runtime tool firewall implementing least privilege and taint-aware policy (§6 G1)."""

    def __init__(
        self,
        allowed_email_domains: Optional[set[str]] = None,
        allowed_sql_tables: Optional[set[str]] = None,
    ):
        self.allowed_email_domains = allowed_email_domains or ALLOWED_EMAIL_DOMAINS
        self.allowed_sql_tables = allowed_sql_tables or ALLOWED_SQL_TABLES

    def classify_tool_tier(self, tool: str, args: dict[str, Any]) -> ToolTier:
        """Map tool and arguments to its operational risk tier (§6 G1)."""
        tool_lower = tool.lower().strip()

        if tool_lower == "fetch_url":
            return ToolTier.READ_PUBLIC
        elif tool_lower == "read_email":
            return ToolTier.READ_PUBLIC
        elif tool_lower == "read_file":
            path = str(args.get("path", "")).lower()
            if "confidential" in path or "secret" in path:
                return ToolTier.READ_SENSITIVE
            return ToolTier.READ_PUBLIC
        elif tool_lower in ("write_file", "write_note"):
            return ToolTier.WRITE_LOCAL
        elif tool_lower in ("send_email", "http_post", "webhook_post"):
            return ToolTier.EGRESS
        elif tool_lower in ("run_bash", "exec", "transfer_funds"):
            return ToolTier.EXEC_DESTRUCTIVE
        elif tool_lower == "run_sql":
            query = str(args.get("query", "")).strip().upper()
            if query.startswith("SELECT"):
                return ToolTier.READ_PUBLIC
            return ToolTier.EXEC_DESTRUCTIVE

        return ToolTier.EXEC_DESTRUCTIVE  # Default to highest risk for unknown tools

    def check(self, tool: str, args: dict[str, Any], ctx: GuardContext) -> ToolGuardResult:
        """Validate tool execution against taint rules and argument security policies (§6 G1)."""
        tier = self.classify_tool_tier(tool, args)
        tool_call_sig = f"{tool}:{json.dumps(args, sort_keys=True)}"

        # 1. Canary Token Leakage in Arguments (Always Deny)
        if ctx.canary_token:
            for k, val in args.items():
                if isinstance(val, str) and ctx.canary_token in val:
                    return ToolGuardResult(
                        action="DENY",
                        tool=tool,
                        tier=tier,
                        reason=f"Canary token leaked in argument '{k}'",
                        tainted=ctx.tainted,
                    )

        # 2. Argument Validation Policies (Always Enforced)
        # 2a. Email Egress Validation
        if tool == "send_email":
            to_addr = str(args.get("to", "")).strip().lower()
            domain = to_addr.split("@")[-1] if "@" in to_addr else ""
            if not domain or domain not in self.allowed_email_domains:
                return ToolGuardResult(
                    action="DENY",
                    tool=tool,
                    tier=tier,
                    reason=f"Email recipient domain '{domain}' is not on the allow-list",
                    tainted=ctx.tainted,
                )

        # 2b. SQL Safety Validation
        elif tool == "run_sql":
            query = str(args.get("query", "")).strip()
            # Must strictly be a SELECT query
            if re.search(r"\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE)\b", query, re.IGNORECASE):
                return ToolGuardResult(
                    action="DENY",
                    tool=tool,
                    tier=tier,
                    reason="Destructive SQL statements (DROP, DELETE, UPDATE, INSERT, ALTER) prohibited",
                    tainted=ctx.tainted,
                )

        # 2c. Shell Command Safety Validation
        elif tool == "run_bash":
            cmd = str(args.get("command", "")).strip()
            deny_patterns = [
                r"\|\s*(?:ba)?sh",
                r"rm\s+-rf",
                r"curl\s+",
                r"wget\s+",
                r"format\s+[a-z]:",
                r"cat\s+/etc/passwd",
                r"\b(?:nc|netcat)\b",
            ]
            for pat in deny_patterns:
                if re.search(pat, cmd, re.IGNORECASE):
                    return ToolGuardResult(
                        action="DENY",
                        tool=tool,
                        tier=tier,
                        reason=f"Prohibited shell pattern matched in command: {cmd[:60]}",
                        tainted=ctx.tainted,
                    )

        # 2d. File Path Traversal Validation
        elif tool in ("read_file", "write_file"):
            path_str = str(args.get("path", "")).strip()
            if ".." in path_str or path_str.startswith("/") or path_str.startswith("\\"):
                return ToolGuardResult(
                    action="DENY",
                    tool=tool,
                    tier=tier,
                    reason="Path traversal prohibited; paths must be relative within demo_data",
                    tainted=ctx.tainted,
                )

        # 3. Taint Rules (§6 G1)
        if ctx.tainted:
            # EGRESS and EXEC_DESTRUCTIVE are strictly denied when tainted unless confirmed
            if tier in (ToolTier.EGRESS, ToolTier.EXEC_DESTRUCTIVE):
                if tool_call_sig not in ctx.user_confirmed_calls:
                    return ToolGuardResult(
                        action="DENY",
                        tool=tool,
                        tier=tier,
                        reason="Tainted context prohibits egress or destructive tool execution without user confirmation",
                        tainted=True,
                    )

            # READ_SENSITIVE requires confirmation, or denied if flagged findings exist
            elif tier == ToolTier.READ_SENSITIVE:
                if ctx.flagged_findings:
                    return ToolGuardResult(
                        action="DENY",
                        tool=tool,
                        tier=tier,
                        reason="Sensitive data read denied due to active attack findings in context",
                        tainted=True,
                    )
                if tool_call_sig not in ctx.user_confirmed_calls:
                    return ToolGuardResult(
                        action="CONFIRM",
                        tool=tool,
                        tier=tier,
                        reason="Sensitive data access in tainted context requires user confirmation",
                        tainted=True,
                    )

        # 4. Untainted Default Action by Tier
        if tier == ToolTier.EXEC_DESTRUCTIVE:
            if tool_call_sig not in ctx.user_confirmed_calls:
                return ToolGuardResult(
                    action="CONFIRM",
                    tool=tool,
                    tier=tier,
                    reason="Destructive actions require confirmation",
                    tainted=False,
                )

        return ToolGuardResult(
            action="ALLOW",
            tool=tool,
            tier=tier,
            reason="Tool call permitted by guard policy",
            tainted=ctx.tainted,
        )


_TOOL_GUARD = None


def get_tool_guard() -> ToolGuard:
    global _TOOL_GUARD
    if _TOOL_GUARD is None:
        _TOOL_GUARD = ToolGuard()
    return _TOOL_GUARD

