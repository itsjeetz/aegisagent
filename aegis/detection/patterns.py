"""ReDoS-safe regex pattern families for rule-based prompt injection detection (§5.3)."""

from dataclasses import dataclass
import re
from aegis.models import AttackType


@dataclass(frozen=True)
class RulePattern:
    """A weighted regex detection pattern."""

    id: str
    attack_type: AttackType
    regex: re.Pattern
    weight: float
    description: str


# 1. INSTRUCTION_OVERRIDE patterns
OVERRIDE_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="ovr_ignore_prev",
        attack_type=AttackType.INSTRUCTION_OVERRIDE,
        regex=re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass|discard|cancel)\s+"
            r"(?:all\s+)?(?:previous|prior|above|earlier|all|original|current)\s+"
            r"(?:instructions|rules|prompt|guidelines|context|constraints|system\s+message)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Ignore/override previous instructions directive",
    ),
    RulePattern(
        id="ovr_new_instructions",
        attack_type=AttackType.INSTRUCTION_OVERRIDE,
        regex=re.compile(
            r"\b(?:new\s+(?:instructions?|rules?|directives?)|here\s+are\s+your\s+real\s+instructions?)\s*:",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Declaration of new instructions/rules",
    ),
    RulePattern(
        id="ovr_delimiter_hijack",
        attack_type=AttackType.INSTRUCTION_OVERRIDE,
        regex=re.compile(
            r"(?:<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|###\s*System:?</system>|<system>|\[SYSTEM\s+PROMPT\]|\bHuman:\s*|\bAssistant:\s*|\bend\s+of\s+prompt\b)",
            re.IGNORECASE,
        ),
        weight=0.90,
        description="Prompt delimiter injection or hijack token",
    ),
    RulePattern(
        id="ovr_from_now_on",
        attack_type=AttackType.INSTRUCTION_OVERRIDE,
        regex=re.compile(
            r"\bfrom\s+now\s+on\s+you\s+(?:will|must|shall|should|are|have\s+to)\b",
            re.IGNORECASE,
        ),
        weight=0.80,
        description="'From now on you must/will' imperative override",
    ),
]

# 2. ROLE_CHANGE patterns
ROLE_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="role_act_as",
        attack_type=AttackType.ROLE_CHANGE,
        regex=re.compile(
            r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|simulate\s+being|play\s+the\s+role\s+of)\s+"
            r"(?:an?\s+)?(?:unfiltered|unrestricted|evil|jailbroken|DAN|anti-?ai|hacker|root|admin)",
            re.IGNORECASE,
        ),
        weight=0.90,
        description="Adoption of malicious, unrestricted, or evil persona",
    ),
    RulePattern(
        id="role_dan_devmode",
        attack_type=AttackType.ROLE_CHANGE,
        regex=re.compile(
            r"\b(?:DAN\s+mode|developer\s+mode\s+(?:enabled|activated)|jailbroken\s+mode|god\s+mode|unfiltered\s+mode)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Jailbreak persona toggle (DAN, developer mode)",
    ),
    RulePattern(
        id="role_no_restrictions",
        attack_type=AttackType.ROLE_CHANGE,
        regex=re.compile(
            r"\b(?:without\s+(?:any\s+)?restrictions?|no\s+(?:rules|filters|guidelines|safety)|disregard\s+content\s+policy)\b",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Explicit removal of safety filters or restrictions",
    ),
]

# 3. SECRET_EXTRACTION patterns
SECRET_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="sec_reveal_system",
        attack_type=AttackType.SECRET_EXTRACTION,
        regex=re.compile(
            r"\b(?:print|reveal|show|repeat|output|leak|display|echo|tell\s+me|give\s+me|dump|share)\s+"
            r"(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|hidden\s+instructions?|developer\s+prompt|guardrails|canary)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Direct request to reveal system prompt or internal instructions",
    ),
    RulePattern(
        id="sec_what_told",
        attack_type=AttackType.SECRET_EXTRACTION,
        regex=re.compile(
            r"\b(?:what\s+were\s+you\s+told\s+(?:at\s+the\s+beginning|initially|in\s+your\s+prompt)|what\s+is\s+your\s+system\s+prompt)\b",
            re.IGNORECASE,
        ),
        weight=0.90,
        description="Querying initial prompt content",
    ),
    RulePattern(
        id="sec_api_keys",
        attack_type=AttackType.SECRET_EXTRACTION,
        regex=re.compile(
            r"\b(?:print|reveal|give\s+me|what\s+is|leak)\s+(?:your\s+)?(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|api_key|api\s+key|access\s+token|secret\s+key|env\s+vars?|environment\s+variables?)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Request for API keys, secret credentials, or environment variables",
    ),
    RulePattern(
        id="sec_verbatim_leak",
        attack_type=AttackType.SECRET_EXTRACTION,
        regex=re.compile(
            r"\b(?:output|repeat)\s+(?:everything\s+)?verbatim\s+(?:from\s+the\s+beginning|above)\b",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Request for verbatim output of prior instructions",
    ),
]

# 4. TOOL_ABUSE patterns
TOOL_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="tool_email_exfil",
        attack_type=AttackType.TOOL_ABUSE,
        regex=re.compile(
            r"\b(?:forward|send_email|send\s+an?\s+email)\b[^;\n.]{0,60}?\bto\s+[a-zA-Z0-9_.+-]+@(?!company\.local)[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Direct instruction to send or forward data/email to an external recipient",
    ),
    RulePattern(
        id="tool_shell_pipe",
        attack_type=AttackType.TOOL_ABUSE,
        regex=re.compile(
            r"\b(?:curl|wget)\s+[^|\n;]+\|\s*(?:ba)?sh\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Shell execution pipe via curl/wget to shell",
    ),
    RulePattern(
        id="tool_destructive_cmd",
        attack_type=AttackType.TOOL_ABUSE,
        regex=re.compile(
            r"\b(?:rm\s+-rf\s+[/~]|DROP\s+TABLE\s+\w+|TRUNCATE\s+TABLE\s+\w+|DELETE\s+FROM\s+\w+\s*;|format\s+[a-z]:)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Destructive filesystem or database commands",
    ),
    RulePattern(
        id="tool_invoke_directive",
        attack_type=AttackType.TOOL_ABUSE,
        regex=re.compile(
            r"\b(?:run_bash|run_command|run_sql|execute_query|transfer_funds|make_payment)\s*\(",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Direct invocation syntax of restricted agent tools",
    ),
]

# 5. CREDENTIAL_THEFT patterns
CREDENTIAL_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="cred_reenter_password",
        attack_type=AttackType.CREDENTIAL_THEFT,
        regex=re.compile(
            r"\b(?:session\s+(?:has\s+)?expired|security\s+alert|identity\s+verification\s+required)\s*[,.:\-]\s*"
            r"(?:re-?enter|submit|provide|verify)\s+(?:your\s+)?(?:password|credentials|login|token|OTP)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Fake session expiration or identity re-verification challenge",
    ),
    RulePattern(
        id="cred_send_password",
        attack_type=AttackType.CREDENTIAL_THEFT,
        regex=re.compile(
            r"\b(?:send|submit|message|email|enter)\s+(?:your\s+)?(?:password|API\s+key|private\s+key|recovery\s+phrase|seed\s+phrase|pin)\s+(?:to|at)\b",
            re.IGNORECASE,
        ),
        weight=0.90,
        description="Solicitation of user passwords, private keys, or PINs",
    ),
]

# 6. CONTEXT_POISONING patterns
POISONING_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="pois_persistence",
        attack_type=AttackType.CONTEXT_POISONING,
        regex=re.compile(
            r"\b(?:remember\s+that\s+for\s+all\s+future|from\s+now\s+on\s+always\s+remember|permanently\s+record\s+in\s+memory|add\s+to\s+your\s+(?:long-?term\s+)?(?:memory|notes))\b",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Instructions attempting persistent memory or agent state poisoning",
    ),
    RulePattern(
        id="pois_authority_spoof",
        attack_type=AttackType.CONTEXT_POISONING,
        regex=re.compile(
            r"\b(?:official\s+(?:CFO|CEO|admin|IT|executive)\s+(?:memo|directive|order)|admin\s+has\s+authorized|treat\s+this\s+(?:file|document|text)\s+as\s+trusted\s+(?:source|authority))\b",
            re.IGNORECASE,
        ),
        weight=0.80,
        description="Spoofed administrative or executive authority directive",
    ),
    RulePattern(
        id="pois_rule_relaxation",
        attack_type=AttackType.CONTEXT_POISONING,
        regex=re.compile(
            r"\b(?:security\s+policy\s+(?:has\s+been\s+)?updated|restrictions\s+are\s+temporarily\s+suspended|prompt\s+injection\s+firewall\s+is\s+disabled)\b",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Claims of security policy relaxation or firewall suspension",
    ),
]

ALL_RULE_PATTERNS: list[RulePattern] = (
    OVERRIDE_PATTERNS
    + ROLE_PATTERNS
    + SECRET_PATTERNS
    + TOOL_PATTERNS
    + CREDENTIAL_PATTERNS
    + POISONING_PATTERNS
)
