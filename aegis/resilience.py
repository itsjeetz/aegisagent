"""Fault tolerance, per-layer timeouts, circuit breakers, and degraded mode (§8.3)."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import logging
import time
from typing import Any, Callable, Optional, TypeVar

from aegis.models import InputSource, Trust, Verdict
from aegis.policy.config import PolicyConfig, get_policy

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Maximum input limits (§8.3)
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_PDF_PAGES = 200
MAX_IMAGE_PIXELS = 20_000_000  # 20 MP
MAX_JSON_DEPTH = 20
MAX_DECODE_DEPTH = 3
MAX_VARIANTS = 12

# Per-layer timeout thresholds in seconds (§8.3)
TIMEOUTS = {
    "rules": 0.50,       # 500 ms
    "classifier": 1.0,   # 1 s
    "judge": 8.0,        # 8 s
    "ocr": 10.0,         # 10 s
}

_THREAD_POOL = ThreadPoolExecutor(max_workers=16, thread_name_prefix="aegis_resilience")


def run_with_timeout(
    func: Callable[..., T],
    args: tuple = (),
    kwargs: Optional[dict[str, Any]] = None,
    timeout_sec: float = 1.0,
    layer_name: str = "layer",
) -> tuple[Optional[T], bool, Optional[str]]:
    """Execute a callable with a strict timeout and catch-all exception handling.
    
    Returns (result, degraded_flag, error_message).
    """
    kwargs = kwargs or {}
    future = _THREAD_POOL.submit(func, *args, **kwargs)
    try:
        result = future.result(timeout=timeout_sec)
        return result, False, None
    except FuturesTimeoutError:
        msg = f"Layer '{layer_name}' timed out after {timeout_sec:.2f}s"
        logger.warning(msg)
        return None, True, msg
    except Exception as exc:
        msg = f"Layer '{layer_name}' raised {type(exc).__name__}: {exc}"
        logger.warning(msg)
        return None, True, msg


def validate_input_limits(content: bytes | str, filename: Optional[str] = None) -> None:
    """Validate content size against safety caps (§8.3). Raises ValueError if exceeded."""
    size_bytes = len(content.encode("utf-8")) if isinstance(content, str) else len(content)
    if size_bytes > MAX_UPLOAD_BYTES:
        raise ValueError(
            f"Content size {size_bytes} bytes exceeds maximum upload limit of {MAX_UPLOAD_BYTES} bytes (10 MB)."
        )


def check_json_depth(obj: Any, current_depth: int = 1) -> int:
    """Recursively check JSON structure depth (§8.3). Raises ValueError if > MAX_JSON_DEPTH."""
    if current_depth > MAX_JSON_DEPTH:
        raise ValueError(f"JSON nesting depth exceeds safety limit of {MAX_JSON_DEPTH}.")
    if isinstance(obj, dict):
        return max([check_json_depth(v, current_depth + 1) for v in obj.values()], default=current_depth)
    elif isinstance(obj, list):
        return max([check_json_depth(item, current_depth + 1) for item in obj], default=current_depth)
    return current_depth


def adjust_policy_for_degraded_mode(policy: PolicyConfig) -> PolicyConfig:
    """Apply degraded mode threshold tightening: allow_below - 0.10 (§8.3)."""
    # Create copy of policy with tightened allow_below
    cloned_data = policy.model_dump()
    base_allow = cloned_data.get("thresholds", {}).get("allow_below", 0.30)
    cloned_data["thresholds"]["allow_below"] = max(0.0, base_allow - 0.10)
    return PolicyConfig.model_validate(cloned_data)


def fail_closed_verdict(
    request_id: str,
    source: InputSource,
    trust: Trust,
    content_sha256: str,
    layer_status: dict[str, dict],
    error_msg: str,
) -> Verdict:
    """Construct a fail-closed verdict when rules layer itself fails (§8.3).
    
    Untrusted sources are BLOCKED; user messages are ESCALATED.
    """
    action = "BLOCK" if trust == Trust.UNTRUSTED else "ESCALATE"
    return Verdict(
        request_id=request_id,
        source=source,
        trust=trust,
        action=action,
        risk=1.0,
        category_scores={},
        findings=[],
        degraded=True,
        layer_status=layer_status,
        sanitized_text=None,
        envelope_text=None,
        timings_ms={"fail_closed": 0.0},
        content_sha256=content_sha256,
    )
