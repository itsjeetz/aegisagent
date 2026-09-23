"""Ingestion adapter for direct user messages (§5.1)."""

from typing import TYPE_CHECKING
from aegis.ingestion.base import BaseAdapter, OversizeContentError
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class UserMessageAdapter(BaseAdapter):
    """Adapter for USER_MESSAGE source."""

    source = InputSource.USER_MESSAGE

    def extract(
        self,
        data: bytes | str,
        *,
        filename: str | None = None,
        policy: "PolicyConfig | None" = None,
    ) -> list[Segment]:
        pol = policy or get_policy()
        if isinstance(data, bytes):
            if len(data) > pol.limits.max_upload_bytes:
                raise OversizeContentError(
                    f"Message size {len(data)} exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            text = data.decode("utf-8", errors="replace")
        else:
            if len(data.encode("utf-8")) > pol.limits.max_upload_bytes:
                raise OversizeContentError(
                    f"Message size exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            text = data

        return [
            Segment(
                id="seg-user-0",
                text=text,
                origin="visible",
                location="user_message",
                hidden_reason=None,
            )
        ]
