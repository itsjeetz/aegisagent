"""Ingestion adapter for API responses (JSON and XML) (§5.1)."""

import json
from typing import Any, TYPE_CHECKING
import xml.etree.ElementTree as std_ET
import defusedxml.ElementTree as defused_ET

from aegis.ingestion.base import (
    BaseAdapter,
    OversizeContentError,
    IngestionError,
)
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class ApiResponseAdapter(BaseAdapter):
    """Adapter for API_RESPONSE source supporting JSON and XML."""

    source = InputSource.API_RESPONSE

    def _walk_json(
        self,
        node: Any,
        path: str,
        depth: int,
        max_depth: int,
        segments: list[Segment],
        seg_idx: list[int],
    ):
        """Recursively walk JSON object up to max_depth."""
        if depth > max_depth:
            raise OversizeContentError(
                f"JSON nesting depth exceeds maximum allowed limit of {max_depth}"
            )

        if isinstance(node, dict):
            for k, v in node.items():
                key_path = f"{path}.{k}" if path != "$" else f"$.{k}"
                # Extract key as segment
                segments.append(
                    Segment(
                        id=f"seg-api-{seg_idx[0]}",
                        text=str(k),
                        origin="json_key",
                        location=key_path,
                        hidden_reason=None,
                    )
                )
                seg_idx[0] += 1
                # Recurse into value
                self._walk_json(v, key_path, depth + 1, max_depth, segments, seg_idx)

        elif isinstance(node, list):
            for i, item in enumerate(node):
                item_path = f"{path}[{i}]"
                self._walk_json(item_path_item := item, item_path, depth + 1, max_depth, segments, seg_idx)

        elif isinstance(node, str):
            if node.strip():
                segments.append(
                    Segment(
                        id=f"seg-api-{seg_idx[0]}",
                        text=node.strip(),
                        origin="json_value",
                        location=path,
                        hidden_reason=None,
                    )
                )
                seg_idx[0] += 1

        elif node is not None and not isinstance(node, (bool, int, float)):
            val_str = str(node).strip()
            if val_str:
                segments.append(
                    Segment(
                        id=f"seg-api-{seg_idx[0]}",
                        text=val_str,
                        origin="json_value",
                        location=path,
                        hidden_reason=None,
                    )
                )
                seg_idx[0] += 1

    def _walk_xml(
        self,
        elem: std_ET.Element,
        path: str,
        depth: int,
        max_depth: int,
        segments: list[Segment],
        seg_idx: list[int],
    ):
        """Recursively walk XML element up to max_depth."""
        if depth > max_depth:
            raise OversizeContentError(
                f"XML nesting depth exceeds maximum allowed limit of {max_depth}"
            )

        # Attributes
        for attr_k, attr_v in elem.attrib.items():
            attr_path = f"{path}/@{attr_k}"
            segments.append(
                Segment(
                    id=f"seg-api-{seg_idx[0]}",
                    text=attr_v.strip(),
                    origin="json_value",
                    location=attr_path,
                    hidden_reason=None,
                )
            )
            seg_idx[0] += 1

        # Text content
        if elem.text and elem.text.strip():
            segments.append(
                Segment(
                    id=f"seg-api-{seg_idx[0]}",
                    text=elem.text.strip(),
                    origin="json_value",
                    location=path,
                    hidden_reason=None,
                )
            )
            seg_idx[0] += 1

        # Children
        for i, child in enumerate(elem):
            child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            child_path = f"{path}/{child_tag}[{i}]"
            self._walk_xml(child, child_path, depth + 1, max_depth, segments, seg_idx)

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
                    f"API response size exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            text = data.decode("utf-8", errors="replace")
        else:
            if len(data.encode("utf-8")) > pol.limits.max_upload_bytes:
                raise OversizeContentError(
                    f"API response size exceeds limit of {pol.limits.max_upload_bytes} bytes"
                )
            text = data

        text_stripped = text.strip()
        segments: list[Segment] = []
        seg_idx = [0]

        # Check if XML
        if text_stripped.startswith("<"):
            try:
                root = defused_ET.fromstring(text_stripped)
                root_tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag
                self._walk_xml(root, f"/{root_tag}", 0, pol.limits.max_json_depth, segments, seg_idx)
                return segments
            except Exception:
                # If XML parsing fails, fall through to JSON
                pass

        # Parse JSON
        try:
            parsed = json.loads(text_stripped)
            self._walk_json(parsed, "$", 0, pol.limits.max_json_depth, segments, seg_idx)
        except json.JSONDecodeError as e:
            raise IngestionError(f"Failed to parse API response as JSON or XML: {e}") from e

        if not segments:
            segments.append(
                Segment(
                    id="seg-api-0",
                    text="",
                    origin="json_value",
                    location="$",
                    hidden_reason=None,
                )
            )

        return segments
