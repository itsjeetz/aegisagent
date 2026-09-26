"""Dataset loading, models, and freeze verification (§9.2, §9.3)."""

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Optional


@dataclass
class DatasetItem:
    """Benchmark evaluation dataset item (§9.2)."""
    id: str
    split: str
    source: str
    carrier: str
    technique: str
    is_attack: bool
    attack_types: list[str] = field(default_factory=list)
    content_path: str = ""
    origin: str = "curated"
    turns: Optional[list[dict[str, str]]] = None
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DatasetItem":
        return cls(
            id=data["id"],
            split=data["split"],
            source=data["source"],
            carrier=data.get("carrier", data["source"]),
            technique=data.get("technique", "direct"),
            is_attack=data.get("is_attack", False),
            attack_types=data.get("attack_types", []),
            content_path=data.get("content_path", ""),
            origin=data.get("origin", "curated"),
            turns=data.get("turns"),
            notes=data.get("notes", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "split": self.split,
            "source": self.source,
            "carrier": self.carrier,
            "technique": self.technique,
            "is_attack": self.is_attack,
            "attack_types": self.attack_types,
            "content_path": self.content_path,
            "origin": self.origin,
            "turns": self.turns,
            "notes": self.notes,
        }


def load_dataset(split: str = "dev", path: Optional[Path | str] = None) -> list[DatasetItem]:
    """Load dataset items for given split ('dev' or 'test')."""
    if path is None:
        path = Path(f"data/{split}.jsonl")
    else:
        path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Dataset split file not found: {path}. Run python -m eval.build_dataset first.")

    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                items.append(DatasetItem.from_dict(data))
            except Exception as e:
                raise ValueError(f"Failed to parse line {line_no} in {path}: {e}")

    return items


def verify_test_freeze(
    test_path: Path | str = "data/test.jsonl",
    freeze_path: Path | str = "data/test.frozen.sha256",
) -> tuple[bool, str, str]:
    """Verify test split against frozen SHA-256 hash (§9.3).
    
    Returns (matches, computed_hash, recorded_hash).
    """
    t_path = Path(test_path)
    f_path = Path(freeze_path)

    if not t_path.exists():
        raise FileNotFoundError(f"Test split file not found: {t_path}")
    if not f_path.exists():
        raise FileNotFoundError(f"Test freeze file not found: {f_path}")

    with open(t_path, "rb") as f:
        computed = hashlib.sha256(f.read()).hexdigest()

    with open(f_path, "r", encoding="utf-8") as f:
        first_line = f.readline().strip()
        recorded = first_line.split()[0] if first_line else ""

    return (computed.lower() == recorded.lower(), computed, recorded)
