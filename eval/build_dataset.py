"""Dataset builder generating dev and frozen test splits with real fixture files (§9.2, §9.3)."""

import hashlib
import json
from pathlib import Path
from typing import Any
import yaml

from aegis.models import AttackType, InputSource
from eval.fixture_factory import make

FIXTURES_DIR = Path("data/fixtures")
DEV_PATH = Path("data/dev.jsonl")
TEST_PATH = Path("data/test.jsonl")
TEST_FREEZE_PATH = Path("data/test.frozen.sha256")
SEEDS_PATH = Path("eval/payloads/seeds.yaml")
BENIGN_SEEDS_PATH = Path("eval/benign/benign_seeds.yaml")

CARRIER_EXTENSIONS = {
    "user_message": ".txt",
    "web_page": ".html",
    "html": ".html",
    "pdf": ".pdf",
    "docx": ".docx",
    "email": ".eml",
    "markdown": ".md",
    "api_response": ".json",
    "source_code": ".py",
    "ocr_text": ".ocr",
    "image": ".png",
}

CARRIER_SOURCES = {
    "user_message": InputSource.USER_MESSAGE,
    "web_page": InputSource.WEB_PAGE,
    "html": InputSource.HTML,
    "pdf": InputSource.PDF,
    "docx": InputSource.DOCX,
    "email": InputSource.EMAIL,
    "markdown": InputSource.MARKDOWN,
    "api_response": InputSource.API_RESPONSE,
    "source_code": InputSource.SOURCE_CODE,
    "ocr_text": InputSource.OCR_TEXT,
    "image": InputSource.IMAGE,
}

CARRIER_TECHNIQUES = {
    "user_message": ["direct", "base64", "hex", "rot13", "leet", "spaced", "homoglyph", "zero_width"],
    "html": ["hidden_div", "comment", "offscreen", "tiny_font", "meta_tag", "alt_text"],
    "web_page": ["hidden_div", "comment", "offscreen", "tiny_font"],
    "pdf": ["visible_paragraph", "white_text", "tiny_text", "metadata", "annotation"],
    "docx": ["visible", "hidden_run", "comment", "white_text"],
    "email": ["header_field", "body_visible", "quoted_thread", "html_hidden", "attachment"],
    "markdown": ["comment", "link_title", "image_alt", "inline_html"],
    "api_response": ["nested_value", "key_name", "metadata_field"],
    "source_code": ["comment", "docstring", "string_literal"],
    "ocr_text": ["noisy_visible", "confusable_chars"],
    "image": ["visible_text", "faint_text", "small_text", "exif_comment"],
}


def _save_fixture(item_id: str, carrier: str, content: bytes | str) -> str:
    """Save fixture file to disk and return relative path."""
    ext = CARRIER_EXTENSIONS.get(carrier, ".txt")
    if carrier == "image" and isinstance(content, bytes) and content.startswith(b"\xff\xd8\xff"):
        ext = ".jpg"
    filename = f"{item_id}{ext}"
    target_path = FIXTURES_DIR / filename

    if isinstance(content, bytes):
        with open(target_path, "wb") as f:
            f.write(content)
    else:
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)

    return str(target_path.as_posix())


def build_dataset() -> tuple[int, int]:
    """Generate dev and test dataset splits with real carrier fixtures (§9.2)."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    with open(SEEDS_PATH, "r", encoding="utf-8") as f:
        attack_seeds = yaml.safe_load(f)

    with open(BENIGN_SEEDS_PATH, "r", encoding="utf-8") as f:
        benign_data = yaml.safe_load(f)

    carriers = list(CARRIER_SOURCES.keys())

    # Build Test Split
    test_items: list[dict[str, Any]] = []
    dev_items: list[dict[str, Any]] = []

    carrier_idx = 0

    # 1. Generate Attack Items for Test and Dev splits
    for cat_name, cat_dict in attack_seeds.items():
        attack_type_enum = AttackType(cat_name.upper())

        # Test payloads
        test_payloads = cat_dict.get("test", [])
        for p_idx, p_data in enumerate(test_payloads):
            item_id = f"test-atk-{cat_name[:4]}-{p_idx:02d}"

            # Handle multi-turn items
            turns = None
            if isinstance(p_data, dict) and "turn1" in p_data:
                turns = [
                    {"role": "user", "text": p_data["turn1"]},
                    {"role": "user", "text": p_data["turn2"]},
                ]
                raw_payload = p_data["turn2"]
                carrier = "user_message"
                source_enum = InputSource.USER_MESSAGE
                technique = "multi_turn_split"
            else:
                raw_payload = str(p_data)
                carrier = carriers[carrier_idx % len(carriers)]
                carrier_idx += 1
                source_enum = CARRIER_SOURCES[carrier]
                techniques = CARRIER_TECHNIQUES[carrier]
                technique = techniques[p_idx % len(techniques)]

            fixture_content = make(raw_payload, carrier, technique)
            content_path = _save_fixture(item_id, carrier, fixture_content)

            # Attack types includes INDIRECT_PROMPT_INJECTION if untrusted
            cat_list = [attack_type_enum.value]
            if source_enum != InputSource.USER_MESSAGE and AttackType.INDIRECT_PROMPT_INJECTION.value not in cat_list:
                cat_list.append(AttackType.INDIRECT_PROMPT_INJECTION.value)

            item = {
                "id": item_id,
                "split": "test",
                "source": source_enum.value,
                "carrier": carrier,
                "technique": technique,
                "is_attack": True,
                "attack_types": cat_list,
                "content_path": content_path,
                "origin": "llm_generated",
                "turns": turns,
                "notes": f"Test attack payload for {cat_name}",
            }
            test_items.append(item)

        # Dev payloads (expanded to 2x-3x test size)
        dev_payloads = cat_dict.get("dev", []) + cat_dict.get("test", [])[:8]
        for p_idx, p_data in enumerate(dev_payloads):
            for mult in (1, 2):
                item_id = f"dev-atk-{cat_name[:4]}-{p_idx:02d}-{mult}"

                turns = None
                if isinstance(p_data, dict) and "turn1" in p_data:
                    turns = [
                        {"role": "user", "text": p_data["turn1"]},
                        {"role": "user", "text": p_data["turn2"]},
                    ]
                    raw_payload = p_data["turn2"]
                    carrier = "user_message"
                    source_enum = InputSource.USER_MESSAGE
                    technique = "multi_turn_split"
                else:
                    raw_payload = str(p_data)
                    carrier = carriers[(carrier_idx + mult) % len(carriers)]
                    source_enum = CARRIER_SOURCES[carrier]
                    techniques = CARRIER_TECHNIQUES[carrier]
                    technique = techniques[(p_idx + mult) % len(techniques)]

                fixture_content = make(raw_payload, carrier, technique)
                content_path = _save_fixture(item_id, carrier, fixture_content)

                cat_list = [attack_type_enum.value]
                if source_enum != InputSource.USER_MESSAGE and AttackType.INDIRECT_PROMPT_INJECTION.value not in cat_list:
                    cat_list.append(AttackType.INDIRECT_PROMPT_INJECTION.value)

                item = {
                    "id": item_id,
                    "split": "dev",
                    "source": source_enum.value,
                    "carrier": carrier,
                    "technique": technique,
                    "is_attack": True,
                    "attack_types": cat_list,
                    "content_path": content_path,
                    "origin": "dev_seed",
                    "turns": turns,
                    "notes": f"Dev attack payload for {cat_name}",
                }
                dev_items.append(item)

    def _make_benign_content(carrier: str, text: str) -> bytes | str:
        """Wrap text in a valid container if the format is binary (pdf, docx, image)."""
        if carrier == "pdf":
            return make(text, "pdf", "visible_paragraph")
        elif carrier == "docx":
            return make(text, "docx", "visible")
        elif carrier in ("image", "png", "jpeg", "jpg"):
            return make(text, "image", "visible_text")
        return text

    # 2. Generate Benign Items (Ordinary + Hard Negatives >= 30%)
    hard_negs = benign_data.get("hard_negatives", [])
    ord_benign = benign_data.get("benign_ordinary", {})

    # Add hard negatives to test (all of them) and dev
    for hn_idx, hn in enumerate(hard_negs):
        item_id = f"test-benign-hn-{hn_idx:02d}"
        src_name = hn.get("source", "user_message")
        fixture_content = _make_benign_content(src_name, hn["text"])
        content_path = _save_fixture(item_id, src_name, fixture_content)
        test_items.append({
            "id": item_id,
            "split": "test",
            "source": CARRIER_SOURCES.get(src_name, InputSource.USER_MESSAGE).value,
            "carrier": src_name,
            "technique": "hard_negative",
            "is_attack": False,
            "attack_types": [],
            "content_path": content_path,
            "origin": "hard_negative",
            "turns": None,
            "notes": hn.get("reason", "Hard negative benign item"),
        })

        # Also add to dev
        dev_id = f"dev-benign-hn-{hn_idx:02d}"
        dev_path = _save_fixture(dev_id, src_name, fixture_content)
        dev_items.append({
            "id": dev_id,
            "split": "dev",
            "source": CARRIER_SOURCES.get(src_name, InputSource.USER_MESSAGE).value,
            "carrier": src_name,
            "technique": "hard_negative",
            "is_attack": False,
            "attack_types": [],
            "content_path": dev_path,
            "origin": "hard_negative",
            "turns": None,
            "notes": hn.get("reason", "Hard negative benign item"),
        })

    # Add ordinary benign items across all sources
    b_counter = 0
    for src_name, samples in ord_benign.items():
        for s_idx, sample_text in enumerate(samples):
            # Test item
            b_counter += 1
            t_id = f"test-benign-ord-{b_counter:03d}"
            fixture_content = _make_benign_content(src_name, sample_text)
            t_path = _save_fixture(t_id, src_name, fixture_content)
            test_items.append({
                "id": t_id,
                "split": "test",
                "source": CARRIER_SOURCES.get(src_name, InputSource.USER_MESSAGE).value,
                "carrier": src_name,
                "technique": "ordinary",
                "is_attack": False,
                "attack_types": [],
                "content_path": t_path,
                "origin": "human_curated",
                "turns": None,
                "notes": "Ordinary benign document",
            })

            # Dev items (replicated to maintain 2x ratio)
            for d_rep in (1, 2):
                d_id = f"dev-benign-ord-{b_counter:03d}-{d_rep}"
                d_path = _save_fixture(d_id, src_name, fixture_content)
                dev_items.append({
                    "id": d_id,
                    "split": "dev",
                    "source": CARRIER_SOURCES.get(src_name, InputSource.USER_MESSAGE).value,
                    "carrier": src_name,
                    "technique": "ordinary",
                    "is_attack": False,
                    "attack_types": [],
                    "content_path": d_path,
                    "origin": "human_curated",
                    "turns": None,
                    "notes": "Ordinary benign document",
                })

    # Write data/dev.jsonl
    with open(DEV_PATH, "w", encoding="utf-8") as f:
        for item in dev_items:
            f.write(json.dumps(item) + "\n")

    # Write data/test.jsonl
    test_lines = [json.dumps(item) + "\n" for item in test_items]
    with open(TEST_PATH, "w", encoding="utf-8") as f:
        f.writelines(test_lines)

    # 3. Freeze Protocol (§9.3): Compute SHA-256 and write data/test.frozen.sha256
    with open(TEST_PATH, "rb") as f:
        test_sha256 = hashlib.sha256(f.read()).hexdigest()

    with open(TEST_FREEZE_PATH, "w", encoding="utf-8") as f:
        f.write(f"{test_sha256}  data/test.jsonl\n")

    print(f"Dataset successfully built:")
    print(f"  Dev split:  {len(dev_items)} items -> {DEV_PATH}")
    print(f"  Test split: {len(test_items)} items -> {TEST_PATH}")
    print(f"  Test SHA-256 frozen: {test_sha256} -> {TEST_FREEZE_PATH}")

    return len(dev_items), len(test_items)


if __name__ == "__main__":
    build_dataset()
