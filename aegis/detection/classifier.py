"""ML prompt injection classifier using TF-IDF and Logistic Regression (§5.3b)."""

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Optional
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from aegis.detection.base import DetectionContext
from aegis.models import AttackType, Finding, InputSource, Segment, Trust
from aegis.normalize.mapped_text import MappedText
from aegis.policy.config import PolicyConfig, get_policy

DEFAULT_MODEL_PATH = Path("data/models/classifier.joblib")


class MLClassifier:
    """TF-IDF character n-gram + Logistic Regression injection classifier (§5.3b)."""

    def __init__(
        self,
        model_path: Path | str = DEFAULT_MODEL_PATH,
        policy: Optional[PolicyConfig] = None,
    ):
        self.model_path = Path(model_path)
        self.policy = policy or get_policy()
        self.pipeline: Optional[Pipeline] = None
        self._load_or_init()

    def _load_or_init(self) -> None:
        """Load trained model if exists; otherwise remain uninitialized until train() is called."""
        if self.model_path.exists():
            try:
                self.pipeline = joblib.load(self.model_path)
            except Exception:
                self.pipeline = None
        else:
            self.pipeline = None

    @property
    def is_trained(self) -> bool:
        return self.pipeline is not None

    def train(self, texts: list[str], labels: list[int]) -> None:
        """Train pipeline on texts and binary labels (1=attack, 0=benign)."""
        if not texts or len(set(labels)) < 2:
            raise ValueError("Training requires at least two classes (benign and attack).")

        vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            min_df=1,
            max_df=0.98,
            sublinear_tf=True,
        )
        classifier = LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            C=1.0,
            random_state=42,
        )

        self.pipeline = Pipeline([
            ("tfidf", vectorizer),
            ("clf", classifier),
        ])

        self.pipeline.fit(texts, labels)

        # Save to model_path
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, self.model_path)

    def predict_proba(self, texts: list[str]) -> list[float]:
        """Return probability P(injection) for each text."""
        if not self.is_trained or not texts:
            return [0.0] * len(texts)

        try:
            probs = self.pipeline.predict_proba(texts)
            # Probability of positive class (label 1)
            return [float(p[1]) for p in probs]
        except Exception:
            return [0.0] * len(texts)

    def predict_windowed(
        self,
        text: str,
        window_size: int = 400,
        stride: int = 200,
    ) -> tuple[float, Optional[tuple[int, int]]]:
        """Perform sliding window inference over text.
        
        Returns (max_probability, (start, end) span in text).
        """
        if not self.is_trained or not text.strip():
            return 0.0, None

        n = len(text)
        if n <= window_size:
            probs = self.predict_proba([text])
            p = round(probs[0], 4)
            return p, (0, n)

        windows: list[tuple[int, int, str]] = []
        for start in range(0, n, stride):
            end = min(start + window_size, n)
            chunk = text[start:end]
            if chunk.strip():
                windows.append((start, end, chunk))
            if end >= n:
                break

        if not windows:
            return 0.0, None

        chunk_texts = [w[2] for w in windows]
        probs = self.predict_proba(chunk_texts)

        max_idx = int(np.argmax(probs))
        max_prob = round(float(probs[max_idx]), 4)
        best_span = (windows[max_idx][0], windows[max_idx][1])

        return max_prob, best_span

    def detect(
        self,
        segment: Segment,
        variants: list[tuple[MappedText, list[str]]],
        ctx: DetectionContext,
        rule_categories: Optional[set[AttackType]] = None,
    ) -> list[Finding]:
        """Run ML classifier over segment variants (§5.3b)."""
        if not self.is_trained:
            return []

        threshold = 0.50
        findings: list[Finding] = []
        seen_spans = set()

        for v_mapped, v_chain in variants:
            text = v_mapped.text
            if not text.strip():
                continue

            prob, win_span = self.predict_windowed(text)
            if prob >= threshold and win_span:
                orig_span = v_mapped.to_original(win_span[0], win_span[1])
                span_key = (orig_span[0], orig_span[1])

                if span_key not in seen_spans:
                    seen_spans.add(span_key)
                    evidence = text[win_span[0]:win_span[1]][:120]

                    # §5.3b: Contributes a score to categories via the rules' labels,
                    # or to INDIRECT_PROMPT_INJECTION on untrusted sources.
                    if rule_categories is not None:
                        if rule_categories:
                            for cat in rule_categories:
                                findings.append(
                                    Finding(
                                        attack_type=cat,
                                        score=prob,
                                        segment_id=segment.id,
                                        span_original=orig_span,
                                        evidence=evidence,
                                        detector="ml_classifier",
                                        layer="classifier",
                                        variant_chain=v_chain,
                                    )
                                )
                        elif ctx.trust == Trust.UNTRUSTED or ctx.source != InputSource.USER_MESSAGE:
                            findings.append(
                                Finding(
                                    attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
                                    score=prob,
                                    segment_id=segment.id,
                                    span_original=orig_span,
                                    evidence=evidence,
                                    detector="ml_classifier",
                                    layer="classifier",
                                    variant_chain=v_chain,
                                )
                            )
                        elif prob >= 0.70:
                            findings.append(
                                Finding(
                                    attack_type=AttackType.INSTRUCTION_OVERRIDE,
                                    score=prob,
                                    segment_id=segment.id,
                                    span_original=orig_span,
                                    evidence=evidence,
                                    detector="ml_classifier",
                                    layer="classifier",
                                    variant_chain=v_chain,
                                )
                            )
                    else:
                        # Standalone detect call (rule_categories is None)
                        cat = AttackType.INDIRECT_PROMPT_INJECTION if (
                            ctx.trust == Trust.UNTRUSTED or ctx.source != InputSource.USER_MESSAGE
                        ) else AttackType.INSTRUCTION_OVERRIDE
                        findings.append(
                            Finding(
                                attack_type=cat,
                                score=prob,
                                segment_id=segment.id,
                                span_original=orig_span,
                                evidence=evidence,
                                detector="ml_classifier",
                                layer="classifier",
                                variant_chain=v_chain,
                            )
                        )

        return findings


def train_classifier_from_dev(
    dev_path: Path | str = "data/dev.jsonl",
    model_path: Path | str = DEFAULT_MODEL_PATH,
) -> MLClassifier:
    """Train classifier on the dev split (§9.2, §5.3b)."""
    p_dev = Path(dev_path)
    if not p_dev.exists():
        raise FileNotFoundError(f"Dev dataset not found at {p_dev}")

    texts = []
    labels = []

    with open(p_dev, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            is_attack = item.get("is_attack", False)
            label = 1 if is_attack else 0

            # Get text from turns or fixture
            if item.get("turns"):
                # Multi-turn text
                full_turn_text = " ".join(t.get("text", "") for t in item["turns"])
                texts.append(full_turn_text)
                labels.append(label)
            elif item.get("content_path"):
                c_path = Path(item["content_path"])
                if c_path.exists():
                    try:
                        content_str = c_path.read_text(encoding="utf-8", errors="ignore")
                        if content_str.strip():
                            texts.append(content_str[:2000])  # limit chunk
                            labels.append(label)
                    except Exception:
                        pass

    clf = MLClassifier(model_path=model_path)
    clf.train(texts, labels)
    return clf
