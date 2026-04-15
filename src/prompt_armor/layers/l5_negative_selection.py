"""L5 — Negative Selection anomaly detection layer.

Learns what "normal" prompts look like and flags deviations.
Trained on benign prompts via Isolation Forest. Catches zero-day
attacks that don't resemble any known pattern.

Pure statistical features, <1ms inference. Requires scikit-learn.
"""

from __future__ import annotations

import logging
import math
import re
import string
import time
from pathlib import Path

import numpy as np

from prompt_armor.config import ShieldConfig
from prompt_armor.layers.base import BaseLayer
from prompt_armor.layers.l4_structural import _IMPERATIVE_VERBS
from prompt_armor.models import Category, Evidence, LayerResult

logger = logging.getLogger("prompt_armor")

_MODEL_PATH = Path(__file__).parent.parent / "data" / "models" / "l5_negative_selection.pkl"

_INJECTION_KEYWORDS = frozenset({
    "ignore", "forget", "disregard", "override", "bypass", "skip",
    "instructions", "prompt", "system", "previous", "above", "rules",
    "pretend", "roleplay", "jailbreak", "dan", "unrestricted",
    "decode", "base64", "translate", "morse", "hex", "binary",
})

_DELIMITER_PATTERNS = re.compile(
    r"(\[system\]|\[inst\]|<\|im_start\|>|<\|im_end\|>|### ?system|### ?instruction|```system)",
    re.IGNORECASE,
)


def _extract_l5_features(text: str) -> np.ndarray:
    """Extract 15 statistical + structural features for anomaly detection.

    Shared between training script and inference layer.
    Features 1-11 capture text shape, 12-15 capture attack-like patterns.
    """
    words = text.lower().split()
    word_count = max(len(words), 1)
    char_count = max(len(text), 1)
    sentences = re.split(r"(?<=[.!?\n])\s+", text)
    sentence_count = max(len(sentences), 1)

    # 1-3: Length features
    f_word_count = float(word_count)
    f_char_count = float(char_count)
    f_sentence_count = float(sentence_count)

    # 4-5: Average lengths
    f_avg_word_length = char_count / word_count
    f_avg_sentence_length = word_count / sentence_count

    # 6: Imperative verb ratio (reused from L4)
    imperative_count = sum(1 for w in words if w.strip(string.punctuation) in _IMPERATIVE_VERBS)
    f_imperative_ratio = imperative_count / word_count

    # 7: Question mark ratio
    question_marks = text.count("?")
    f_question_ratio = question_marks / sentence_count

    # 8: Special character density
    special = sum(1 for c in text if not c.isalnum() and c not in " \t\n.,!?;:'-\"()[]{}/")
    f_special_density = special / char_count

    # 9: Shannon entropy
    if len(text) < 20:
        f_entropy = 0.0
    else:
        from collections import Counter

        freq = Counter(text)
        length = len(text)
        f_entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())

    # 10: Uppercase ratio
    upper_count = sum(1 for c in text if c.isupper())
    f_uppercase_ratio = upper_count / char_count

    # 11: Unique word ratio (vocabulary diversity)
    unique_words = len(set(words))
    f_unique_ratio = unique_words / word_count

    # 12: Injection keyword density (attack-discriminative)
    injection_count = sum(1 for w in words if w.strip(string.punctuation) in _INJECTION_KEYWORDS)
    f_injection_density = injection_count / word_count

    # 13: First sentence imperative ratio (attacks front-load commands)
    first_sentence_words = sentences[0].lower().split() if sentences else []
    first_sent_len = max(len(first_sentence_words), 1)
    first_imp = sum(1 for w in first_sentence_words if w.strip(string.punctuation) in _IMPERATIVE_VERBS)
    f_first_sent_imperative = first_imp / first_sent_len

    # 14: Delimiter presence (system/instruction markers)
    f_delimiter_count = float(len(_DELIMITER_PATTERNS.findall(text)))

    # 15: Language mixing (multiple scripts in same text — common evasion)
    has_latin = bool(re.search(r"[a-zA-Z]", text))
    has_cyrillic = bool(re.search(r"[\u0400-\u04FF]", text))
    has_cjk = bool(re.search(r"[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff]", text))
    has_arabic = bool(re.search(r"[\u0600-\u06FF]", text))
    f_script_mixing = float(sum([has_latin, has_cyrillic, has_cjk, has_arabic]) - 1)
    f_script_mixing = max(0.0, f_script_mixing)

    return np.array(
        [
            f_word_count,
            f_char_count,
            f_sentence_count,
            f_avg_word_length,
            f_avg_sentence_length,
            f_imperative_ratio,
            f_question_ratio,
            f_special_density,
            f_entropy,
            f_uppercase_ratio,
            f_unique_ratio,
            f_injection_density,
            f_first_sent_imperative,
            f_delimiter_count,
            f_script_mixing,
        ],
        dtype=np.float32,
    )


class L5NegativeSelectionLayer(BaseLayer):
    """Anomaly detection via Isolation Forest on text features."""

    name = "l5_negative_selection"

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or ShieldConfig()
        self._model = None
        self._score_min: float = 0.0
        self._score_max: float = 1.0

    @staticmethod
    def _download_model() -> None:
        """Auto-download L5 model from HuggingFace Hub."""
        try:
            from huggingface_hub import hf_hub_download

            logger.info("L5: downloading model from prompt-armor/l5-negative-selection...")
            hf_hub_download(
                repo_id="prompt-armor/l5-negative-selection",
                filename="l5_negative_selection.pkl",
                local_dir=str(_MODEL_PATH.parent),
            )
            logger.info("L5: model downloaded")
        except Exception as e:
            logger.warning("L5: auto-download failed: %s", e)

    def setup(self) -> None:
        """Load the trained Isolation Forest model."""
        import joblib

        if not _MODEL_PATH.exists():
            self._download_model()

        if not _MODEL_PATH.exists():
            raise FileNotFoundError(f"L5 model not found at {_MODEL_PATH}. Run: python scripts/train_l5_model.py")

        data = joblib.load(_MODEL_PATH)
        self._model = data["model"]
        self._score_min = data["score_min"]
        self._score_max = data["score_max"]

    def analyze(self, text: str) -> LayerResult:
        """Score how anomalous the text is compared to normal prompts."""
        start = time.perf_counter()

        if self._model is None:
            latency = (time.perf_counter() - start) * 1000
            return LayerResult(layer=self.name, score=0.0, confidence=0.5, latency_ms=latency)

        features = _extract_l5_features(text)
        raw = float(self._model.decision_function(features.reshape(1, -1))[0])

        # sklearn decision_function: positive = inlier, negative = outlier.
        # Only flag outliers (negative scores). Inliers get score 0.
        if raw >= 0:
            score = 0.0
        else:
            # Normalize: map negative range to [0, 1] using training min
            # More negative = more anomalous = higher score
            score = min(1.0, abs(raw) / max(abs(self._score_min), 1e-10))
        score = max(0.0, min(1.0, score))

        evidence: list[Evidence] = []
        categories: set[Category] = set()

        if score > 0.3:
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.PROMPT_INJECTION,
                    description=f"Anomalous text pattern (deviation: {score:.2f})",
                    score=score,
                )
            )
            categories.add(Category.PROMPT_INJECTION)

        confidence = 0.7 if 0.2 < score < 0.8 else 0.9
        latency = (time.perf_counter() - start) * 1000

        return LayerResult(
            layer=self.name,
            score=round(score, 4),
            confidence=round(confidence, 4),
            categories=tuple(sorted(categories, key=lambda c: c.value)),
            evidence=tuple(evidence),
            latency_ms=round(latency, 2),
        )
