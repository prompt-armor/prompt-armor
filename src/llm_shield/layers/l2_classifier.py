"""L2 — Sequence classifier layer.

Uses a DistilBERT model (ONNX Runtime) fine-tuned for prompt injection
classification. Falls back to a heuristic TF-IDF-like approach if no
ONNX model is available.

Requires: onnxruntime, tokenizers (or transformers for model loading)
"""

from __future__ import annotations

import time
from pathlib import Path

import numpy as np

from llm_shield.config import ShieldConfig
from llm_shield.layers.base import BaseLayer
from llm_shield.models import Category, Evidence, LayerResult

_DEFAULT_MODEL_DIR = Path(__file__).parent.parent / "data" / "models"

# Heuristic classifier keywords (used when no ONNX model is available)
_INJECTION_KEYWORDS = {
    "ignore": 0.7,
    "disregard": 0.7,
    "forget": 0.6,
    "override": 0.7,
    "bypass": 0.7,
    "jailbreak": 0.9,
    "unrestricted": 0.8,
    "unfiltered": 0.8,
    "uncensored": 0.8,
    "DAN": 0.9,
    "STAN": 0.85,
    "developer mode": 0.8,
    "admin mode": 0.8,
    "god mode": 0.85,
    "system prompt": 0.7,
    "previous instructions": 0.8,
    "no restrictions": 0.8,
    "no limitations": 0.75,
    "no filters": 0.75,
    "safety disabled": 0.85,
    "content policy": 0.5,
}

_BENIGN_KEYWORDS = {
    "help": 0.3,
    "please": 0.2,
    "explain": 0.3,
    "how to": 0.3,
    "what is": 0.3,
    "write": 0.2,
    "code": 0.2,
    "function": 0.2,
    "translate": 0.3,
    "summarize": 0.3,
}


class L2ClassifierLayer(BaseLayer):
    """Sequence classifier for prompt injection detection.

    Uses ONNX model if available, falls back to keyword-based heuristic.
    """

    name = "l2_classifier"

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or ShieldConfig()
        self._onnx_session = None
        self._tokenizer = None
        self._use_heuristic = True

    def setup(self) -> None:
        """Load ONNX model, downloading if needed. Falls back to heuristic."""
        model_path = _DEFAULT_MODEL_DIR / "classifier.onnx"
        tokenizer_path = _DEFAULT_MODEL_DIR / "tokenizer.json"

        # Auto-download if model not present
        if not model_path.is_file():
            self._try_download_model(model_path, tokenizer_path)

        if model_path.is_file():
            try:
                import onnxruntime as ort

                self._onnx_session = ort.InferenceSession(
                    str(model_path),
                    providers=["CPUExecutionProvider"],
                )

                if tokenizer_path.is_file():
                    from tokenizers import Tokenizer

                    self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
                    self._tokenizer.enable_padding(pad_id=0, pad_token="[PAD]")
                    self._tokenizer.enable_truncation(max_length=512)
                    self._use_heuristic = False
            except Exception:
                self._use_heuristic = True

    # Pinned model revision for supply chain security
    _MODEL_ID = "aldenb/scout-prompt-injection-classifier-22m"
    _MODEL_REVISION = "1b28ceb546c0a79de8f590cde6882fe75c203ede"

    @staticmethod
    def _try_download_model(model_path: Path, tokenizer_path: Path) -> None:
        """Download the ONNX model from HuggingFace Hub on first use."""
        try:
            import logging
            import shutil

            from huggingface_hub import hf_hub_download

            logger = logging.getLogger("llm_shield")
            logger.info("Downloading L2 classifier model (83MB, one-time)...")

            model_id = L2ClassifierLayer._MODEL_ID
            revision = L2ClassifierLayer._MODEL_REVISION
            model_path.parent.mkdir(parents=True, exist_ok=True)

            onnx = hf_hub_download(model_id, "onnx/model_quant.onnx", revision=revision)
            shutil.copy2(onnx, model_path)

            tok = hf_hub_download(model_id, "tokenizer.json", revision=revision)
            shutil.copy2(tok, tokenizer_path)

            logger.info("Model downloaded successfully.")
        except Exception as e:
            logging.getLogger("llm_shield").warning("Model download failed: %s", e)

    def analyze(self, text: str) -> LayerResult:
        """Classify prompt as malicious or benign."""
        start = time.perf_counter()

        if self._use_heuristic:
            result = self._heuristic_classify(text)
        else:
            result = self._onnx_classify(text)

        latency = (time.perf_counter() - start) * 1000
        return LayerResult(
            layer=self.name,
            score=result["score"],
            confidence=result["confidence"],
            categories=tuple(result["categories"]),
            evidence=tuple(result["evidence"]),
            latency_ms=round(latency, 2),
        )

    def _heuristic_classify(self, text: str) -> dict:
        """Keyword-based heuristic classifier (fallback)."""
        text_lower = text.lower()
        words = text_lower.split()

        # Score injection signals
        injection_score = 0.0
        injection_hits = 0
        evidence: list[Evidence] = []

        for keyword, weight in _INJECTION_KEYWORDS.items():
            if keyword.lower() in text_lower:
                injection_score = max(injection_score, weight)
                injection_hits += 1
                if weight >= 0.7:
                    evidence.append(
                        Evidence(
                            layer=self.name,
                            category=Category.PROMPT_INJECTION,
                            description=f"Keyword '{keyword}' detected (weight: {weight})",
                            score=weight,
                        )
                    )

        # Score benign signals
        benign_score = 0.0
        for keyword, weight in _BENIGN_KEYWORDS.items():
            if keyword.lower() in text_lower:
                benign_score = max(benign_score, weight)

        # Combine: injection score dampened by benign signals
        if injection_hits > 0:
            # Boost for multiple injection keywords
            multi_boost = min(0.2, injection_hits * 0.05)
            raw_score = min(1.0, injection_score + multi_boost)
            # Dampen by benign signals
            final_score = raw_score * (1.0 - benign_score * 0.3)
        else:
            final_score = 0.0

        # Length-based penalty for very short prompts (less likely to be attacks)
        if len(words) < 5 and injection_hits <= 1:
            final_score *= 0.5

        categories = [Category.PROMPT_INJECTION] if final_score > 0.3 else []

        # Confidence is lower for heuristic (no ML model)
        confidence = 0.65 if injection_hits > 0 else 0.75

        return {
            "score": round(min(1.0, max(0.0, final_score)), 4),
            "confidence": confidence,
            "categories": categories,
            "evidence": evidence,
        }

    def _onnx_classify(self, text: str) -> dict:
        """ONNX model-based classification."""
        if self._tokenizer is None or self._onnx_session is None:
            return self._heuristic_classify(text)

        # Tokenize
        encoding = self._tokenizer.encode(text)
        input_ids = np.array([encoding.ids], dtype=np.int64)
        attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

        # Run inference
        outputs = self._onnx_session.run(
            None,
            {"input_ids": input_ids, "attention_mask": attention_mask},
        )

        # Softmax on logits
        logits = outputs[0][0]
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / exp_logits.sum()

        # Raw probability of injection class
        raw_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])

        # Calibrate: stretch the model's effective range to 0.0-1.0
        # Scout-22m outputs ~0.23 for benign and ~0.78 for attacks.
        # Without calibration, the fusion layer sees compressed scores that
        # underweight L2 relative to L1/L3/L4 which use the full 0-1 range.
        _FLOOR = 0.23  # typical benign score
        _CEIL = 0.78   # typical attack score
        calibrated = (raw_prob - _FLOOR) / (_CEIL - _FLOOR)
        calibrated = max(0.0, min(1.0, calibrated))

        # Evidence threshold on calibrated score
        evidence = []
        if calibrated > 0.3:
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.PROMPT_INJECTION,
                    description=f"ML classifier: {calibrated:.2f} (raw: {raw_prob:.2f})",
                    score=calibrated,
                )
            )

        categories = [Category.PROMPT_INJECTION] if calibrated > 0.3 else []

        # Confidence based on how decisive the raw score is
        if raw_prob > 0.7 or raw_prob < 0.25:
            confidence = 0.9
        else:
            confidence = 0.7

        return {
            "score": round(calibrated, 4),
            "confidence": confidence,
            "categories": categories,
            "evidence": evidence,
        }
