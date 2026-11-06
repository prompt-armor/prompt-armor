"""L2 — Sequence classifier layer.

Uses ProtectAI's DeBERTa-v3 prompt injection classifier
(``protectai/deberta-v3-base-prompt-injection-v2``, Apache-2.0) as ONNX with FP16
weights that ONNX Runtime casts to FP32 at load, so scores match the upstream
model on any CPU (dynamic INT8 did not: x86 and ARM disagreed). Hosted at
``prompt-armor/l2-deberta-onnx``. Falls back to a
keyword heuristic if the model cannot be loaded; that fallback is logged and
reported via ``degraded``, because the fusion meta-classifier is trained on the
real model's scores.

Requires: onnxruntime, tokenizers
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import numpy as np

from prompt_armor.config import ShieldConfig
from prompt_armor.layers.base import BaseLayer, onnx_session_options
from prompt_armor.models import Category, Evidence, LayerResult

logger = logging.getLogger("prompt_armor")

# Own directory, not the old data/models/classifier.onnx: v0.9.1 downloaded a
# different model to that path, and pip upgrades leave downloaded files behind.
# A fresh directory guarantees an upgraded install never pairs the old model
# with the new calibration and fusion coefficients.
_DEFAULT_MODEL_DIR = Path(__file__).parent.parent / "data" / "models" / "l2-deberta-onnx"
_MODEL_FILE = "model_fp16.onnx"
_TOKENIZER_FILE = "tokenizer.json"

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

    # Pinned model revision for supply chain security
    _MODEL_ID = "prompt-armor/l2-deberta-onnx"
    _MODEL_REVISION = "e723caa5a7d3fe21cebed67761b67cc7e3744723"

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or ShieldConfig()
        self._onnx_session = None
        self._tokenizer = None
        self._use_heuristic = True

    @property
    def degraded(self) -> bool:
        return self._use_heuristic

    def setup(self) -> None:
        """Load the ONNX model, downloading it if needed. Falls back to heuristic."""
        files = self._resolve_model_files()
        if files is None:
            logger.warning("L2: classifier model unavailable, using the keyword heuristic (degraded)")
            return

        model_path, tokenizer_path = files
        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer

            self._onnx_session = ort.InferenceSession(
                str(model_path), onnx_session_options(threads=2), providers=["CPUExecutionProvider"]
            )
            self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
            self._tokenizer.enable_padding(pad_id=0, pad_token="[PAD]")
            self._tokenizer.enable_truncation(max_length=512)
            self._use_heuristic = False
        except Exception as e:
            logger.warning("L2: failed to load classifier model (%s), using the keyword heuristic (degraded)", e)
            self._use_heuristic = True

    @classmethod
    def _resolve_model_files(cls, model_dir: Path = _DEFAULT_MODEL_DIR) -> tuple[Path, Path] | None:
        """Return (model, tokenizer) paths, downloading from the Hub on first use.

        Prefers the package data dir (where air-gapped installs can also drop the
        files by hand); if that is not writable, falls back to the HF cache.
        """
        model_path = model_dir / _MODEL_FILE
        tokenizer_path = model_dir / _TOKENIZER_FILE
        if model_path.is_file() and tokenizer_path.is_file():
            return model_path, tokenizer_path

        try:
            from huggingface_hub import hf_hub_download
        except ImportError:
            return None

        logger.info("L2: downloading classifier model from %s (~400MB, one-time)...", cls._MODEL_ID)
        for local_dir in (model_dir, None):
            kwargs = {"revision": cls._MODEL_REVISION}
            try:
                if local_dir is not None:
                    local_dir.mkdir(parents=True, exist_ok=True)
                    kwargs["local_dir"] = str(local_dir)
                model = hf_hub_download(cls._MODEL_ID, _MODEL_FILE, **kwargs)
                tokenizer = hf_hub_download(cls._MODEL_ID, _TOKENIZER_FILE, **kwargs)
                return Path(model), Path(tokenizer)
            except PermissionError as e:
                logger.info("L2: %s is not writable (%s), downloading to the Hugging Face cache", local_dir, e)
            except Exception as e:
                logger.warning("L2: model download failed: %s", e)
                break
        return None

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

        # Raw probability of the INJECTION class (label 1)
        raw_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])

        # No range stretch: unlike the v0.9.1 model (which compressed its output
        # to ~0.23 benign / ~0.78 attack), this model already spans 0-1 — on the
        # 1,534-sample benchmark, benign median ~0.00 and attacks are bimodal
        # (~0.00 or ~1.00). The fusion meta-classifier is retrained on these
        # scores, so the raw probability is used as-is.
        calibrated = max(0.0, min(1.0, raw_prob))

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
