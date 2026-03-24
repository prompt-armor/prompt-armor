"""L3 — Semantic similarity layer.

Compares prompt embeddings against a database of known attack embeddings
using cosine similarity via FAISS. Detects paraphrased or novel variations
of known attacks that regex cannot catch.

Requires: onnxruntime, tokenizers, faiss-cpu
Falls back to sentence-transformers if ONNX model not available.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import numpy as np

from prompt_armor.config import ShieldConfig
from prompt_armor.layers.base import BaseLayer
from prompt_armor.models import CATEGORY_MAP, Category, Evidence, LayerResult

logger = logging.getLogger("prompt_armor")

_CATEGORY_MAP: dict[str, Category | None] = {**CATEGORY_MAP, "benign": None}

_DEFAULT_ATTACKS_PATH = Path(__file__).parent.parent / "data" / "attacks" / "known_attacks.jsonl"
_ONNX_MODEL_PATH = Path(__file__).parent.parent / "data" / "models" / "l3-contrastive-onnx"
_CONTRASTIVE_MODEL_PATH = Path(__file__).parent.parent / "data" / "models" / "l3-contrastive"
_DEFAULT_MODEL_NAME = "paraphrase-multilingual-MiniLM-L12-v2"

# Similarity thresholds
_HIGH_SIMILARITY = 0.75
_MEDIUM_SIMILARITY = 0.55


class L3SimilarityLayer(BaseLayer):
    """Cosine similarity against known attack embeddings."""

    name = "l3_similarity"

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or ShieldConfig()
        self._onnx_session: Any = None
        self._tokenizer: Any = None
        self._st_model: Any = None  # SentenceTransformer fallback
        self._index: Any = None
        self._attack_metadata: list[dict[str, str]] = []
        self._use_onnx = False

    def _mean_pool(self, token_embeddings: np.ndarray, attention_mask: np.ndarray) -> np.ndarray:
        """Mean pooling over non-padding tokens, then L2 normalize."""
        mask = attention_mask[..., np.newaxis].astype(np.float32)
        pooled = (token_embeddings * mask).sum(axis=1) / mask.sum(axis=1).clip(min=1e-9)
        norms = np.linalg.norm(pooled, axis=1, keepdims=True).clip(min=1e-9)
        return (pooled / norms).astype(np.float32)

    @staticmethod
    def _download_onnx_model() -> None:
        """Auto-download L3 ONNX model from HuggingFace Hub."""
        try:
            from huggingface_hub import hf_hub_download

            _ONNX_MODEL_PATH.mkdir(parents=True, exist_ok=True)
            logger.info("L3: downloading ONNX model from prompt-armor/l3-contrastive-onnx...")
            hf_hub_download(
                repo_id="prompt-armor/l3-contrastive-onnx",
                filename="model_quant.onnx",
                local_dir=str(_ONNX_MODEL_PATH),
            )
            hf_hub_download(
                repo_id="prompt-armor/l3-contrastive-onnx",
                filename="tokenizer.json",
                local_dir=str(_ONNX_MODEL_PATH),
            )
            logger.info("L3: ONNX model downloaded")
        except Exception as e:
            logger.warning("L3: auto-download failed: %s", e)

    def _encode_onnx(self, texts: list[str], batch_size: int = 256) -> np.ndarray:
        """Encode texts using ONNX model + tokenizers. Batched for efficiency."""
        all_embeddings = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            encodings = self._tokenizer.encode_batch(batch)
            input_ids = np.array([e.ids for e in encodings], dtype=np.int64)
            attention_mask = np.array([e.attention_mask for e in encodings], dtype=np.int64)
            outputs = self._onnx_session.run(None, {"input_ids": input_ids, "attention_mask": attention_mask})
            pooled = self._mean_pool(outputs[0], attention_mask)
            all_embeddings.append(pooled)
        return np.vstack(all_embeddings) if all_embeddings else np.zeros((0, 384), dtype=np.float32)

    def _encode_single_onnx(self, text: str) -> np.ndarray:
        """Encode a single text using ONNX. Returns (1, 384)."""
        encoding = self._tokenizer.encode(text)
        input_ids = np.array([encoding.ids], dtype=np.int64)
        attention_mask = np.array([encoding.attention_mask], dtype=np.int64)
        outputs = self._onnx_session.run(None, {"input_ids": input_ids, "attention_mask": attention_mask})
        return self._mean_pool(outputs[0], attention_mask)

    def setup(self) -> None:
        """Load embedding model, build FAISS index from attack database."""
        import os

        import faiss

        os.environ["TOKENIZERS_PARALLELISM"] = "false"

        # Try ONNX first (no torch/sentence-transformers needed)
        onnx_model = _ONNX_MODEL_PATH / "model_quant.onnx"
        onnx_tokenizer = _ONNX_MODEL_PATH / "tokenizer.json"

        # Auto-download from HuggingFace if not present
        if not onnx_model.exists() or not onnx_tokenizer.exists():
            self._download_onnx_model()

        if onnx_model.exists() and onnx_tokenizer.exists():
            import onnxruntime as ort
            from tokenizers import Tokenizer

            self._onnx_session = ort.InferenceSession(str(onnx_model), providers=["CPUExecutionProvider"])
            self._tokenizer = Tokenizer.from_file(str(onnx_tokenizer))
            self._tokenizer.enable_padding(pad_id=1, pad_token="<pad>")
            self._tokenizer.enable_truncation(max_length=128)
            self._use_onnx = True
            logger.info("L3: using ONNX model")
        else:
            # Fallback to SentenceTransformer
            import io
            import sys

            logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
            logging.getLogger("transformers").setLevel(logging.ERROR)
            logging.getLogger("huggingface_hub").setLevel(logging.ERROR)

            from sentence_transformers import SentenceTransformer

            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                if _CONTRASTIVE_MODEL_PATH.exists():
                    self._st_model = SentenceTransformer(str(_CONTRASTIVE_MODEL_PATH))
                else:
                    self._st_model = SentenceTransformer(_DEFAULT_MODEL_NAME)
            finally:
                sys.stdout = old_stdout
            logger.info("L3: using SentenceTransformer fallback")

        # Load attack database
        attacks_path = self._config.attacks_path or _DEFAULT_ATTACKS_PATH
        texts: list[str] = []
        self._attack_metadata = []

        with open(attacks_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                cat = entry.get("category", "")
                if cat == "benign":
                    continue
                texts.append(entry["text"])
                self._attack_metadata.append({"category": cat, "source": entry.get("source", "unknown")})

        if not texts:
            self._index = faiss.IndexFlatIP(384)
            return

        # Encode all attack texts
        if self._use_onnx:
            embeddings = self._encode_onnx(texts)
        else:
            embeddings = self._st_model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
        embeddings = np.asarray(embeddings, dtype=np.float32)

        # Build FAISS index
        dim = embeddings.shape[1]
        n_vectors = embeddings.shape[0]

        if n_vectors >= 10_000:
            n_clusters = min(int(np.sqrt(n_vectors)), 256)
            quantizer = faiss.IndexFlatIP(dim)
            self._index = faiss.IndexIVFFlat(quantizer, dim, n_clusters, faiss.METRIC_INNER_PRODUCT)
            self._index.train(embeddings)
            self._index.add(embeddings)
            self._index.nprobe = min(16, n_clusters)
        else:
            self._index = faiss.IndexFlatIP(dim)
            self._index.add(embeddings)

    def analyze(self, text: str) -> LayerResult:
        """Compare prompt against known attacks via cosine similarity."""
        start = time.perf_counter()

        if self._index is None or self._index.ntotal == 0:
            latency = (time.perf_counter() - start) * 1000
            return LayerResult(layer=self.name, score=0.0, confidence=0.5, latency_ms=latency)

        if not self._use_onnx and self._st_model is None:
            latency = (time.perf_counter() - start) * 1000
            return LayerResult(layer=self.name, score=0.0, confidence=0.5, latency_ms=latency)

        # Encode the input
        if self._use_onnx:
            embedding = self._encode_single_onnx(text)
        else:
            embedding = self._st_model.encode([text], convert_to_numpy=True, normalize_embeddings=True)
        embedding = np.asarray(embedding, dtype=np.float32)

        # Search top-k similar attacks
        k = min(5, self._index.ntotal)
        scores, indices = self._index.search(embedding, k)

        top_similarity = float(scores[0][0])
        evidence: list[Evidence] = []
        categories_seen: set[Category] = set()

        for i in range(k):
            sim = float(scores[0][i])
            idx = int(indices[0][i])
            if sim < _MEDIUM_SIMILARITY:
                break

            meta = self._attack_metadata[idx]
            cat = _CATEGORY_MAP.get(meta["category"])
            if cat is None:
                continue

            evidence.append(
                Evidence(
                    layer=self.name,
                    category=cat,
                    description=f"Similarity {sim:.2f} to known {meta['category']} attack (source: {meta['source']})",
                    score=sim,
                )
            )
            categories_seen.add(cat)

        # Map similarity to risk score
        if top_similarity >= _HIGH_SIMILARITY:
            risk_score = 0.5 + (top_similarity - _HIGH_SIMILARITY) * 2.78
        elif top_similarity >= _MEDIUM_SIMILARITY:
            risk_score = (top_similarity - _MEDIUM_SIMILARITY) / (_HIGH_SIMILARITY - _MEDIUM_SIMILARITY) * 0.5
        else:
            risk_score = 0.0

        risk_score = min(1.0, max(0.0, risk_score))

        if top_similarity > 0.9 or top_similarity < 0.4:
            confidence = 0.95
        else:
            confidence = 0.7

        latency = (time.perf_counter() - start) * 1000
        return LayerResult(
            layer=self.name,
            score=round(risk_score, 4),
            confidence=round(confidence, 4),
            categories=tuple(sorted(categories_seen, key=lambda c: c.value)),
            evidence=tuple(evidence),
            latency_ms=round(latency, 2),
        )
