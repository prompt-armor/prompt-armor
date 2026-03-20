"""L3 — Semantic similarity layer.

Compares prompt embeddings against a database of known attack embeddings
using cosine similarity via FAISS. Detects paraphrased or novel variations
of known attacks that regex cannot catch.

Requires: sentence-transformers, faiss-cpu
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

from prompt_armor.config import ShieldConfig
from prompt_armor.layers.base import BaseLayer
from prompt_armor.models import CATEGORY_MAP, Category, Evidence, LayerResult

_CATEGORY_MAP: dict[str, Category | None] = {**CATEGORY_MAP, "benign": None}

_DEFAULT_ATTACKS_PATH = Path(__file__).parent.parent / "data" / "attacks" / "known_attacks.jsonl"
_DEFAULT_MODEL_NAME = "paraphrase-multilingual-MiniLM-L12-v2"

# Similarity thresholds
_HIGH_SIMILARITY = 0.75
_MEDIUM_SIMILARITY = 0.55


class L3SimilarityLayer(BaseLayer):
    """Cosine similarity against known attack embeddings."""

    name = "l3_similarity"

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or ShieldConfig()
        self._model = None
        self._index = None
        self._attack_metadata: list[dict[str, str]] = []

    def setup(self) -> None:
        """Load embedding model, build FAISS index from attack database."""
        import io
        import logging
        import os
        import sys

        import faiss

        # Suppress noisy model loading output
        os.environ["TOKENIZERS_PARALLELISM"] = "false"
        logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
        logging.getLogger("transformers").setLevel(logging.ERROR)
        logging.getLogger("huggingface_hub").setLevel(logging.ERROR)

        from sentence_transformers import SentenceTransformer

        # Redirect stdout to suppress tqdm/torch load reports
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            self._model = SentenceTransformer(_DEFAULT_MODEL_NAME)
        finally:
            sys.stdout = old_stdout

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
                # Skip benign entries — we only index attacks
                if cat == "benign":
                    continue
                texts.append(entry["text"])
                self._attack_metadata.append(
                    {"category": cat, "source": entry.get("source", "unknown")}
                )

        if not texts:
            # Empty index
            self._index = faiss.IndexFlatIP(384)
            return

        # Encode all attack texts
        embeddings = self._model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
        embeddings = np.asarray(embeddings, dtype=np.float32)

        # Build FAISS index (inner product on normalized vectors = cosine similarity)
        dim = embeddings.shape[1]
        self._index = faiss.IndexFlatIP(dim)
        self._index.add(embeddings)

    def analyze(self, text: str) -> LayerResult:
        """Compare prompt against known attacks via cosine similarity."""
        start = time.perf_counter()

        if self._model is None or self._index is None or self._index.ntotal == 0:
            latency = (time.perf_counter() - start) * 1000
            return LayerResult(layer=self.name, score=0.0, confidence=0.5, latency_ms=latency)

        # Encode the input
        embedding = self._model.encode([text], convert_to_numpy=True, normalize_embeddings=True)
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
            risk_score = 0.5 + (top_similarity - _HIGH_SIMILARITY) * 2.78  # scales 0.82->0.5, 1.0->1.0
        elif top_similarity >= _MEDIUM_SIMILARITY:
            risk_score = (top_similarity - _MEDIUM_SIMILARITY) / (_HIGH_SIMILARITY - _MEDIUM_SIMILARITY) * 0.5
        else:
            risk_score = 0.0

        risk_score = min(1.0, max(0.0, risk_score))

        # Confidence based on how decisive the similarity is
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
