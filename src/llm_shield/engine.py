"""LiteEngine — orchestrates parallel layer dispatch.

Runs all analysis layers in parallel via ThreadPoolExecutor,
collects results, and fuses them into a single ShieldResult.
"""

from __future__ import annotations

import re
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor

from llm_shield.config import ShieldConfig, load_config
from llm_shield.fusion import fuse_results
from llm_shield.layers.base import BaseLayer
from llm_shield.layers.l1_regex import L1RegexLayer
from llm_shield.layers.l4_structural import L4StructuralLayer
from llm_shield.models import ShieldResult


def _build_layers(config: ShieldConfig) -> list[BaseLayer]:
    """Build the list of available layers.

    L2 (classifier) and L3 (similarity) are optional and only loaded
    when their dependencies are available.
    """
    layers: list[BaseLayer] = [
        L1RegexLayer(config),
        L4StructuralLayer(config),
    ]

    # Try to load L3 (sentence-transformers + faiss)
    try:
        from llm_shield.layers.l3_similarity import L3SimilarityLayer

        layers.append(L3SimilarityLayer(config))
    except ImportError:
        pass

    # Try to load L2 (onnxruntime)
    try:
        from llm_shield.layers.l2_classifier import L2ClassifierLayer

        layers.append(L2ClassifierLayer(config))
    except ImportError:
        pass

    return layers


# Zero-width and invisible characters to strip
_ZERO_WIDTH_CHARS = re.compile(
    "["
    "\u200b"  # zero-width space
    "\u200c"  # zero-width non-joiner
    "\u200d"  # zero-width joiner
    "\u200e"  # left-to-right mark
    "\u200f"  # right-to-left mark
    "\u00ad"  # soft hyphen
    "\ufeff"  # BOM / zero-width no-break space
    "\u2060"  # word joiner
    "\u2061"  # function application
    "\u2062"  # invisible times
    "\u2063"  # invisible separator
    "\u2064"  # invisible plus
    "\u180e"  # Mongolian vowel separator
    "]"
)


def _normalize_text(text: str) -> str:
    """Normalize text to defeat common evasion techniques.

    - NFKC Unicode normalization (resolves homoglyphs, compatibility chars)
    - Strip zero-width and invisible characters
    - Collapse excessive whitespace
    """
    # NFKC normalization: maps compatibility chars to canonical forms
    # e.g., fullwidth 'Ａ' → 'A', ligatures 'ﬁ' → 'fi'
    text = unicodedata.normalize("NFKC", text)

    # Strip zero-width and invisible characters
    text = _ZERO_WIDTH_CHARS.sub("", text)

    # Collapse excessive whitespace (but preserve newlines)
    text = re.sub(r"[^\S\n]+", " ", text)

    return text


# Sliding window config
_WINDOW_WORD_THRESHOLD = 150  # Only segment if text has more than this many words
_WINDOW_SIZE = 200  # Words per window
_WINDOW_STRIDE = 100  # Overlap between windows
_MAX_SEGMENTS = 10  # Cap segments to prevent DoS on very long inputs
_MAX_INPUT_CHARS = 50_000  # Reject inputs above this length


def _segment_text(text: str) -> list[str]:
    """Split long text into overlapping windows.

    Compound injections hide attacks inside benign text. Analyzing each
    segment independently prevents the benign majority from diluting the
    attack signal in embeddings and keyword ratios.
    """
    words = text.split()
    if len(words) <= _WINDOW_WORD_THRESHOLD:
        return [text]

    segments = []
    for i in range(0, len(words), _WINDOW_STRIDE):
        window = words[i : i + _WINDOW_SIZE]
        if len(window) < 20:  # Skip tiny trailing windows
            break
        segments.append(" ".join(window))
        if len(segments) >= _MAX_SEGMENTS:
            break

    return segments


class LiteEngine:
    """Orchestrates parallel analysis across all available layers."""

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or load_config()
        self._layers = _build_layers(self._config)
        self._pool = ThreadPoolExecutor(max_workers=len(self._layers))

        # Initialize all layers
        for layer in self._layers:
            layer.setup()

    def _analyze_single(self, text: str, start: float) -> ShieldResult:
        """Run all layers in parallel on a single text segment.

        Uses per-layer timeout and fail-open: if a layer hangs or crashes,
        analysis proceeds with the remaining layers.
        """
        import logging

        logger = logging.getLogger("llm_shield")
        futures = {
            self._pool.submit(layer.analyze, text): layer.name
            for layer in self._layers
        }
        layer_results = []
        for future in futures:
            layer_name = futures[future]
            try:
                result = future.result(timeout=2.0)  # 2s per-layer timeout
                layer_results.append(result)
            except TimeoutError:
                logger.warning("Layer %s timed out, skipping", layer_name)
            except Exception as e:
                logger.warning("Layer %s failed: %s, skipping", layer_name, e)

        return fuse_results(layer_results, self._config, total_start=start)

    def analyze(self, text: str) -> ShieldResult:
        """Run all layers in parallel and fuse results.

        For long texts, uses sliding window segmentation to catch
        compound injections hidden inside benign content.
        """
        start = time.perf_counter()

        # Input length guard — prevents DoS via very long inputs
        if len(text) > _MAX_INPUT_CHARS:
            text = text[:_MAX_INPUT_CHARS]

        # Preprocess: normalize Unicode to defeat homoglyph and zero-width bypasses
        text = _normalize_text(text)

        segments = _segment_text(text)

        if len(segments) == 1:
            # Short text: single pass (fast path)
            return self._analyze_single(text, start)

        # Long text: analyze full text + each segment, take max
        results = [self._analyze_single(text, start)]  # Full text for context
        for segment in segments:
            results.append(self._analyze_single(segment, start))

        # Return the result with the highest risk score
        best = max(results, key=lambda r: r.risk_score)

        # Recalculate latency from original start
        latency = (time.perf_counter() - start) * 1000
        return ShieldResult(
            risk_score=best.risk_score,
            confidence=best.confidence,
            decision=best.decision,
            categories=best.categories,
            evidence=best.evidence,
            needs_council=best.needs_council,
            latency_ms=round(latency, 2),
            layer_results=best.layer_results,
        )

    @property
    def active_layers(self) -> list[str]:
        """Return names of active layers."""
        return [layer.name for layer in self._layers]

    def close(self) -> None:
        """Shut down the thread pool."""
        self._pool.shutdown(wait=False)
