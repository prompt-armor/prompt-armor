"""LiteEngine — orchestrates parallel layer dispatch.

Runs all analysis layers in parallel via ThreadPoolExecutor,
collects results, and fuses them into a single ShieldResult.
"""

from __future__ import annotations

import atexit
import logging
import re
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError

from llm_shield.config import ShieldConfig, load_config
from llm_shield.fusion import fuse_results
from llm_shield.layers.base import BaseLayer
from llm_shield.layers.l1_regex import L1RegexLayer
from llm_shield.layers.l4_structural import L4StructuralLayer
from llm_shield.models import ShieldResult

logger = logging.getLogger("llm_shield")


def _build_layers(config: ShieldConfig) -> list[BaseLayer]:
    """Build the list of available layers.

    L2 (classifier) and L3 (similarity) are optional and only loaded
    when their dependencies are available. Catches all exceptions (not just
    ImportError) to handle broken native libraries (OSError, RuntimeError).
    """
    layers: list[BaseLayer] = [
        L1RegexLayer(config),
        L4StructuralLayer(config),
    ]

    # Try to load L3 (requires sentence-transformers + faiss-cpu)
    try:
        import faiss  # noqa: F401
        import sentence_transformers  # noqa: F401
        from llm_shield.layers.l3_similarity import L3SimilarityLayer

        layers.append(L3SimilarityLayer(config))
    except Exception:
        pass

    # Try to load L2 (requires onnxruntime)
    try:
        import onnxruntime  # noqa: F401
        from llm_shield.layers.l2_classifier import L2ClassifierLayer

        layers.append(L2ClassifierLayer(config))
    except Exception:
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
    """Normalize text to defeat common evasion techniques."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH_CHARS.sub("", text)
    text = re.sub(r"[^\S\n]+", " ", text)
    return text


# Sliding window config
_WINDOW_WORD_THRESHOLD = 150
_WINDOW_SIZE = 200
_WINDOW_STRIDE = 100
_MAX_SEGMENTS = 10
_MAX_INPUT_CHARS = 50_000


def _segment_text(text: str) -> list[str]:
    """Split long text into overlapping windows for compound injection detection."""
    words = text.split()
    if len(words) <= _WINDOW_WORD_THRESHOLD:
        return [text]

    segments = []
    for i in range(0, len(words), _WINDOW_STRIDE):
        window = words[i : i + _WINDOW_SIZE]
        if len(window) < 20:
            break
        segments.append(" ".join(window))
        if len(segments) >= _MAX_SEGMENTS:
            break

    return segments


class LiteEngine:
    """Orchestrates parallel analysis across all available layers.

    Supports context manager protocol for proper resource cleanup:
        with LiteEngine() as engine:
            result = engine.analyze("some text")
    """

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or load_config()
        self._layers = _build_layers(self._config)
        self._pool = ThreadPoolExecutor(max_workers=max(len(self._layers), 1))

        # Initialize layers with fail-open: if a layer fails to setup,
        # remove it and continue with remaining layers.
        loaded: list[BaseLayer] = []
        for layer in self._layers:
            try:
                layer.setup()
                loaded.append(layer)
            except Exception as e:
                logger.warning("Layer %s failed to setup: %s, disabling", layer.name, e)
        self._layers = loaded

        # Register cleanup on process exit
        atexit.register(self.close)

    def _analyze_single(self, text: str, start: float) -> ShieldResult:
        """Run all layers in parallel on a single text segment.

        Uses per-layer timeout and fail-open: if a layer hangs or crashes,
        analysis proceeds with the remaining layers.
        """
        futures = {
            self._pool.submit(layer.analyze, text): layer.name
            for layer in self._layers
        }
        layer_results = []
        for future in futures:
            layer_name = futures[future]
            try:
                result = future.result(timeout=2.0)
                layer_results.append(result)
            except FuturesTimeoutError:
                logger.warning("Layer %s timed out, skipping", layer_name)
            except Exception as e:
                logger.warning("Layer %s failed: %s, skipping", layer_name, e)

        return fuse_results(layer_results, self._config, total_start=start)

    def analyze(self, text: str) -> ShieldResult:
        """Run all layers in parallel and fuse results."""
        if not isinstance(text, str):
            raise TypeError(f"Expected str, got {type(text).__name__}")

        start = time.perf_counter()

        if len(text) > _MAX_INPUT_CHARS:
            text = text[:_MAX_INPUT_CHARS]

        text = _normalize_text(text)

        segments = _segment_text(text)

        if len(segments) == 1:
            return self._analyze_single(text, start)

        results = [self._analyze_single(text, start)]
        for segment in segments:
            results.append(self._analyze_single(segment, start))

        best = max(results, key=lambda r: r.risk_score)

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

    def __enter__(self) -> LiteEngine:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
