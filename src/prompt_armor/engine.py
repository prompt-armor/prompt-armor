"""LiteEngine — orchestrates parallel layer dispatch.

Runs all analysis layers in parallel via ThreadPoolExecutor,
collects results, and fuses them into a single ShieldResult.
"""

from __future__ import annotations

import atexit
import logging
import re
import threading
import time
import unicodedata
import weakref
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any

from prompt_armor.config import ShieldConfig, load_config
from prompt_armor.fusion import _META_THRESHOLD, _decide, fuse_results
from prompt_armor.layers.base import BaseLayer
from prompt_armor.layers.l1_regex import L1RegexLayer
from prompt_armor.layers.l4_structural import L4StructuralLayer
from prompt_armor.models import Decision, ShieldResult

logger = logging.getLogger("prompt_armor")


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

        from prompt_armor.layers.l3_similarity import L3SimilarityLayer

        layers.append(L3SimilarityLayer(config))
    except Exception:
        pass

    # Try to load L2 (requires onnxruntime)
    try:
        import onnxruntime  # noqa: F401

        from prompt_armor.layers.l2_classifier import L2ClassifierLayer

        layers.append(L2ClassifierLayer(config))
    except Exception:
        pass

    # Try to load L5 (requires scikit-learn + trained model)
    try:
        import sklearn  # noqa: F401

        from prompt_armor.layers.l5_negative_selection import L5NegativeSelectionLayer

        layers.append(L5NegativeSelectionLayer(config))
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

    Session-level inflammation cascade: when a suspicious prompt passes
    (WARN decision), the engine lowers the effective threshold for
    subsequent prompts, catching iterative probing attacks. Inflammation
    decays exponentially so it doesn't permanently bias the engine.
    """

    # Inflammation parameters
    _INFLAMMATION_BOOST = 0.25  # threshold reduction per WARN
    _INFLAMMATION_DECAY = 0.7  # exponential decay per request
    _MAX_INFLAMMATION = 0.15  # max threshold reduction

    # Class-level tracking to prevent atexit handler accumulation
    _active_engines: weakref.WeakSet[LiteEngine] = weakref.WeakSet()
    _atexit_registered: bool = False

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or load_config()
        self._layers = _build_layers(self._config)
        self._pool = ThreadPoolExecutor(max_workers=max(len(self._layers), 1))
        self._inflammation: float = 0.0  # session-level threat awareness
        self._inflammation_lock = threading.Lock()  # thread-safe inflammation
        self._council: Any = None  # Lazy-initialized when council.enabled

        # Initialize layers with fail-open
        loaded: list[BaseLayer] = []
        for layer in self._layers:
            try:
                layer.setup()
                loaded.append(layer)
            except Exception as e:
                logger.warning("Layer %s failed to setup: %s, disabling", layer.name, e)
        self._layers = loaded

        # Initialize analytics collector if enabled
        self._collector = None
        if self._config.analytics.enabled:
            try:
                from prompt_armor.collector import AnalyticsCollector

                self._collector = AnalyticsCollector(
                    db_path=self._config.analytics.db_path,
                    store_prompts=self._config.analytics.store_prompts,
                    max_records=self._config.analytics.max_records,
                )
                logger.info("Analytics enabled: %s", self._config.analytics.db_path)
            except Exception as e:
                logger.warning("Analytics init failed: %s", e)

        # Register cleanup on process exit (once, not per instance)
        LiteEngine._active_engines.add(self)
        if not LiteEngine._atexit_registered:
            atexit.register(LiteEngine._cleanup_all)
            LiteEngine._atexit_registered = True

    def _analyze_single(self, text: str, start: float) -> ShieldResult:
        """Run all layers in parallel on a single text segment.

        Uses per-layer timeout and fail-open: if a layer hangs or crashes,
        analysis proceeds with the remaining layers.
        """
        futures = {self._pool.submit(layer.analyze, text): layer.name for layer in self._layers}
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

    def _record_analytics(self, text: str, result: ShieldResult) -> None:
        """Record analysis result to analytics DB (non-blocking)."""
        if self._collector is not None:
            self._collector.record(text, result)

    def analyze(self, text: str) -> ShieldResult:
        """Run all layers in parallel and fuse results.

        Applies inflammation cascade: previous WARN/BLOCK decisions
        temporarily increase sensitivity for subsequent requests.
        """
        if not isinstance(text, str):
            raise TypeError(f"Expected str, got {type(text).__name__}")

        original_text = text
        start = time.perf_counter()

        if len(text) > _MAX_INPUT_CHARS:
            text = text[:_MAX_INPUT_CHARS]

        text = _normalize_text(text)

        segments = _segment_text(text)

        if len(segments) == 1:
            result = self._analyze_single(text, start)
        else:
            results = [self._analyze_single(text, start)]
            for segment in segments:
                results.append(self._analyze_single(segment, start))

            best = max(results, key=lambda r: r.risk_score)

            latency = (time.perf_counter() - start) * 1000
            result = ShieldResult(
                risk_score=best.risk_score,
                confidence=best.confidence,
                decision=best.decision,
                categories=best.categories,
                evidence=best.evidence,
                needs_council=best.needs_council,
                latency_ms=round(latency, 2),
                layer_results=best.layer_results,
            )

        # Apply inflammation cascade
        result = self._apply_inflammation(result, start)

        # Council: LLM second opinion for uncertain cases
        if self._config.council.enabled and result.needs_council:
            result = self._run_council(original_text, result)

        self._record_analytics(original_text, result)
        return result

    def _run_council(self, text: str, result: ShieldResult) -> ShieldResult:
        """Dispatch to council for uncertain results. Fail-safe on any error."""
        if self._council is None:
            from prompt_armor.council import Council

            self._council = Council(self._config.council)

        try:
            verdict = self._council.judge(text, result)
            if verdict is not None:
                result = self._council.apply_veto(result, verdict)
                return result
        except Exception as e:
            logger.warning("Council failed: %s, using fallback", e)

        # Fallback: use configured fallback decision
        fallback = Decision.WARN if self._config.council.fallback_decision == "warn" else Decision.BLOCK
        return ShieldResult(
            risk_score=result.risk_score,
            confidence=result.confidence,
            decision=fallback,
            categories=result.categories,
            evidence=result.evidence,
            needs_council=result.needs_council,
            latency_ms=result.latency_ms,
            cost_usd=result.cost_usd,
            layer_results=result.layer_results,
            council_reasoning=f"Council unavailable, fallback={fallback.value}",
        )

    def _apply_inflammation(self, result: ShieldResult, start: float) -> ShieldResult:
        """Apply session-level inflammation to the result.

        If previous requests raised inflammation (WARN/BLOCK), the effective
        risk score gets a small boost, catching iterative probing.
        Inflammation decays exponentially so it doesn't permanently bias.
        Thread-safe: all inflammation state access is locked.
        """
        with self._inflammation_lock:
            # Boost risk score by current inflammation level
            if self._inflammation > 0.01:
                boosted_score = min(1.0, result.risk_score + self._inflammation)
                # Only re-decide if score actually changed meaningfully
                if boosted_score > result.risk_score + 0.005:
                    new_decision = _decide(boosted_score, _META_THRESHOLD)
                    latency = (time.perf_counter() - start) * 1000
                    result = ShieldResult(
                        risk_score=round(boosted_score, 4),
                        confidence=result.confidence,
                        decision=new_decision,
                        categories=result.categories,
                        evidence=result.evidence,
                        needs_council=result.needs_council,
                        latency_ms=round(latency, 2),
                        layer_results=result.layer_results,
                    )

            # Update inflammation for NEXT request
            self._inflammation *= self._INFLAMMATION_DECAY

            if result.decision in (Decision.WARN, Decision.BLOCK):
                self._inflammation = min(
                    self._MAX_INFLAMMATION,
                    self._inflammation + self._INFLAMMATION_BOOST * result.risk_score,
                )

        return result

    def reset_session(self) -> None:
        """Reset inflammation state for a new session."""
        with self._inflammation_lock:
            self._inflammation = 0.0

    @property
    def active_layers(self) -> list[str]:
        """Return names of active layers."""
        return [layer.name for layer in self._layers]

    def close(self) -> None:
        """Shut down the thread pool and analytics collector."""
        self._pool.shutdown(wait=False)
        if self._collector is not None:
            self._collector.close()

    @classmethod
    def _cleanup_all(cls) -> None:
        """Cleanup all active engines on process exit."""
        for engine in list(cls._active_engines):
            try:
                engine.close()
            except Exception:
                pass

    def __enter__(self) -> LiteEngine:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
