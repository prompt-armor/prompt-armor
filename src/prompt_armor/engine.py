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
from collections import OrderedDict
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

    # Try to load L3 (requires faiss-cpu + onnxruntime or sentence-transformers)
    try:
        import faiss  # noqa: F401

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


# Zero-width and invisible characters to strip.
# Includes: basic zero-widths, Bidi format controls (RTL override attacks),
# Unicode Tag chars (ASCII Smuggler attack — U+E0000-E007F range),
# and interlinear annotation marks.
_INVISIBLE_CHARS = re.compile(
    "["
    "\u200b-\u200f"  # zero-widths + LRM/RLM
    "\u202a-\u202e"  # Bidi formatting (RTL override, etc.)
    "\u2060-\u206f"  # word joiner, invisible operators, interlinear
    "\u00ad"  # soft hyphen
    "\ufeff"  # BOM / zero-width no-break space
    "\u180e"  # Mongolian vowel separator
    "\U000e0000-\U000e007f"  # Unicode Tag chars — ASCII smuggler attack
    "]"
)

# Homoglyph fold: map common Cyrillic/Greek/fullwidth lookalikes to ASCII Latin.
# Keeps detection focused on intent, not on which script was used to write it.
# Applied AFTER NFKC so fullwidth variants are normalized first.
_HOMOGLYPH_MAP = str.maketrans(
    {
        # Cyrillic → Latin (lowercase)
        "а": "a",
        "в": "b",
        "е": "e",
        "ё": "e",
        "з": "z",
        "и": "i",
        "і": "i",
        "й": "i",
        "к": "k",
        "м": "m",
        "н": "h",
        "о": "o",
        "р": "p",
        "с": "c",
        "т": "t",
        "у": "y",
        "х": "x",
        "ѕ": "s",
        "ј": "j",
        "ԛ": "q",
        "ԝ": "w",
        # Cyrillic → Latin (uppercase)
        "А": "A",
        "В": "B",
        "Е": "E",
        "Ё": "E",
        "З": "Z",
        "И": "I",
        "І": "I",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "У": "Y",
        "Х": "X",
        "Ѕ": "S",
        "Ј": "J",
        "Ԛ": "Q",
        "Ԝ": "W",
        # Greek → Latin
        "α": "a",
        "ο": "o",
        "ρ": "p",
        "ν": "v",
        "ε": "e",
        "τ": "t",
        "κ": "k",
        "ι": "i",
        "μ": "m",
        "η": "n",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ζ": "Z",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Υ": "Y",
        "Χ": "X",
    }
)


def _normalize_text(text: str) -> str:
    """Normalize text to defeat common evasion techniques.

    Pipeline:
    1. NFKC — normalize fullwidth/compatibility forms
    2. Strip invisible chars (zero-widths, Bidi controls, Unicode Tags)
    3. Fold homoglyphs (Cyrillic/Greek → Latin)
    4. Collapse whitespace (preserve newlines)
    """
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE_CHARS.sub("", text)
    text = text.translate(_HOMOGLYPH_MAP)
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
    _MAX_SESSIONS = 10_000  # bounded LRU of per-session inflammation state

    # Class-level tracking to prevent atexit handler accumulation
    _active_engines: weakref.WeakSet[LiteEngine] = weakref.WeakSet()
    _atexit_registered: bool = False

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or load_config()
        self._layers = _build_layers(self._config)
        self._pool = ThreadPoolExecutor(max_workers=max(len(self._layers), 1))
        # Per-session threat awareness (inflammation cascade), keyed by an
        # explicit session_id. The long-lived / singleton engine therefore never
        # leaks inflammation across unrelated callers; a bounded LRU caps memory.
        # No session_id => stateless (no inflammation), which is the safe default.
        self._inflammation: OrderedDict[str, float] = OrderedDict()
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

    def analyze(self, text: str, session_id: str | None = None) -> ShieldResult:
        """Run all layers in parallel and fuse results.

        Stateless by default. Pass a stable ``session_id`` (e.g. per user /
        connection) to enable the inflammation cascade — previous WARN/BLOCK
        decisions in *that* session temporarily raise sensitivity for subsequent
        requests, catching iterative probing. State is isolated per session, so
        a shared engine never leaks one caller's history into another's.
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

        # Apply inflammation cascade (per session; no-op when session_id is None)
        result = self._apply_inflammation(result, start, session_id)

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

    def _apply_inflammation(self, result: ShieldResult, start: float, session_id: str | None) -> ShieldResult:
        """Apply per-session inflammation to the result.

        ``session_id is None`` => stateless, no inflammation (the safe default
        for a shared engine). With a session_id, previous WARN/BLOCK decisions in
        *that* session boost the effective risk score (catching iterative
        probing) and decay exponentially. State is isolated per session and
        LRU-bounded. Thread-safe: all access is locked.
        """
        if session_id is None:
            return result

        with self._inflammation_lock:
            level = self._inflammation.get(session_id, 0.0)

            # Boost this request's score by the session's current inflammation.
            if level > 0.01:
                boosted_score = min(1.0, result.risk_score + level)
                if boosted_score > result.risk_score + 0.005:
                    new_decision = _decide(boosted_score, _META_THRESHOLD, self._config.thresholds.jitter_sigma)
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

            # Decay, then bump on a hostile verdict — for THIS session's next request.
            level *= self._INFLAMMATION_DECAY
            if result.decision in (Decision.WARN, Decision.BLOCK):
                level = min(
                    self._MAX_INFLAMMATION,
                    level + self._INFLAMMATION_BOOST * result.risk_score,
                )

            # Persist (with LRU eviction) or garbage-collect a decayed session.
            if level > 0.01:
                self._inflammation[session_id] = level
                self._inflammation.move_to_end(session_id)
                while len(self._inflammation) > self._MAX_SESSIONS:
                    self._inflammation.popitem(last=False)
            else:
                self._inflammation.pop(session_id, None)

        return result

    def reset_session(self, session_id: str | None = None) -> None:
        """Clear inflammation state: one session, or all sessions when None."""
        with self._inflammation_lock:
            if session_id is None:
                self._inflammation.clear()
            else:
                self._inflammation.pop(session_id, None)

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
