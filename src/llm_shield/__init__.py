"""llm-shield — Open-core LLM prompt security analysis."""

from __future__ import annotations

import threading

from llm_shield._version import __version__
from llm_shield.config import ShieldConfig
from llm_shield.engine import LiteEngine
from llm_shield.models import Category, Decision, Evidence, LayerResult, ShieldResult

__all__ = [
    "__version__",
    "analyze",
    "Category",
    "Decision",
    "Evidence",
    "LayerResult",
    "LiteEngine",
    "ShieldConfig",
    "ShieldResult",
]

_default_engine: LiteEngine | None = None
_engine_lock = threading.Lock()


def analyze(text: str) -> ShieldResult:
    """Analyze a prompt for security risks.

    One-call API that lazily initializes the default engine.
    Thread-safe via double-checked locking.
    For custom config, use LiteEngine(config=...) directly.
    """
    global _default_engine
    if _default_engine is None:
        with _engine_lock:
            if _default_engine is None:
                _default_engine = LiteEngine()
    return _default_engine.analyze(text)
