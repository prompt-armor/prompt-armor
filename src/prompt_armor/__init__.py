"""prompt-armor — Open-core LLM prompt security analysis."""

from __future__ import annotations

import threading

from prompt_armor._version import __version__
from prompt_armor.config import ShieldConfig
from prompt_armor.engine import LiteEngine
from prompt_armor.models import Category, Decision, Evidence, LayerResult, ShieldResult

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


def analyze(text: str, session_id: str | None = None) -> ShieldResult:
    """Analyze a prompt for security risks.

    One-call API that lazily initializes the default engine.
    Thread-safe via double-checked locking.

    Stateless by default. Pass a stable ``session_id`` (per user/connection) to
    enable per-session iterative-probing detection; state is isolated per
    session, so the shared default engine never leaks history across callers.
    For custom config, use LiteEngine(config=...) directly.
    """
    global _default_engine
    if _default_engine is None:
        with _engine_lock:
            if _default_engine is None:
                _default_engine = LiteEngine()
    return _default_engine.analyze(text, session_id=session_id)
