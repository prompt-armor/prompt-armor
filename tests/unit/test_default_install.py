"""Packaging regression guard: the ML detection layers must ship by default.

`pip install prompt-armor` used to omit the L2/L3/L5 ML layers — they lived behind
an optional `[ml]` extra. But the fusion meta-classifier is trained expecting those
scores, so a base install silently under-scored attacks and returned ALLOW on a
textbook injection ("Ignore all previous instructions ..."), contradicting the
README's own BLOCK example. This test locks the ML packages into the CORE dependency
set so that footgun can't return — regardless of which extras CI happens to install
(the behavioural test env always installs `[ml]`, so only metadata inspection catches
a move back to an extra).
"""

from __future__ import annotations

from importlib.metadata import requires

# Distribution names as they appear in Requires-Dist.
_ML_PACKAGES = ("onnxruntime", "tokenizers", "faiss-cpu", "scikit-learn", "huggingface-hub")


def _core_requirements() -> list[str]:
    """Installed requirements with NO `extra == "..."` marker — i.e. non-optional."""
    return [r for r in (requires("prompt-armor") or []) if "extra ==" not in r]


def test_ml_layers_are_core_dependencies():
    core = " ".join(_core_requirements()).lower()
    missing = [p for p in _ML_PACKAGES if p.lower() not in core]
    assert not missing, (
        f"{missing} must be CORE dependencies, not optional extras. Without them "
        "`pip install prompt-armor` omits the ML layers and the fusion classifier "
        "silently under-scores real attacks (textbook injection -> ALLOW)."
    )
