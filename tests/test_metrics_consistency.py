"""CI guard: F1 / latency claims stay consistent across all live surfaces.

After reconciling the docs to one canonical framing, this test prevents the
8-different-F1-numbers drift from creeping back. It scans the *live claim*
surfaces only — NOT the CHANGELOG or the dated blog post (legitimate historical
records) and NOT docs/layers.md (per-layer technical latencies).

Canonical framing (decided 2026-06): F1 86.9% internal (1,534-sample) /
98.87% external (jayavibhav, same-distribution). Latency ~24ms warm.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).parent.parent

# Surfaces that make user-facing metric claims.
_LIVE_FILES = [
    "README.md",
    "CLAUDE.md",
    "docs/index.md",
    "docs/benchmark.md",
    "docs/quickstart.md",
    "integrations/openclaw-plugin/openclaw.plugin.json",
    "integrations/openclaw-plugin/skills/prompt-armor/SKILL.md",
    "integrations/openclaw/SKILL.md",
    "integrations/openclaw-plugin/package.json",
    "integrations/openclaw-plugin/README.md",
    "integrations/openclaw-plugin/src/index.ts",
]

# The ONLY F1 figures allowed in live surfaces.
_CANONICAL_F1 = {"86.9", "98.87"}

# Stale headline latencies that the reconciliation removed. (Competitor latencies
# like ~50ms / ~100ms in the comparison table are fine — hence a denylist, not an
# "everything must be 24ms" allowlist.)
_STALE_LATENCY = ["~21ms", "~27ms", "~20ms", "~30ms"]

# F1-labelled percentage, prefix ("F1 ... 86.9%") or suffix ("91.7% F1") form.
# The prefix form stops at the first "%" so it never swallows a trailing
# "| Precision 94.6%" on the same line.
_F1_PREFIX = re.compile(r"F1[^0-9%]{0,15}?(\d{2}(?:\.\d+)?)%")
_F1_SUFFIX = re.compile(r"(\d{2}(?:\.\d+)?)%\s*F1\b")


def _existing_live_files():
    return [p for p in (_ROOT / f for f in _LIVE_FILES) if p.exists()]


@pytest.mark.parametrize("path", _existing_live_files(), ids=lambda p: str(p.relative_to(_ROOT)))
def test_f1_claims_are_canonical(path):
    text = path.read_text()
    found = _F1_PREFIX.findall(text) + _F1_SUFFIX.findall(text)
    bad = sorted({n for n in found if n not in _CANONICAL_F1})
    assert not bad, (
        f"{path.relative_to(_ROOT)} cites non-canonical F1 {bad}. "
        f"Use only {sorted(_CANONICAL_F1)} (86.9% internal / 98.87% external)."
    )


@pytest.mark.parametrize("path", _existing_live_files(), ids=lambda p: str(p.relative_to(_ROOT)))
def test_no_stale_headline_latency(path):
    text = path.read_text()
    present = [s for s in _STALE_LATENCY if s in text]
    assert not present, f"{path.relative_to(_ROOT)} cites stale latency {present}; the canonical warm latency is ~24ms."


def test_canonical_numbers_are_actually_present():
    """Sanity: the README must contain both canonical F1 figures (guards a typo'd allowlist)."""
    readme = (_ROOT / "README.md").read_text()
    assert "86.9%" in readme and "98.87%" in readme
