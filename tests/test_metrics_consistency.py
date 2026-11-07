"""CI guard: F1 / latency claims stay consistent across all live surfaces.

After reconciling the docs to one canonical framing, this test prevents the
8-different-F1-numbers drift from creeping back. It scans the *live claim*
surfaces only — NOT the CHANGELOG or the dated blog post (legitimate historical
records) and NOT docs/layers.md (per-layer technical latencies).

Canonical framing (decided 2026-06, re-measured for 0.9.4 after the L2 model
swap to a multilingual classifier): F1 86.6% internal (1,534-sample, CI) / 95.08%
external (jayavibhav, same-distribution). Latency ~17ms warm average (Apple M4).
The out-of-sample validation figure (86.7%, scripts/eval_holdout.py) is also allowed.
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
    "SECURITY.md",
    "Dockerfile",
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

# F1 figures allowed in live surfaces: the two canonical headline numbers, plus
# 86.7 (the out-of-sample validation figure, scripts/eval_holdout.py, cited next
# to the in-sample one to prove it is not leakage-inflated, and the Apple M2 Pro
# result) and 86.8 (the higher CI run; L3 is still INT8). 86.6% / 95.08% are THE headline
# (enforced present below). Superseded figures (82.9 / 98.22 /
# 84.2 from 0.9.2-0.9.3's English-only L2; 84.4 / 85.5 / 98.87 from the withdrawn
# 0.9.1 model; 56.3 from its keyword fallback) belong in the CHANGELOG only.
_HEADLINE_F1 = {"86.6", "95.08"}
# Disclosed next to the headline in docs/benchmark.md and README.md, about the
# attacks the L2 model saw in training: 83.7 is the in-sample F1 without the 119
# jailbreak-classification attacks (79.2 for 0.9.3 on the same subset); 89.4 is what
# training the fusion on them would score, 89.8 / 88.5 the F1 on the attacks L2 had
# not seen without and with that, and 90.7 the held-out F1 without them.
_CANONICAL_F1 = _HEADLINE_F1 | {"86.7", "86.8", "83.7", "79.2", "89.4", "89.8", "88.5", "90.7"}

# Stale headline latencies that the reconciliation removed. (Competitor latencies
# like ~50ms / ~100ms in the comparison table are fine — hence a denylist, not an
# "everything must be 50ms" allowlist.)
_STALE_LATENCY = ["~21ms", "~24ms", "~27ms", "~20ms", "~30ms", "~19ms"]

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
        f"Use only {sorted(_CANONICAL_F1)} (86.6% in-sample / 86.7% held-out / 95.08% external, plus the L2 overlap disclosures)."
    )


@pytest.mark.parametrize("path", _existing_live_files(), ids=lambda p: str(p.relative_to(_ROOT)))
def test_no_stale_headline_latency(path):
    text = path.read_text()
    present = [s for s in _STALE_LATENCY if s in text]
    assert not present, (
        f"{path.relative_to(_ROOT)} cites stale latency {present}; the canonical warm latency is ~17ms (Apple M4)."
    )


def test_canonical_numbers_are_actually_present():
    """Sanity: the README must contain both canonical F1 figures (guards a typo'd allowlist)."""
    readme = (_ROOT / "README.md").read_text()
    assert "86.6%" in readme and "95.08%" in readme
