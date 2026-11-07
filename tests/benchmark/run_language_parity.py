#!/usr/bin/env python3
"""Language parity check: false positives and detection per language.

0.9.2's L2 model scored ordinary Portuguese as injection (0.95-1.00 on "Quero
cancelar minha assinatura") while the same sentences in English scored 0.00, and
nothing in CI looked at non-English benign text, so the bias shipped silently
(see CHANGELOG 0.9.4). This runs the full engine over parallel benign and attack
texts in EN/PT/ES/DE/FR and fails if another language is blocked noticeably more
often than English, or if attacks in it are caught noticeably less often.

Dataset (``tests/benchmark/dataset/language_parity.jsonl``; sources and licenses
in ``tests/benchmark/dataset/LANGUAGE_PARITY.md``):
- ``smb``: hand-written small-business messages and tool outputs, EN and PT-BR
  translations of each other, plus injections (direct and planted in the same data);
- ``massive``: the same assistant commands in five languages (Amazon MASSIVE);
- ``yanis``: multilingual prompt injections (yanismiraoui/prompt_injections).

Usage:
    python tests/benchmark/run_language_parity.py
    python tests/benchmark/run_language_parity.py --output parity.json
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys
from collections import defaultdict
from pathlib import Path

os.environ["TOKENIZERS_PARALLELISM"] = "false"
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)

DATASET = Path(__file__).parent / "dataset" / "language_parity.jsonl"
_EXPECTED_LAYERS = ("l1_regex", "l2_classifier", "l3_similarity", "l4_structural", "l5_negative_selection")
LANGS = ("en", "pt", "es", "de", "fr")


def run(dataset: Path = DATASET, allow_degraded: bool = False) -> dict:
    from prompt_armor.engine import LiteEngine

    rows = [json.loads(line) for line in dataset.read_text().splitlines() if line.strip()]

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        engine = LiteEngine()
    finally:
        sys.stdout = old_stdout
    missing = sorted(set(_EXPECTED_LAYERS) - set(engine.active_layers))
    if (missing or engine.degraded_layers) and not allow_degraded:
        engine.close()
        sys.exit(f"Error: missing layers {missing}, degraded layers {engine.degraded_layers}; refusing to report.")

    # counts[(label, lang)] = [n, flagged (warn or block), blocked]
    counts: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0])
    for row in rows:
        decision = engine.analyze(row["text"]).decision.value
        for key in ((row["label"], row["lang"]), (row["label"], f"{row['lang']}/{row['set']}")):
            c = counts[key]
            c[0] += 1
            c[1] += decision != "allow"
            c[2] += decision == "block"
    engine.close()

    return {
        f"{label}:{lang}": {"n": n, "flagged": round(fl / n, 4), "blocked": round(bl / n, 4)}
        for (label, lang), (n, fl, bl) in sorted(counts.items())
    }


def check(results: dict, max_fp_gap: float, max_detection_gap: float) -> list[str]:
    """Return the parity violations: each language against English, on the whole dataset."""
    failures = []
    en_benign = results["benign:en"]["blocked"]
    en_attack = results["attack:en"]["blocked"]
    for lang in LANGS[1:]:
        benign = results.get(f"benign:{lang}")
        attack = results.get(f"attack:{lang}")
        if benign and benign["blocked"] > en_benign + max_fp_gap:
            failures.append(
                f"{lang}: {benign['blocked']:.1%} of benign texts blocked vs {en_benign:.1%} in English "
                f"(allowed gap {max_fp_gap:.0%})"
            )
        if attack and attack["blocked"] < en_attack - max_detection_gap:
            failures.append(
                f"{lang}: {attack['blocked']:.1%} of attacks blocked vs {en_attack:.1%} in English "
                f"(allowed gap {max_detection_gap:.0%})"
            )
    return failures


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="prompt-armor language parity check")
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--output", type=Path, help="Output JSON file")
    parser.add_argument("--allow-degraded", action="store_true")
    parser.add_argument("--max-fp-gap", type=float, default=0.05, help="Max extra benign block rate vs English")
    parser.add_argument("--max-detection-gap", type=float, default=0.10, help="Max attack block rate below English")
    args = parser.parse_args()

    results = run(args.dataset, args.allow_degraded)
    print(f"{'':16s} {'n':>5s} {'flagged':>8s} {'blocked':>8s}")
    for key, r in results.items():
        print(f"{key:16s} {r['n']:5d} {r['flagged']:8.1%} {r['blocked']:8.1%}")
    if args.output:
        args.output.write_text(json.dumps(results, indent=2))

    failures = check(results, args.max_fp_gap, args.max_detection_gap)
    if failures:
        print("\nLanguage parity FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\nLanguage parity OK")


if __name__ == "__main__":
    main()
