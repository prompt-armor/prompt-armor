#!/usr/bin/env python3
"""Dump per-sample layer scores for meta-classifier training.

Runs the engine on the full benchmark dataset and saves individual
layer scores alongside labels for use in training a fusion model.

Usage:
    python scripts/dump_layer_scores.py
    python scripts/dump_layer_scores.py --output scores.json
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys
from pathlib import Path

os.environ["TOKENIZERS_PARALLELISM"] = "false"
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)

BENCH_DIR = Path(__file__).parent.parent / "tests" / "benchmark" / "dataset"
DEFAULT_OUTPUT = Path(__file__).parent.parent / "scripts" / "layer_scores.json"


def dump_scores(output_path: Path) -> None:
    from prompt_armor.engine import LiteEngine

    # Suppress model loading noise
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        engine = LiteEngine()
    finally:
        sys.stdout = old_stdout

    print(f"Active layers: {engine.active_layers}")

    samples: list[dict] = []

    for path, label in [
        (BENCH_DIR / "benign.jsonl", 0),
        (BENCH_DIR / "malicious.jsonl", 1),
    ]:
        with open(path) as f:
            for line in f:
                entry = json.loads(line.strip())
                if not entry.get("text"):
                    continue

                result = engine.analyze(entry["text"])

                # Extract per-layer scores
                layer_scores = {}
                for lr in result.layer_results:
                    layer_scores[lr.layer] = lr.score

                samples.append({
                    "label": label,
                    "fused_score": result.risk_score,
                    "l1_regex": layer_scores.get("l1_regex", 0.0),
                    "l2_classifier": layer_scores.get("l2_classifier", 0.0),
                    "l3_similarity": layer_scores.get("l3_similarity", 0.0),
                    "l4_structural": layer_scores.get("l4_structural", 0.0),
                    "l5_negative_selection": layer_scores.get("l5_negative_selection", 0.0),
                    "text_preview": entry["text"][:80],
                })

    engine.close()

    with open(output_path, "w") as f:
        json.dump(samples, f, indent=2)

    # Summary
    n_pos = sum(1 for s in samples if s["label"] == 1)
    n_neg = sum(1 for s in samples if s["label"] == 0)
    print(f"\nDumped {len(samples)} samples ({n_neg} benign, {n_pos} malicious)")
    print(f"Saved to {output_path}")

    # Quick stats per layer
    for layer in ["l1_regex", "l2_classifier", "l3_similarity", "l4_structural", "l5_negative_selection"]:
        pos_scores = [s[layer] for s in samples if s["label"] == 1]
        neg_scores = [s[layer] for s in samples if s["label"] == 0]
        print(f"\n{layer}:")
        print(f"  Malicious: mean={sum(pos_scores)/len(pos_scores):.3f} max={max(pos_scores):.3f}")
        print(f"  Benign:    mean={sum(neg_scores)/len(neg_scores):.3f} max={max(neg_scores):.3f}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    dump_scores(args.output)
