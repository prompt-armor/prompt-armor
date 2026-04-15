#!/usr/bin/env python3
"""Evaluate prompt-armor on large external datasets.

Downloads and evaluates against jayavibhav/prompt-injection (327K samples)
or any JSONL dataset with {"text": str, "label": 0|1} format.

Usage:
    python scripts/eval_large_dataset.py
    python scripts/eval_large_dataset.py --sample 5000
    python scripts/eval_large_dataset.py --input custom_dataset.jsonl
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys
import time
from pathlib import Path

os.environ["TOKENIZERS_PARALLELISM"] = "false"
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
logging.getLogger("prompt_armor").setLevel(logging.WARNING)


def load_hf_dataset(split: str = "test", max_rows: int = 0) -> list[dict]:
    """Load jayavibhav/prompt-injection from HuggingFace."""
    from datasets import load_dataset

    print(f"Loading jayavibhav/prompt-injection ({split})...")
    ds = load_dataset("jayavibhav/prompt-injection", split=split, streaming=True)

    samples = []
    for i, row in enumerate(ds):
        if max_rows and i >= max_rows:
            break
        text = row.get("text", "").strip()
        label = int(row.get("label", 0))
        if not text:
            continue
        samples.append({"text": text, "label": label})
        if (i + 1) % 10000 == 0:
            print(f"  Loaded {i + 1} samples...")

    print(f"  Total: {len(samples)} samples")
    return samples


def load_jsonl_dataset(path: Path, max_rows: int = 0) -> list[dict]:
    """Load a JSONL dataset with {text, label} format."""
    samples = []
    with open(path) as f:
        for i, line in enumerate(f):
            if max_rows and i >= max_rows:
                break
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            text = entry.get("text", "").strip()
            label = int(entry.get("label", 0))
            if not text:
                continue
            samples.append({"text": text, "label": label})
    return samples


def evaluate(samples: list[dict], engine) -> dict:
    """Run engine on all samples and compute metrics."""
    tp = fp = tn = fn = 0
    l3_only_fps = 0
    threshold = 0.50
    total = len(samples)

    start = time.time()
    engine.reset_session()

    for i, sample in enumerate(samples):
        try:
            result = engine.analyze(sample["text"])
            predicted_malicious = result.risk_score >= threshold
            actual_malicious = sample["label"] == 1

            if predicted_malicious and actual_malicious:
                tp += 1
            elif predicted_malicious and not actual_malicious:
                fp += 1
                # Check if L3-only FP
                scores = {lr.layer: lr.score for lr in result.layer_results}
                l3 = scores.get("l3_similarity", 0)
                l1 = scores.get("l1_regex", 0)
                l2 = scores.get("l2_classifier", 0)
                l4 = scores.get("l4_structural", 0)
                if l3 > 0.1 and l1 < 0.1 and l2 < 0.15 and l4 < 0.1:
                    l3_only_fps += 1
            elif not predicted_malicious and not actual_malicious:
                tn += 1
            else:
                fn += 1
        except Exception:
            pass

        # Reset inflammation periodically to avoid session bias
        if (i + 1) % 1000 == 0:
            engine.reset_session()
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            eta = (total - i - 1) / rate if rate > 0 else 0
            print(f"  [{i+1}/{total}] TP={tp} FP={fp} TN={tn} FN={fn} "
                  f"({rate:.0f} samples/s, ETA {eta:.0f}s)")

    elapsed = time.time() - start

    # Compute metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / total if total > 0 else 0

    return {
        "total": total,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "l3_only_fps": l3_only_fps,
        "l3_only_fp_pct": round(l3_only_fps / fp * 100, 1) if fp > 0 else 0,
        "elapsed_s": round(elapsed, 1),
        "samples_per_s": round(total / elapsed, 1) if elapsed > 0 else 0,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate on large dataset")
    parser.add_argument("--input", type=Path, default=None,
                        help="JSONL dataset path (default: download jayavibhav/prompt-injection)")
    parser.add_argument("--sample", type=int, default=0,
                        help="Max samples to evaluate (0=all)")
    parser.add_argument("--split", type=str, default="test",
                        help="HuggingFace split (default: test)")
    parser.add_argument("--output", type=Path, default=None,
                        help="Save results to JSON file")
    args = parser.parse_args()

    # Load dataset
    if args.input:
        samples = load_jsonl_dataset(args.input, args.sample)
    else:
        samples = load_hf_dataset(args.split, args.sample)

    n_attack = sum(1 for s in samples if s["label"] == 1)
    n_benign = sum(1 for s in samples if s["label"] == 0)
    print(f"\nDataset: {len(samples)} samples ({n_attack} attacks, {n_benign} benign)")

    # Initialize engine
    print("Initializing engine...")
    from prompt_armor.config import ShieldConfig
    from prompt_armor.engine import LiteEngine

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        engine = LiteEngine(config=ShieldConfig())
    finally:
        sys.stdout = old_stdout
    print(f"Active layers: {engine.active_layers}")

    # Evaluate
    print(f"\nEvaluating {len(samples)} samples...")
    results = evaluate(samples, engine)
    engine.close()

    # Print results
    print("\n" + "=" * 60)
    print("EVALUATION RESULTS")
    print("=" * 60)
    print(f"  Dataset:     {results['total']} samples")
    print(f"  Accuracy:    {results['accuracy']:.2%}")
    print(f"  Precision:   {results['precision']:.2%}")
    print(f"  Recall:      {results['recall']:.2%}")
    print(f"  F1 Score:    {results['f1']:.2%}")
    print()
    print(f"  TP: {results['tp']}  FP: {results['fp']}")
    print(f"  TN: {results['tn']}  FN: {results['fn']}")
    print()
    print(f"  L3-only FPs: {results['l3_only_fps']} ({results['l3_only_fp_pct']}% of all FPs)")
    print(f"  Throughput:  {results['samples_per_s']} samples/s")
    print(f"  Total time:  {results['elapsed_s']}s")
    print("=" * 60)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
