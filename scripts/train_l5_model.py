#!/usr/bin/env python3
"""Train the L5 Negative Selection anomaly detection model.

Collects benign prompts from multiple HuggingFace datasets + local benchmark,
extracts 11 text features, and trains an Isolation Forest that learns what
"normal" prompts look like. Anomalous inputs (potential zero-day attacks)
score high.

Usage:
    python scripts/train_l5_model.py
    python scripts/train_l5_model.py --max-samples 5000
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

MODEL_OUTPUT = Path(__file__).parent.parent / "src" / "prompt_armor" / "data" / "models" / "l5_negative_selection.pkl"
BENCHMARK_BENIGN = Path(__file__).parent.parent / "tests" / "benchmark" / "dataset" / "benign.jsonl"


def collect_benign_texts(max_samples: int = 5000) -> list[str]:
    """Collect benign texts from multiple sources."""
    texts: list[str] = []
    seen: set[str] = set()

    def add(text: str, source: str) -> None:
        text = text.strip()
        if len(text) < 10:
            return
        key = hashlib.sha256(text.lower().encode()).hexdigest()[:16]
        if key not in seen:
            seen.add(key)
            texts.append(text)

    # 1. Local benchmark
    if BENCHMARK_BENIGN.exists():
        with open(BENCHMARK_BENIGN) as f:
            for line in f:
                entry = json.loads(line.strip())
                add(entry.get("text", ""), "benchmark")
        print(f"  benchmark: {len(texts)} benign")

    # 2. xTRam1/safe-guard-prompt-injection (label=0)
    try:
        from datasets import load_dataset

        for split in ["train", "test"]:
            ds = load_dataset("xTRam1/safe-guard-prompt-injection", split=split)
            count = 0
            for row in ds:
                if row.get("label", 1) == 0:
                    add(row.get("text", ""), "safeguard")
                    count += 1
            print(f"  safeguard/{split}: {count} benign")
    except Exception as e:
        print(f"  safeguard: failed ({e})")

    # 3. protectai splits
    try:
        from datasets import load_dataset

        for split_name in ["not_inject", "wildguard", "deepset"]:
            try:
                ds = load_dataset("protectai/prompt-injection-validation", split=split_name)
                count = 0
                for row in ds:
                    label = row.get("label", 1)
                    if label == 0:
                        text = row.get("text", "") or row.get("prompt", "")
                        add(text, f"protectai/{split_name}")
                        count += 1
                print(f"  protectai/{split_name}: {count} benign")
            except Exception:
                pass
    except Exception as e:
        print(f"  protectai: failed ({e})")

    # 4. deepset/prompt-injections (label=0)
    try:
        from datasets import load_dataset

        ds = load_dataset("deepset/prompt-injections", split="train")
        count = 0
        for row in ds:
            if row.get("label", 1) == 0:
                add(row.get("text", ""), "deepset")
                count += 1
        print(f"  deepset: {count} benign")
    except Exception as e:
        print(f"  deepset: failed ({e})")

    print(f"\n  Total unique benign: {len(texts)}")

    # Cap with stratified sampling by length for diversity
    if len(texts) > max_samples:
        texts.sort(key=len)
        step = len(texts) / max_samples
        texts = [texts[int(i * step)] for i in range(max_samples)]
        print(f"  Sampled to: {len(texts)}")

    return texts


def train(max_samples: int = 5000) -> None:
    """Train Isolation Forest on benign text features."""
    from sklearn.ensemble import IsolationForest

    from prompt_armor.layers.l5_negative_selection import _extract_l5_features

    print("=" * 60)
    print("L5 Negative Selection — Training")
    print("=" * 60)

    # Collect data
    print("\n1. Collecting benign texts...")
    texts = collect_benign_texts(max_samples)

    # Extract features
    print("\n2. Extracting features...")
    features = np.array([_extract_l5_features(t) for t in texts], dtype=np.float32)
    print(f"   Feature matrix: {features.shape}")

    # Print feature stats
    feature_names = [
        "word_count",
        "char_count",
        "sentence_count",
        "avg_word_length",
        "avg_sentence_length",
        "imperative_verb_ratio",
        "question_mark_ratio",
        "special_char_density",
        "shannon_entropy",
        "uppercase_ratio",
        "unique_word_ratio",
    ]
    print("\n   Feature statistics:")
    for i, name in enumerate(feature_names):
        col = features[:, i]
        print(f"     {name:25s}: mean={col.mean():.3f}  std={col.std():.3f}  min={col.min():.3f}  max={col.max():.3f}")

    # Train
    print("\n3. Training Isolation Forest...")
    model = IsolationForest(
        n_estimators=100,
        max_samples=min(512, len(texts)),
        contamination=0.01,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(features)

    # Compute normalization bounds
    raw_scores = model.decision_function(features)
    score_min = float(raw_scores.min())
    score_max = float(raw_scores.max())
    print(f"   Raw score range: [{score_min:.4f}, {score_max:.4f}]")

    # Show distribution
    normalized = (score_min - raw_scores) / (score_min - score_max)
    normalized = np.clip(normalized, 0, 1)
    print(f"   Normalized: mean={normalized.mean():.3f}  std={normalized.std():.3f}")
    print(f"   Samples > 0.5 (anomalous in training): {(normalized > 0.5).sum()}/{len(normalized)}")

    # Save
    import joblib

    MODEL_OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    model_data = {
        "model": model,
        "score_min": score_min,
        "score_max": score_max,
        "feature_names": feature_names,
        "n_training_samples": len(texts),
    }
    joblib.dump(model_data, MODEL_OUTPUT)
    print(f"\n4. Saved to {MODEL_OUTPUT}")
    print(f"   File size: {MODEL_OUTPUT.stat().st_size / 1024:.0f} KB")

    print("\n" + "=" * 60)
    print("DONE")
    print("=" * 60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train L5 Negative Selection model")
    parser.add_argument("--max-samples", type=int, default=5000)
    args = parser.parse_args()
    train(max_samples=args.max_samples)
