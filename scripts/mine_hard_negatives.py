#!/usr/bin/env python3
"""Mine hard negatives for L3 contrastive retraining.

Hard negatives = benign prompts that current L3 scores highly (false positives
at the layer level). Contrastive retraining with these explicitly teaches the
embedding model to separate them from attacks.

Pipeline:
1. Load jayavibhav/prompt-injection benign samples (5K-20K)
2. Run current engine, collect L3 scores per prompt
3. Filter: keep benign with L3 score >= threshold (hard negatives)
4. Export JSONL for train_l3_contrastive.py --hard-negatives flag

Usage:
    python scripts/mine_hard_negatives.py
    python scripts/mine_hard_negatives.py --sample 10000 --min-l3-score 0.3
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

OUTPUT = Path(__file__).parent.parent / "internal" / "hard_negatives_l3.jsonl"


def load_jayavibhav_benign(max_samples: int) -> list[str]:
    """Load benign prompts from jayavibhav/prompt-injection (label=0)."""
    from datasets import load_dataset

    print("Loading jayavibhav/prompt-injection (test split)...")
    ds = load_dataset("jayavibhav/prompt-injection", split="test", streaming=True)

    benigns: list[str] = []
    for row in ds:
        if len(benigns) >= max_samples:
            break
        if int(row.get("label", 1)) == 0:
            text = row.get("text", "").strip()
            if text and 20 < len(text) < 2000:
                benigns.append(text)
        if (len(benigns) + 1) % 1000 == 0:
            print(f"  Collected {len(benigns)} benigns...")

    print(f"  Total benigns: {len(benigns)}")
    return benigns


def load_jsonl_benign(path: Path, max_samples: int) -> list[str]:
    """Load benigns from local JSONL (format: {"text": str, "label": 0|1})."""
    benigns = []
    with open(path) as f:
        for line in f:
            if len(benigns) >= max_samples:
                break
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if int(entry.get("label", 1)) == 0:
                text = entry.get("text", "").strip()
                if text and 20 < len(text) < 2000:
                    benigns.append(text)
    print(f"  Loaded {len(benigns)} benigns from {path}")
    return benigns


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=None, help="Local JSONL (skip HF download)")
    parser.add_argument("--sample", type=int, default=10000, help="Max samples to scan")
    parser.add_argument("--min-l3-score", type=float, default=0.3, help="Min L3 score to qualify as hard negative")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()

    # Load benign samples
    if args.input:
        samples = load_jsonl_benign(args.input, args.sample)
    else:
        samples = load_jayavibhav_benign(args.sample)

    # Initialize engine
    print("\nInitializing engine...")
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        from prompt_armor.config import ShieldConfig
        from prompt_armor.engine import LiteEngine

        engine = LiteEngine(config=ShieldConfig())
    finally:
        sys.stdout = old_stdout
    print(f"Active layers: {engine.active_layers}")

    # Scan each benign for L3 score
    print(f"\nScanning {len(samples)} benigns for L3 score >= {args.min_l3_score}...")
    hard_negatives: list[dict] = []
    l3_score_distribution = []
    start = time.time()

    engine.reset_session()
    for i, text in enumerate(samples):
        try:
            result = engine.analyze(text)
            l3_score = 0.0
            for lr in result.layer_results:
                if lr.layer == "l3_similarity":
                    l3_score = lr.score
                    break
            l3_score_distribution.append(l3_score)

            if l3_score >= args.min_l3_score:
                hard_negatives.append({
                    "text": text,
                    "l3_score": round(l3_score, 4),
                    "fused_score": round(result.risk_score, 4),
                    "decision": result.decision.value,
                })
        except Exception:
            pass

        if (i + 1) % 1000 == 0:
            engine.reset_session()
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            eta = (len(samples) - i - 1) / rate if rate > 0 else 0
            print(f"  [{i+1}/{len(samples)}] hard_negs={len(hard_negatives)} "
                  f"({rate:.0f}/s, ETA {eta:.0f}s)")

    engine.close()
    elapsed = time.time() - start

    # Stats
    import numpy as np

    dist = np.array(l3_score_distribution)
    print(f"\nL3 score distribution on {len(dist)} benigns:")
    print(f"  mean: {dist.mean():.3f}")
    print(f"  median: {np.median(dist):.3f}")
    print(f"  >= 0.1: {(dist >= 0.1).sum()} ({100 * (dist >= 0.1).mean():.1f}%)")
    print(f"  >= 0.3: {(dist >= 0.3).sum()} ({100 * (dist >= 0.3).mean():.1f}%)")
    print(f"  >= 0.5: {(dist >= 0.5).sum()} ({100 * (dist >= 0.5).mean():.1f}%)")

    # Write
    args.output.parent.mkdir(exist_ok=True)
    with open(args.output, "w") as f:
        for entry in hard_negatives:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"\n{len(hard_negatives)} hard negatives written to {args.output}")
    print(f"Total time: {elapsed:.0f}s")


if __name__ == "__main__":
    main()
