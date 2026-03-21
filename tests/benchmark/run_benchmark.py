#!/usr/bin/env python3
"""Benchmark runner for prompt-armor.

Runs the analysis engine against a labeled dataset and computes
accuracy, precision, recall, F1, and latency metrics.

Usage:
    python tests/benchmark/run_benchmark.py
    python tests/benchmark/run_benchmark.py --output results.json
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Suppress noisy output
os.environ["TOKENIZERS_PARALLELISM"] = "false"
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)

DATASET_DIR = Path(__file__).parent / "dataset"


@dataclass
class BenchmarkMetrics:
    """Metrics from a benchmark run."""

    total_samples: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    total_time_s: float = 0.0
    active_layers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def load_dataset(path: Path) -> list[dict]:
    """Load a JSONL dataset."""
    samples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def run_benchmark(dataset_dir: Path | None = None, output_path: Path | None = None) -> BenchmarkMetrics:
    """Run the benchmark and return metrics."""
    dataset_dir = dataset_dir or DATASET_DIR

    benign_path = dataset_dir / "benign.jsonl"
    malicious_path = dataset_dir / "malicious.jsonl"

    if not benign_path.exists() or not malicious_path.exists():
        print(f"Error: Dataset files not found in {dataset_dir}")
        sys.exit(1)

    benign_samples = load_dataset(benign_path)
    malicious_samples = load_dataset(malicious_path)

    print(f"Dataset: {len(benign_samples)} benign + {len(malicious_samples)} malicious")
    print(f"Total: {len(benign_samples) + len(malicious_samples)} samples")
    print()

    # Initialize engine (suppress model loading output)
    from prompt_armor.engine import LiteEngine

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        engine = LiteEngine()
    finally:
        sys.stdout = old_stdout

    print(f"Active layers: {engine.active_layers}")
    print()

    metrics = BenchmarkMetrics(
        total_samples=len(benign_samples) + len(malicious_samples),
        active_layers=engine.active_layers,
    )

    latencies: list[float] = []
    start_time = time.perf_counter()

    # Threshold: score >= 0.3 is considered "malicious" prediction
    threshold = 0.65  # Meta-classifier threshold (optimized on held-out test set)

    # Test benign samples (expecting low scores)
    print("Analyzing benign samples...")
    for sample in benign_samples:
        try:
            result = engine.analyze(sample["text"])
            latencies.append(result.latency_ms)

            if result.risk_score < threshold:
                metrics.true_negatives += 1
            else:
                metrics.false_positives += 1
        except Exception as e:
            metrics.errors.append(f"Benign: {str(e)[:100]}")

    # Test malicious samples (expecting high scores)
    print("Analyzing malicious samples...")
    for sample in malicious_samples:
        try:
            result = engine.analyze(sample["text"])
            latencies.append(result.latency_ms)

            if result.risk_score >= threshold:
                metrics.true_positives += 1
            else:
                metrics.false_negatives += 1
        except Exception as e:
            metrics.errors.append(f"Malicious: {str(e)[:100]}")

    engine.close()
    metrics.total_time_s = round(time.perf_counter() - start_time, 2)

    # Compute metrics
    total_correct = metrics.true_positives + metrics.true_negatives
    if metrics.total_samples > 0:
        metrics.accuracy = round(total_correct / metrics.total_samples, 4)

    if metrics.true_positives + metrics.false_positives > 0:
        metrics.precision = round(
            metrics.true_positives / (metrics.true_positives + metrics.false_positives), 4
        )

    if metrics.true_positives + metrics.false_negatives > 0:
        metrics.recall = round(
            metrics.true_positives / (metrics.true_positives + metrics.false_negatives), 4
        )

    if metrics.precision + metrics.recall > 0:
        metrics.f1_score = round(
            2 * (metrics.precision * metrics.recall) / (metrics.precision + metrics.recall), 4
        )

    if latencies:
        latencies.sort()
        metrics.avg_latency_ms = round(sum(latencies) / len(latencies), 2)
        metrics.p95_latency_ms = round(latencies[int(len(latencies) * 0.95)], 2)
        metrics.max_latency_ms = round(max(latencies), 2)
        metrics.min_latency_ms = round(min(latencies), 2)

    # Print results
    print()
    print("=" * 60)
    print("BENCHMARK RESULTS")
    print("=" * 60)
    print(f"  Accuracy:    {metrics.accuracy:.2%}")
    print(f"  Precision:   {metrics.precision:.2%}")
    print(f"  Recall:      {metrics.recall:.2%}")
    print(f"  F1 Score:    {metrics.f1_score:.2%}")
    print()
    print(f"  TP: {metrics.true_positives}  FP: {metrics.false_positives}")
    print(f"  TN: {metrics.true_negatives}  FN: {metrics.false_negatives}")
    print()
    print(f"  Avg Latency: {metrics.avg_latency_ms:.1f}ms")
    print(f"  P95 Latency: {metrics.p95_latency_ms:.1f}ms")
    print(f"  Total Time:  {metrics.total_time_s:.1f}s")
    print("=" * 60)

    if metrics.errors:
        print(f"\n  Errors: {len(metrics.errors)}")
        for err in metrics.errors[:5]:
            print(f"    - {err}")

    # Save results
    if output_path:
        with open(output_path, "w") as f:
            json.dump(asdict(metrics), f, indent=2)
        print(f"\nResults saved to {output_path}")

    return metrics


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="prompt-armor benchmark")
    parser.add_argument("--dataset", type=Path, default=DATASET_DIR, help="Dataset directory")
    parser.add_argument("--output", type=Path, help="Output JSON file")
    args = parser.parse_args()

    run_benchmark(args.dataset, args.output)


if __name__ == "__main__":
    main()
