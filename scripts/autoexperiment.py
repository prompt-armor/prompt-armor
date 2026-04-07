#!/usr/bin/env python3
"""Autonomous experiment runner for prompt-armor optimization.

Inspired by karpathy/autoresearch: iteratively proposes parameter changes,
benchmarks each one, and keeps improvements while reverting regressions.
Runs overnight, ~30s per iteration, logs everything to JSONL.

Usage:
    python scripts/autoexperiment.py
    python scripts/autoexperiment.py --max-iterations 500 --skip-l5
    python scripts/autoexperiment.py --types fusion_coefs,fusion_threshold
    python scripts/autoexperiment.py --resume
"""

from __future__ import annotations

import argparse
import copy
import io
import json
import logging
import os
import random
import signal
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Suppress noisy output from deps
os.environ["TOKENIZERS_PARALLELISM"] = "false"
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
logging.getLogger("prompt_armor").setLevel(logging.WARNING)

SCRIPT_DIR = Path(__file__).parent
DATASET_DIR = SCRIPT_DIR.parent / "tests" / "benchmark" / "dataset"
DEFAULT_LOG = SCRIPT_DIR / "autoexperiment_results.jsonl"
DEFAULT_STATE = SCRIPT_DIR / "autoexperiment_state.json"

COEF_NAMES = [
    "l1_regex",
    "l2_classifier",
    "l3_similarity",
    "l4_structural",
    "l5_negative_selection",
    "max_score",
    "min_score",
    "l1_x_l4",
    "l2_x_l3",
    "n_above_0.1",
]

# Experiment type schedule weights (threshold:coefs:l1)
_SCHEDULE = ["fusion_threshold", "fusion_threshold",
             "fusion_coefs", "fusion_coefs", "fusion_coefs",
             "l1_weights", "l1_weights"]


@dataclass
class Metrics:
    """Benchmark metrics subset for comparison."""

    f1: float = 0.0
    recall: float = 0.0
    precision: float = 0.0
    accuracy: float = 0.0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0


@dataclass
class ExperimentResult:
    """Result of a single experiment."""

    experiment_id: int
    timestamp: str
    experiment_type: str
    description: str
    params: dict
    baseline: dict
    result: dict
    delta_f1: float
    delta_recall: float
    accepted: bool
    duration_s: float
    cumulative_best_f1: float


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def _load_dataset(path: Path) -> list[dict]:
    """Load a JSONL dataset."""
    samples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def run_quick_benchmark(engine, dataset_dir: Path = DATASET_DIR) -> Metrics:
    """Lightweight benchmark that reuses an existing engine instance.

    Same logic as tests/benchmark/run_benchmark.py but without prints,
    analytics, or engine construction overhead.
    """
    benign = _load_dataset(dataset_dir / "benign.jsonl")
    malicious = _load_dataset(dataset_dir / "malicious.jsonl")
    threshold = 0.50

    m = Metrics()

    # Benign samples (expecting low scores)
    engine.reset_session()
    for sample in benign:
        try:
            result = engine.analyze(sample["text"])
            if result.risk_score < threshold:
                m.tn += 1
            else:
                m.fp += 1
        except Exception:
            pass

    # Malicious samples (expecting high scores)
    engine.reset_session()
    for sample in malicious:
        try:
            result = engine.analyze(sample["text"])
            if result.risk_score >= threshold:
                m.tp += 1
            else:
                m.fn += 1
        except Exception:
            pass

    total = m.tp + m.tn + m.fp + m.fn
    if total > 0:
        m.accuracy = round((m.tp + m.tn) / total, 4)
    if m.tp + m.fp > 0:
        m.precision = round(m.tp / (m.tp + m.fp), 4)
    if m.tp + m.fn > 0:
        m.recall = round(m.tp / (m.tp + m.fn), 4)
    if m.precision + m.recall > 0:
        m.f1 = round(2 * m.precision * m.recall / (m.precision + m.recall), 4)

    return m


# ---------------------------------------------------------------------------
# Override mechanisms
# ---------------------------------------------------------------------------

class FusionOverride:
    """Context manager to temporarily replace fusion module globals."""

    def __init__(
        self,
        coefs: list[float] | None = None,
        intercept: float | None = None,
        threshold: float | None = None,
    ):
        self._new_coefs = coefs
        self._new_intercept = intercept
        self._new_threshold = threshold
        self._saved_coefs = None
        self._saved_intercept = None
        self._saved_threshold = None

    def __enter__(self):
        import prompt_armor.fusion as fusion_mod

        self._saved_coefs = list(fusion_mod._META_COEFS)
        self._saved_intercept = fusion_mod._META_INTERCEPT
        self._saved_threshold = fusion_mod._META_THRESHOLD

        if self._new_coefs is not None:
            fusion_mod._META_COEFS = list(self._new_coefs)
        if self._new_intercept is not None:
            fusion_mod._META_INTERCEPT = self._new_intercept
        if self._new_threshold is not None:
            fusion_mod._META_THRESHOLD = self._new_threshold
        return self

    def __exit__(self, *args):
        import prompt_armor.fusion as fusion_mod

        fusion_mod._META_COEFS = self._saved_coefs
        fusion_mod._META_INTERCEPT = self._saved_intercept
        fusion_mod._META_THRESHOLD = self._saved_threshold


def apply_fusion_state(coefs: list[float], intercept: float, threshold: float) -> None:
    """Persistently apply fusion overrides (for accepted experiments)."""
    import prompt_armor.fusion as fusion_mod

    fusion_mod._META_COEFS = list(coefs)
    fusion_mod._META_INTERCEPT = intercept
    fusion_mod._META_THRESHOLD = threshold


def get_l1_layer(engine):
    """Find L1RegexLayer instance from engine."""
    for layer in engine._layers:
        if layer.name == "l1_regex":
            return layer
    return None


# ---------------------------------------------------------------------------
# Experiment generators
# ---------------------------------------------------------------------------

def gen_threshold_experiment(current_threshold: float, temperature: float) -> tuple[str, dict]:
    """Generate a threshold perturbation."""
    delta = random.gauss(0, 0.03 * temperature)
    new_val = max(0.30, min(0.70, current_threshold + delta))
    new_val = round(new_val, 3)
    desc = f"Threshold {current_threshold:.3f} → {new_val:.3f}"
    return desc, {"threshold": new_val, "old_threshold": current_threshold}


def gen_coef_experiment(current_coefs: list[float], temperature: float) -> tuple[str, dict]:
    """Generate a coefficient perturbation."""
    idx = random.randint(0, len(current_coefs) - 1)
    old_val = current_coefs[idx]
    delta = random.gauss(0, 0.08 * temperature)
    new_val = max(0.0, min(3.0, old_val + delta))
    new_val = round(new_val, 4)
    desc = f"Coef {COEF_NAMES[idx]} {old_val:.4f} → {new_val:.4f}"
    return desc, {"index": idx, "name": COEF_NAMES[idx], "old": old_val, "new": new_val}


def gen_l1_weight_experiment(engine, temperature: float) -> tuple[str, dict]:
    """Generate an L1 regex weight perturbation."""
    l1 = get_l1_layer(engine)
    if l1 is None or not l1._rules:
        return "No L1 rules", {}
    rule = random.choice(l1._rules)
    old_val = rule.weight
    delta = random.gauss(0, 0.05 * temperature)
    new_val = max(0.10, min(1.0, old_val + delta))
    new_val = round(new_val, 4)
    desc = f"L1 rule {rule.id} weight {old_val:.4f} → {new_val:.4f}"
    return desc, {"rule_id": rule.id, "old": old_val, "new": new_val}


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def save_state(path: Path, state: dict) -> None:
    """Atomically save state to JSON file."""
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    tmp.rename(path)


def load_state(path: Path) -> dict | None:
    """Load state from JSON file if it exists."""
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

class ExperimentRunner:
    """Autonomous experiment loop."""

    def __init__(self, args):
        self.max_iterations: int = args.max_iterations
        self.recall_floor: float = args.recall_floor
        self.log_path: Path = Path(args.log)
        self.state_path: Path = Path(args.state)
        self.skip_l5: bool = args.skip_l5
        self.temperature: float = args.temperature
        self.types: set[str] = set(args.types.split(",")) if args.types != "all" else {
            "fusion_threshold", "fusion_coefs", "l1_weights"
        }
        self.resume: bool = args.resume
        self.seed: int | None = args.seed

        # State
        self.current_coefs: list[float] = []
        self.current_intercept: float = 0.0
        self.current_threshold: float = 0.0
        self.l1_weight_overrides: dict[str, float] = {}
        self.best_f1: float = 0.0
        self.best_recall: float = 0.0
        self.experiment_id: int = 0
        self.engine = None
        self._shutdown = False

    def run(self) -> None:
        """Main experiment loop."""
        if self.seed is not None:
            random.seed(self.seed)

        # Register signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        # Initialize fusion state
        import prompt_armor.fusion as fusion_mod

        self.current_coefs = list(fusion_mod._META_COEFS)
        self.current_intercept = fusion_mod._META_INTERCEPT
        self.current_threshold = fusion_mod._META_THRESHOLD

        # Resume from state if requested
        if self.resume:
            state = load_state(self.state_path)
            if state:
                self.current_coefs = state.get("fusion_coefs", self.current_coefs)
                self.current_intercept = state.get("fusion_intercept", self.current_intercept)
                self.current_threshold = state.get("fusion_threshold", self.current_threshold)
                self.l1_weight_overrides = state.get("l1_weight_overrides", {})
                self.experiment_id = state.get("iterations_completed", 0)
                self.best_f1 = state.get("best_f1", 0.0)
                self.best_recall = state.get("best_recall", 0.0)
                print(f"Resumed from state: {self.experiment_id} iterations, best F1={self.best_f1:.4f}")

        # Apply current best state
        apply_fusion_state(self.current_coefs, self.current_intercept, self.current_threshold)

        # Create engine
        print("Initializing engine...")
        self.engine = self._create_engine()
        self._apply_l1_overrides()

        # Baseline benchmark
        print("Running baseline benchmark...")
        baseline = run_quick_benchmark(self.engine)
        self.best_f1 = max(self.best_f1, baseline.f1)
        self.best_recall = baseline.recall

        print(f"Baseline: F1={baseline.f1:.4f} Recall={baseline.recall:.4f} "
              f"Precision={baseline.precision:.4f} (TP={baseline.tp} FP={baseline.fp} "
              f"TN={baseline.tn} FN={baseline.fn})")
        print(f"Starting {self.max_iterations} experiments "
              f"(types: {', '.join(sorted(self.types))})")
        print("-" * 70)

        total_accepted = 0
        start_time = time.time()

        for i in range(self.max_iterations):
            if self._shutdown:
                print("\nShutting down gracefully...")
                break

            self.experiment_id += 1
            exp_type = self._pick_type(i)
            t0 = time.time()

            if exp_type == "fusion_threshold":
                accepted = self._run_threshold_experiment(baseline)
            elif exp_type == "fusion_coefs":
                accepted = self._run_coef_experiment(baseline)
            elif exp_type == "l1_weights":
                accepted = self._run_l1_experiment(baseline)
            else:
                continue

            duration = time.time() - t0
            if accepted:
                total_accepted += 1
                # Re-benchmark to update baseline
                baseline = run_quick_benchmark(self.engine)

            self.temperature *= 0.995  # Decay

            if (i + 1) % 10 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed * 3600
                print(f"  [{i+1}/{self.max_iterations}] "
                      f"accepted={total_accepted} best_f1={self.best_f1:.4f} "
                      f"temp={self.temperature:.3f} rate={rate:.0f}/hr")

        # Summary
        elapsed = time.time() - start_time
        print("=" * 70)
        print(f"DONE: {self.experiment_id} experiments in {elapsed:.0f}s")
        print(f"Accepted: {total_accepted}")
        print(f"Best F1: {self.best_f1:.4f} (recall={self.best_recall:.4f})")
        print(f"Log: {self.log_path}")
        print(f"State: {self.state_path}")

        if self.engine:
            self.engine.close()

    def _create_engine(self):
        """Create a LiteEngine with suppressed output."""
        from prompt_armor.config import ShieldConfig
        from prompt_armor.engine import LiteEngine

        config = ShieldConfig()
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            engine = LiteEngine(config=config)
        finally:
            sys.stdout = old_stdout
        print(f"Active layers: {engine.active_layers}")
        return engine

    def _apply_l1_overrides(self) -> None:
        """Apply saved L1 weight overrides to engine."""
        if not self.l1_weight_overrides:
            return
        l1 = get_l1_layer(self.engine)
        if l1 is None:
            return
        for rule in l1._rules:
            if rule.id in self.l1_weight_overrides:
                rule.weight = self.l1_weight_overrides[rule.id]

    def _pick_type(self, iteration: int) -> str:
        """Pick experiment type via round-robin schedule."""
        available = [t for t in _SCHEDULE if t in self.types]
        if not available:
            return list(self.types)[0]
        return available[iteration % len(available)]

    def _run_threshold_experiment(self, baseline: Metrics) -> bool:
        """Run a fusion threshold experiment."""
        desc, params = gen_threshold_experiment(self.current_threshold, self.temperature)
        if not params:
            return False

        with FusionOverride(threshold=params["threshold"]):
            result = run_quick_benchmark(self.engine)

        accepted = self._accept(baseline, result)
        if accepted:
            self.current_threshold = params["threshold"]
            apply_fusion_state(self.current_coefs, self.current_intercept, self.current_threshold)
            self._save_state()

        self._log_result("fusion_threshold", desc, params, baseline, result, accepted)
        return accepted

    def _run_coef_experiment(self, baseline: Metrics) -> bool:
        """Run a fusion coefficient experiment."""
        desc, params = gen_coef_experiment(self.current_coefs, self.temperature)
        if not params:
            return False

        new_coefs = list(self.current_coefs)
        new_coefs[params["index"]] = params["new"]

        with FusionOverride(coefs=new_coefs):
            result = run_quick_benchmark(self.engine)

        accepted = self._accept(baseline, result)
        if accepted:
            self.current_coefs = new_coefs
            apply_fusion_state(self.current_coefs, self.current_intercept, self.current_threshold)
            self._save_state()

        self._log_result("fusion_coefs", desc, params, baseline, result, accepted)
        return accepted

    def _run_l1_experiment(self, baseline: Metrics) -> bool:
        """Run an L1 regex weight experiment."""
        desc, params = gen_l1_weight_experiment(self.engine, self.temperature)
        if not params:
            return False

        # Apply weight change
        l1 = get_l1_layer(self.engine)
        rule = None
        for r in l1._rules:
            if r.id == params["rule_id"]:
                rule = r
                break
        if rule is None:
            return False

        rule.weight = params["new"]
        result = run_quick_benchmark(self.engine)
        accepted = self._accept(baseline, result)

        if accepted:
            self.l1_weight_overrides[params["rule_id"]] = params["new"]
            self._save_state()
        else:
            # Revert
            rule.weight = params["old"]

        self._log_result("l1_weights", desc, params, baseline, result, accepted)
        return accepted

    def _accept(self, baseline: Metrics, result: Metrics) -> bool:
        """Accept if F1 improved and recall stays above floor."""
        return result.f1 > baseline.f1 and result.recall >= self.recall_floor

    def _log_result(
        self,
        exp_type: str,
        desc: str,
        params: dict,
        baseline: Metrics,
        result: Metrics,
        accepted: bool,
    ) -> None:
        """Append experiment result to JSONL log."""
        if accepted and result.f1 > self.best_f1:
            self.best_f1 = result.f1
            self.best_recall = result.recall

        symbol = "✓" if accepted else "✗"
        delta = result.f1 - baseline.f1
        print(f"  {symbol} [{self.experiment_id}] {desc} "
              f"F1: {baseline.f1:.4f}→{result.f1:.4f} ({delta:+.4f}) "
              f"R: {result.recall:.4f}")

        entry = ExperimentResult(
            experiment_id=self.experiment_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            experiment_type=exp_type,
            description=desc,
            params=params,
            baseline=asdict(baseline),
            result=asdict(result),
            delta_f1=round(result.f1 - baseline.f1, 4),
            delta_recall=round(result.recall - baseline.recall, 4),
            accepted=accepted,
            duration_s=0.0,
            cumulative_best_f1=self.best_f1,
        )

        with open(self.log_path, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def _save_state(self) -> None:
        """Save current best state atomically."""
        state = {
            "best_f1": self.best_f1,
            "best_recall": self.best_recall,
            "fusion_coefs": self.current_coefs,
            "fusion_intercept": self.current_intercept,
            "fusion_threshold": self.current_threshold,
            "l1_weight_overrides": self.l1_weight_overrides,
            "iterations_completed": self.experiment_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        save_state(self.state_path, state)

    def _handle_signal(self, signum, frame) -> None:
        """Handle shutdown signal gracefully."""
        self._shutdown = True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Autonomous experiment runner for prompt-armor optimization"
    )
    parser.add_argument("--max-iterations", type=int, default=200,
                        help="Maximum number of experiments (default: 200)")
    parser.add_argument("--log", type=str, default=str(DEFAULT_LOG),
                        help="Path to JSONL log file")
    parser.add_argument("--state", type=str, default=str(DEFAULT_STATE),
                        help="Path to state file")
    parser.add_argument("--recall-floor", type=float, default=0.98,
                        help="Minimum recall to accept a change (default: 0.98)")
    parser.add_argument("--types", type=str, default="all",
                        help="Experiment types (comma-sep): fusion_threshold,fusion_coefs,l1_weights")
    parser.add_argument("--skip-l5", action="store_true",
                        help="Skip slow L5 hyperparameter experiments")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    parser.add_argument("--temperature", type=float, default=1.0,
                        help="Perturbation magnitude (decays 0.995x/iter)")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from state file")
    args = parser.parse_args()

    runner = ExperimentRunner(args)
    runner.run()


if __name__ == "__main__":
    main()
