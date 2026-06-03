# Benchmark

## Running

```bash
python tests/benchmark/run_benchmark.py
python tests/benchmark/run_benchmark.py --output results.json
```

## Current Results (v0.8.0)

### External evaluation (jayavibhav/prompt-injection) — real-world distribution

Evaluated on 1,000 samples (308 attacks, 692 benign) from the [jayavibhav/prompt-injection](https://huggingface.co/datasets/jayavibhav/prompt-injection) dataset (327K total, public on HuggingFace).

| Metric | Value |
|--------|-------|
| Accuracy | 99.3% |
| Precision | **98.4%** |
| Recall | 99.4% |
| F1 Score | **98.87%** |
| FP / FN | 5 / 2 |
| L3-only FPs | 0 |

### Internal benchmark v2 (expanded to 1,534 samples)

Dataset: 969 benign + 565 malicious (1,534 total) from deepset/prompt-injections (train+test), wildjailbreak, jackhhao/jailbreak-classification, JailbreakBench, jayavibhav/prompt-injection (train split only — test is reserved for external eval), lmsys/toxic-chat (benign hard negatives), and hand-curated samples.

| Metric | Value |
|--------|-------|
| Accuracy | 89.6% |
| Precision | 94.5% |
| Recall | 76.3% |
| F1 Score | **84.4%** |
| Avg Latency | ~24ms (warm) |
| FP / FN | 25 / 134 |

> **How to read these two numbers.** The **internal 84.4%** is the harder, canonical figure — but it is *in-sample*: fusion thresholds/coefficients are currently tuned directly on this benchmark (no holdout), and L3's benign discrimination is trained on this set's benigns. The **external 98.87%** is *in-distribution*, not generalization: the internal benchmark and L3 training draw from jayavibhav's train split, so it should be read as an upper bound. Benchmark↔attack-DB overlap is low (~1.9%, guarded by `tests/test_no_leakage.py`). A held-out, out-of-distribution number is tracked for v0.9. The 134 FN are edge-case attacks under analysis. Decisions are deterministic (no threshold jitter) and the benchmark is **single-shot** — an earlier internal 86.9% was inflated by per-session inflammation accumulating across the benchmark run (now isolated per session, so it no longer leaks across prompts or tenants).

## Methodology

5 analysis layers run in parallel. A trained logistic regression meta-classifier fuses layer scores with interaction features. Layer coefficients are clamped to non-negative values to prevent adversarial exploitation. Isotonic calibration of `confidence` field (ECE 0.0).

L3 uses a contrastive fine-tuned embedding model (MiniLM-L12-v2, TripletLoss + mined hard negatives) that matches by intent rather than topic. Cross-similarity attack↔benign is **-0.063** (points in opposite directions). L5 uses an Isolation Forest trained on 5,000 benign prompts to detect anomalous text patterns.

The benchmark includes attacks in English, German, Spanish, French, and Portuguese, covering 8 attack categories. Attack DB v2: 1,509 high-specificity entries (curated from 25,160 via semantic dedup).

## Retraining

If you change layers or datasets:

```bash
# Retrain L3 contrastive embeddings (~70min on CPU)
python scripts/train_l3_contrastive.py

# Retrain L5 anomaly model (~1min)
python scripts/train_l5_model.py

# Retrain meta-classifier
python scripts/dump_layer_scores.py
python scripts/train_fusion.py
```

Then update `_META_COEFS` in `src/prompt_armor/fusion.py` with the new coefficients.

## Dataset

The benchmark dataset is in `tests/benchmark/dataset/`:

- `benign.jsonl` — 353 safe prompts (coding questions, general knowledge, multilingual, hard negatives)
- `malicious.jsonl` — 162 attack prompts (injections, jailbreaks, exfiltration, encoding, multilingual)

Format:
```json
{"text": "the prompt", "label": "benign|malicious", "category": "optional_category"}
```

## Contributing Samples

PRs with new attack patterns or benign edge cases are welcome. See [CONTRIBUTING.md](../CONTRIBUTING.md).
