# Benchmark

## Running

```bash
python tests/benchmark/run_benchmark.py
python tests/benchmark/run_benchmark.py --output results.json
```

## Current Results (v0.9.2)

### External evaluation (jayavibhav/prompt-injection) — real-world distribution

Evaluated on 1,000 samples (308 attacks, 692 benign) from the [jayavibhav/prompt-injection](https://huggingface.co/datasets/jayavibhav/prompt-injection) dataset (327K total, public on HuggingFace).

| Metric | Value |
|--------|-------|
| Accuracy | 98.9% |
| Precision | **98.1%** |
| Recall | 98.4% |
| F1 Score | **98.22%** |
| FP / FN | 6 / 5 |
| L3-only FPs | 0 |

### Internal benchmark v2 (expanded to 1,534 samples)

Dataset: 969 benign + 565 malicious (1,534 total) from deepset/prompt-injections (train+test), wildjailbreak, jackhhao/jailbreak-classification, JailbreakBench, jayavibhav/prompt-injection (train split only — test is reserved for external eval), lmsys/toxic-chat (benign hard negatives), and hand-curated samples.

| Metric | Value |
|--------|-------|
| Accuracy | 88.5% |
| Precision | 90.2% |
| Recall | 77.0% |
| F1 Score | **83.1%** |
| Avg Latency | ~50ms (warm, Apple M4; median ~19ms) |
| FP / FN | 47 / 130 |

> **How to read these two numbers.** The **internal 83.1%** is the harder, canonical figure — but it is *in-sample*: fusion thresholds/coefficients are currently tuned directly on this benchmark (no holdout), and L3's benign discrimination is trained on this set's benigns. The **external 98.22%** is *in-distribution*, not generalization: the internal benchmark and L3 training draw from jayavibhav's train split, so it should be read as an upper bound. Benchmark↔attack-DB overlap is low (~1.9%, guarded by `tests/test_no_leakage.py`). The held-out, out-of-distribution counterpart is now measured (see **Out-of-sample validation** below): a cluster-aware split with the threshold picked on train only scores **84.2% ± 1.5%**, within about one standard deviation of the in-sample 83.1%. L2 adds a training-data overlap of its own: Protect AI trained it on `jackhhao/jailbreak-classification`, the source of 119 of the 565 benchmark attacks; excluding those, in-sample F1 is **79.2%** (0.9.1's L2 on the same subset: 81.7%). The 130 FN are edge-case attacks under analysis; 94 of them are JailbreakBench harmful-behavior requests, which the L2 model does not target. Decisions are deterministic (no threshold jitter) and the benchmark is **single-shot** — an earlier internal 86.9% was inflated by per-session inflammation accumulating across the benchmark run (now isolated per session, so it no longer leaks across prompts or tenants).

### Out-of-sample validation (leakage audit)

The internal 83.1% is *in-sample*: the shipped fusion coefficients and decision threshold are tuned on this benchmark. To check whether that inflates the number, [`scripts/eval_holdout.py`](../scripts/eval_holdout.py) measures the honest out-of-sample counterpart:

- **Cluster-aware split** — benchmark samples are grouped into near-duplicate clusters (token-Jaccard ≥ 0.85, union-find) and split by *whole cluster* into 70% train / 30% holdout, so no held-out sample has a near-twin in train.
- **Threshold on train only** — the fusion logistic-regression is retrained on the train split and the decision threshold is chosen by out-of-fold cross-validation on train, *never* on the holdout (which `train_fusion.py` does — a subtle leak this avoids).
- Averaged over **10 random splits** to damp the noise of a single 30% holdout.

| Metric (held-out, 10 splits) | Value |
|--------|-------|
| **F1** | **84.2% ± 1.5%** |
| Precision | 86.1% ± 1.9% |
| Recall | 82.5% ± 1.5% |
| Recall on **out-of-DB** attacks (zero-day) | 82.1% ± 1.5% |
| Recall on **in-DB** attacks (11 samples, memorizable) | 100% |

The out-of-sample result is **within about one standard deviation of the in-sample 83.1%** — confirming the benchmark is **not materially inflated by leakage**. The retrained holdout classifier is F1-balanced (more recall, less precision) versus the shipped precision-leaning coefficients, which is why it lands a hair higher despite being out-of-sample; the takeaway is *the number holds*, not *the number improved*.

**One caveat this cannot remove without an L3 retrain:** the L3 contrastive model was trained with the benchmark benigns as negatives (a precision-side leak). The **out-of-DB recall (82%)** is the cleanest zero-day proxy available without that retrain; a fully clean number is tracked as a heavier follow-up.

Reproduce: `python scripts/eval_holdout.py` (runs the current engine over the benchmark, then the split → retrain → eval loop; first run caches layer scores).

## Methodology

5 analysis layers run in parallel. A trained logistic regression meta-classifier fuses layer scores with interaction features. Layer coefficients are constrained to non-negative values to prevent adversarial exploitation: features whose weight comes out negative are pinned to 0 and the rest refit (`scripts/train_fusion.py`). Isotonic calibration of `confidence` field (ECE 0.0).

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

- `benign.jsonl` — 969 safe prompts (coding questions, general knowledge, multilingual, hard negatives)
- `malicious.jsonl` — 565 attack prompts (injections, jailbreaks, exfiltration, encoding, multilingual)

Format:
```json
{"text": "the prompt", "label": "benign|malicious", "category": "optional_category"}
```

## Contributing Samples

PRs with new attack patterns or benign edge cases are welcome. See [CONTRIBUTING.md](../CONTRIBUTING.md).
