# Benchmark

## Running

```bash
python tests/benchmark/run_benchmark.py
python tests/benchmark/run_benchmark.py --output results.json
```

## Current Results (v0.9.4)

### External evaluation (jayavibhav/prompt-injection) — real-world distribution

Evaluated on 1,000 samples (308 attacks, 692 benign) from the [jayavibhav/prompt-injection](https://huggingface.co/datasets/jayavibhav/prompt-injection) dataset (327K total, public on HuggingFace).

| Metric | Value |
|--------|-------|
| Accuracy | 97.0% |
| Precision | **96.0%** |
| Recall | 94.2% |
| F1 Score | **95.08%** |
| FP / FN | 12 / 18 |
| L3-only FPs | 0 |

Lower than 0.9.3 (98.22% on Apple M4; 97.91% with 9 FP / 4 FN on the Apple M2 Pro where 0.9.4 was measured): the English-only L2 that 0.9.4 replaced fit this dataset better. 0.9.4 also loses a little on the benchmark's own jayavibhav attacks (recall 97.6% → 94.7%).

### Internal benchmark v2 (expanded to 1,534 samples)

Dataset: 969 benign + 565 malicious (1,534 total) from deepset/prompt-injections (train+test), wildjailbreak, jackhhao/jailbreak-classification, JailbreakBench, jayavibhav/prompt-injection (train split only — test is reserved for external eval), lmsys/toxic-chat (benign hard negatives), and hand-curated samples.

| Metric | Value |
|--------|-------|
| Accuracy | 90.7% |
| Precision | 91.6% |
| Recall | 82.5% |
| F1 Score | **86.8%** |
| Avg Latency | ~17ms (warm, quiet Apple M4; median ~6ms; 0.9.3 on the same machine: ~31ms / ~13ms). CI runner (4 vCPU): ~54ms, 0.9.3 ~112ms |
| FP / FN | 43 / 99 |

Measured by the CI `Benchmark` workflow (Linux x86, GitHub-hosted runner), which re-runs it on every push to `main`. L2 now computes in FP32 (only its embedding table is INT8) and gives the same scores on x86 and ARM (600 of 600 decisions identical in a cross-architecture check); L3's embedding model is still dynamic INT8, so the figure still moves by a tenth or two across CPU types: 86.8% (43 FP / 99 FN) on the CI runner, 86.7% (100 FN) on Apple M2 Pro, 86.6% (101 FN) on Apple M4. The out-of-sample, external, per-source and language figures on this page were measured on Apple M2 Pro.

Recall by source (Apple M2 Pro, 0.9.3 → 0.9.4): jayavibhav 97.6% → 94.7%, jailbreak-classification 95.0% → 95.0%, deepset test 62.7% → 72.9%, JailbreakBench 6% → 35%, hand-crafted (encoding, compound, indirect, multilingual) 100% → 100%.

> **How to read these two numbers.** The **internal 86.8%** is the harder, canonical figure — but it is *in-sample*: fusion thresholds/coefficients are tuned on this benchmark, and L3's benign discrimination is trained on this set's benigns. The **external 95.08%** is *in-distribution*, not generalization: the internal benchmark and L3 training draw from jayavibhav's train split, so it should be read as an upper bound. Benchmark↔attack-DB overlap is low (~1.9%, guarded by `tests/test_no_leakage.py`). The held-out counterpart is measured (see **Out-of-sample validation** below): a cluster-aware split with the threshold picked on train only scores **86.7% ± 1.5%**, within a tenth of in-sample. L2 adds a training-data overlap of its own, found by exact text match against the datasets its authors list: all 119 `jackhhao/jailbreak-classification` attacks, 70 of the 100 JailbreakBench ones and 11 of the 247 jayavibhav ones. The fusion is trained without the first two sources (`train_fusion.py`, `L2_TRAINING_OVERLAP`); training on them too would score 89.4% in-sample, but with 75 false positives instead of 43 and a lower F1 on the attacks L2 had not seen (88.5% vs 89.8%). Excluding the 119 jackhhao attacks, in-sample F1 is **83.7%** (0.9.3 on the same subset: 79.2%). Most of the 100 FN are JailbreakBench harmful-behavior requests, which the L2 model deliberately labels safe when they carry no override attempt. Decisions are deterministic (no threshold jitter) and the benchmark is **single-shot** — an earlier internal 86.9% was inflated by per-session inflammation accumulating across the benchmark run (now isolated per session, so it no longer leaks across prompts or tenants).

### Languages

[`tests/benchmark/run_language_parity.py`](../tests/benchmark/run_language_parity.py) runs the full engine over 864 texts in five languages (`tests/benchmark/dataset/language_parity.jsonl`; sources and licenses in [`LANGUAGE_PARITY.md`](../tests/benchmark/dataset/LANGUAGE_PARITY.md)): small-business messages and tool outputs written in English and Brazilian Portuguese, the same 100 Amazon MASSIVE assistant commands in each language, and 40 public prompt injections per language. The `Benchmark` workflow runs it on every pull request and fails if a language's benign texts are blocked more than 5 points above English, or its attacks more than 10 points below.

| Apple M2 Pro | EN | PT | ES | DE | FR |
|--|--|--|--|--|--|
| Benign blocked, 0.9.3 | 7.9% | **30.9%** | 20.0% | 13.0% | 11.0% |
| Benign blocked, 0.9.4 | 7.2% | **5.3%** | 3.0% | 4.0% | 4.0% |
| Attacks blocked, 0.9.3 | 81.4% | 95.7% | 92.5% | 92.5% | 95.0% |
| Attacks blocked, 0.9.4 | 84.3% | 95.7% | 92.5% | 92.5% | 95.0% |

0.9.3 fails the check; its English-only L2 scored ordinary Portuguese as injection. The English-Portuguese part was written while choosing 0.9.4's L2, so it is a regression guard rather than an independent measurement; MASSIVE and the public injections are third-party.

### Out-of-sample validation (leakage audit)

The internal 86.8% is *in-sample*: the shipped fusion coefficients and decision threshold are tuned on this benchmark. To check whether that inflates the number, [`scripts/eval_holdout.py`](../scripts/eval_holdout.py) measures the honest out-of-sample counterpart:

- **Cluster-aware split** — benchmark samples are grouped into near-duplicate clusters (token-Jaccard ≥ 0.85, union-find) and split by *whole cluster* into 70% train / 30% holdout, so no held-out sample has a near-twin in train.
- **Threshold on train only** — the fusion logistic-regression is retrained on the train split and the decision threshold is chosen by out-of-fold cross-validation on train, *never* on the holdout (which `train_fusion.py` does — a subtle leak this avoids).
- **Same exclusion as the shipped fusion** — attacks from the sources in L2's training data are never in the train split.
- Averaged over **10 random splits** to damp the noise of a single 30% holdout.

| Metric (held-out, 10 splits) | Value |
|--------|-------|
| **F1** | **86.7% ± 1.5%** |
| Precision | 92.9% ± 2.6% |
| Recall | 81.4% ± 1.7% |
| F1 without the sources in L2's training data | 90.7% ± 2.0% |
| Recall on **out-of-DB** attacks (zero-day) | 81.0% ± 1.8% |
| Recall on **in-DB** attacks (11 samples, memorizable) | 100% |

The out-of-sample result **matches the in-sample 86.8% within a tenth** — the benchmark is **not materially inflated by the fusion tuning**.

**One caveat this cannot remove without an L3 retrain:** the L3 contrastive model was trained with the benchmark benigns as negatives (a precision-side leak). The **out-of-DB recall (81%)** is the cleanest zero-day proxy available without that retrain; a fully clean number is tracked as a heavier follow-up.

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

# Retrain meta-classifier (leaves out the benchmark sources in L2's training data)
python scripts/dump_layer_scores.py
python scripts/train_fusion.py

# Check false positives and detection per language
python tests/benchmark/run_language_parity.py
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
