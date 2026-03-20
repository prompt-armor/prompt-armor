# Benchmark

## Running

```bash
python tests/benchmark/run_benchmark.py
python tests/benchmark/run_benchmark.py --output results.json
```

## Current Results (v0.1.1)

Dataset: 258 benign + 97 malicious (355 total) from deepset/prompt-injections, TrustAIRLab/in-the-wild-jailbreak-prompts, Lakera/gandalf, and hand-curated samples.

**Held-out test set (30%, never seen during training):**

| Metric | Value |
|--------|-------|
| Precision | 93.3% |
| Recall | 96.6% |
| F1 Score | 93.0% |

**Full dataset:**

| Metric | Value |
|--------|-------|
| Accuracy | 91.8% |
| Precision | 79.8% |
| Recall | 93.8% |
| F1 Score | 86.3% |
| Avg Latency | ~19ms |
| P95 Latency | ~41ms |

## Methodology

The meta-classifier fusion is trained on 70% of the data and validated on a held-out 30% test set to prevent overfitting. Layer coefficients for L3 (similarity) and L4 (structural) are clamped to non-negative values to prevent adversarial exploitation.

The benchmark includes attacks in English, German, Spanish, French, and Portuguese, covering 8 attack categories.

## Retraining the Meta-Classifier

If you change the layers or dataset, retrain the fusion:

```bash
python scripts/dump_layer_scores.py
python scripts/train_fusion.py
```

Then update the `_META_COEFS` in `src/llm_shield/fusion.py` with the new coefficients.

## Dataset

The benchmark dataset is in `tests/benchmark/dataset/`:

- `benign.jsonl` — 258 safe prompts (coding questions, general knowledge, multilingual)
- `malicious.jsonl` — 97 attack prompts (injections, jailbreaks, exfiltration, etc.)

Format:
```json
{"text": "the prompt", "label": "benign|malicious", "category": "optional_category"}
```

## Contributing Samples

PRs with new attack patterns or benign edge cases are welcome. See [CONTRIBUTING.md](../CONTRIBUTING.md).
