# Benchmark

## Running

```bash
python tests/benchmark/run_benchmark.py
python tests/benchmark/run_benchmark.py --output results.json
```

## Current Results (v0.3.0)

Dataset: 353 benign + 162 malicious (515 total) from deepset/prompt-injections, TrustAIRLab/in-the-wild-jailbreak-prompts, SaTML CTF 2024, LLMail-Inject, ProtectAI, Lakera/gandalf, and hand-curated samples.

**Full dataset:**

| Metric | Value |
|--------|-------|
| Accuracy | 93.2% |
| Precision | 85.9% |
| Recall | 93.8% |
| F1 Score | **89.7%** |
| Avg Latency | ~27ms |
| P95 Latency | ~130ms |

## Methodology

The meta-classifier fusion is trained on 70% of the data and validated on a held-out 30% test set to prevent overfitting. Layer coefficients for L3 (similarity) and L4 (structural) are clamped to non-negative values to prevent adversarial exploitation.

The benchmark includes attacks in English, German, Spanish, French, and Portuguese, covering 8 attack categories.

L3 uses a contrastive fine-tuned embedding model (TripletLoss) that matches by intent rather than topic, reducing false positives on security-related benign text.

## Retraining the Meta-Classifier

If you change the layers or dataset, retrain the fusion:

```bash
python scripts/dump_layer_scores.py
python scripts/train_fusion.py
```

Then update the `_META_COEFS` in `src/prompt_armor/fusion.py` with the new coefficients.

To retrain L3 contrastive embeddings (~50min on CPU):

```bash
python scripts/train_l3_contrastive.py
```

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
