# Benchmark

## Running

```bash
python tests/benchmark/run_benchmark.py
python tests/benchmark/run_benchmark.py --output results.json
```

## Current Results

Dataset: 353 benign + 162 malicious (515 total) from deepset/prompt-injections, TrustAIRLab/in-the-wild-jailbreak-prompts, SaTML CTF 2024, LLMail-Inject, ProtectAI, SafeGuard, jackhhao, Lakera/gandalf, and hand-curated samples.

**Full dataset:**

| Metric | Value |
|--------|-------|
| Accuracy | 95.73% |
| Precision | 89.3% |
| Recall | 98.2% |
| F1 Score | **93.5%** |
| Avg Latency | ~27ms |
| P95 Latency | ~209ms |
| Adversarial Recall | 94.4% (43/46 evasion prompts) |

## Methodology

5 analysis layers run in parallel. A trained logistic regression meta-classifier fuses layer scores with interaction features. Layer coefficients are clamped to non-negative values to prevent adversarial exploitation.

L3 uses a contrastive fine-tuned embedding model (TripletLoss) that matches by intent rather than topic. L5 uses an Isolation Forest trained on 5,000 benign prompts to detect anomalous text patterns.

The benchmark includes attacks in English, German, Spanish, French, and Portuguese, covering 8 attack categories. Attack DB: 25,160 entries from 10 sources.

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
