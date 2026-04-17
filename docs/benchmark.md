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

### Internal benchmark

Dataset: 353 benign + 162 malicious (515 total) from deepset/prompt-injections, TrustAIRLab/in-the-wild-jailbreak-prompts, SaTML CTF 2024, LLMail-Inject, ProtectAI, SafeGuard, jackhhao, Lakera/gandalf, and hand-curated samples.

| Metric | Value |
|--------|-------|
| Accuracy | 94.2% |
| Precision | 95.8% |
| Recall | 85.2% |
| F1 Score | **90.2%** |
| Avg Latency | ~21ms |
| FP / FN | 6 / 24 |

> Note: internal benchmark has 162 curated attacks with some edge cases not represented in the training anchor pool. External eval (jayavibhav 327K) is more representative of production traffic — that's where v0.8.0 shows its dramatic improvement.

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
