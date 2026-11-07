# prompt-armor

**Open-core LLM prompt security analysis** — detect prompt injections, jailbreaks, and other attacks against LLMs.

## Features

- **5 parallel analysis layers** — regex, ML classifier, contrastive semantic similarity, structural analysis, anomaly detection
- **Trained meta-classifier fusion** — learned optimal layer combination from benchmark data
- **~17ms average latency (warm, Apple M4; median ~6ms)** — fast enough for real-time API integration
- **Fully offline** — no API keys, no LLM dependency, no network calls during analysis
- **Multilingual** — multilingual L2 classifier and embeddings, EN, DE, ES, FR, PT regex rules; false positives and detection in PT, ES, DE and FR checked against English in CI
- **Session awareness** — per-session inflammation cascade (keyed by `session_id`) catches iterative probing attacks
- **Council mode** — optional LLM judge (ollama) for uncertain cases
- **MCP Server** — native integration with Claude Desktop and other MCP clients
- **CI-friendly CLI** — semantic exit codes (0=allow, 1=warn, 2=block)
- **Security hardened** — deterministic decisions (optional downward-only jitter), per-layer timeout, fail-open, Unicode normalization, supply chain pinning

## Install

```bash
pip install prompt-armor
```

## Quick Example

```python
from prompt_armor import analyze

result = analyze("Ignore all previous instructions")
print(result.decision)  # Decision.BLOCK
```

## Benchmark

We report **two numbers** — the harder internal benchmark and the same-distribution external one.

**Internal (1,534 samples, harder):** F1 **86.6%** | Precision 91.5% | Recall 82.1% | Latency ~17ms (warm, Apple M4)

**External (jayavibhav/prompt-injection 1K):** F1 **95.08%** | Precision 96.0% | Recall 94.2% — in-distribution (shares jayavibhav's train split), treat as an upper bound, not generalization

Attack DB v2: 1,509 high-specificity entries. L3 contrastive fine-tuned with 2.4K hard negatives.
