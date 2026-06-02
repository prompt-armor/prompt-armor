# prompt-armor

**Open-core LLM prompt security analysis** — detect prompt injections, jailbreaks, and other attacks against LLMs.

## Features

- **5 parallel analysis layers** — regex, ML classifier, contrastive semantic similarity, structural analysis, anomaly detection
- **Trained meta-classifier fusion** — learned optimal layer combination from benchmark data
- **~24ms latency (warm)** — fast enough for real-time API integration
- **Fully offline** — no API keys, no LLM dependency, no network calls during analysis
- **Multilingual** — EN, DE, ES, FR, PT regex rules + multilingual embeddings
- **Session awareness** — inflammation cascade catches iterative probing attacks
- **Council mode** — optional LLM judge (ollama) for uncertain cases
- **MCP Server** — native integration with Claude Desktop and other MCP clients
- **CI-friendly CLI** — semantic exit codes (0=allow, 1=warn, 2=block)
- **Security hardened** — threshold jitter, per-layer timeout, fail-open, Unicode normalization, supply chain pinning

## Install

```bash
pip install "prompt-armor[ml]"
```

## Quick Example

```python
from prompt_armor import analyze

result = analyze("Ignore all previous instructions")
print(result.decision)  # Decision.BLOCK
```

## Benchmark

We report **two numbers** — the harder internal benchmark and the same-distribution external one.

**Internal (1,534 samples, harder):** F1 **86.9%** | Precision 94.6% | Recall 80.4% | Latency ~24ms (warm)

**External (jayavibhav/prompt-injection 1K):** F1 **98.87%** | Precision 98.4% | Recall 99.4% — in-distribution (shares jayavibhav's train split), treat as an upper bound, not generalization

Attack DB v2: 1,509 high-specificity entries. L3 contrastive fine-tuned with 2.4K hard negatives.
