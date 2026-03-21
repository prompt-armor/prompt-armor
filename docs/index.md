# prompt-armor

**Open-core LLM prompt security analysis** — detect prompt injections, jailbreaks, and other attacks against LLMs.

## Features

- **4 parallel analysis layers** — regex, ML classifier, contrastive semantic similarity, structural analysis
- **Trained meta-classifier fusion** — learned optimal layer combination from benchmark data
- **~27ms latency** — fast enough for real-time API integration
- **Fully offline** — no API keys, no LLM dependency, no network calls during analysis
- **Multilingual** — EN, DE, ES, FR, PT regex rules + multilingual embeddings
- **Session awareness** — inflammation cascade catches iterative probing attacks
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

F1: **89.7%** | Recall: 93.8% | Precision: 85.9% | Latency: ~27ms | Attack DB: 5,540 entries
