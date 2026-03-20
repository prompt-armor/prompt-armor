# prompt-armor

**Open-core LLM prompt security analysis** — detect prompt injections, jailbreaks, and other attacks against LLMs.

## Features

- **4 parallel analysis layers** — regex, ML classifier, semantic similarity, structural analysis
- **Trained meta-classifier fusion** — learned optimal layer combination from benchmark data
- **~19ms latency** — fast enough for real-time API integration
- **Fully offline** — no API keys, no LLM dependency, no network calls during analysis
- **Multilingual** — EN, DE, ES, FR, PT regex rules + multilingual embeddings
- **MCP Server** — native integration with Claude Desktop and other MCP clients
- **CI-friendly CLI** — semantic exit codes (0=allow, 1=warn, 2=block)
- **Security hardened** — per-layer timeout, fail-open, Unicode normalization, supply chain pinning

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

Held-out F1: **93.0%** | Recall: 93.8% | Latency: ~19ms
