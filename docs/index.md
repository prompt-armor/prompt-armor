# prompt-armor

**Open-core LLM prompt security analysis** — detect prompt injections, jailbreaks, and other attacks against LLMs.

## Features

- **5 parallel analysis layers** — regex, ML classifier, contrastive semantic similarity, structural analysis, anomaly detection
- **Trained meta-classifier fusion** — learned optimal layer combination from benchmark data
- **~34ms latency** — fast enough for real-time API integration
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

F1: **91.1%** | Recall: 98.1% | Precision: 85.0% | Latency: ~34ms | Attack DB: 25,160 entries
