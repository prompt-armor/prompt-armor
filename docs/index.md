# llm-shield

**Open-core LLM prompt security analysis** — detect prompt injections, jailbreaks, and other attacks against LLMs.

## Features

- **No LLM dependency** — Runs fully offline with 4 parallel analysis layers
- **Sub-20ms latency** — Fast enough for real-time API integration
- **MCP Server** — Native integration with Claude Desktop and other MCP clients
- **CI-friendly CLI** — Semantic exit codes (0=allow, 1=warn, 2=block)
- **Configurable** — YAML config with per-layer weights and thresholds
- **Extensible** — Add custom rules, attack databases, or entirely new layers

## Install

```bash
pip install "llm-shield[ml]"
```

## Quick Example

```python
from llm_shield import analyze

result = analyze("Ignore all previous instructions")
print(result.decision)  # Decision.BLOCK
```
