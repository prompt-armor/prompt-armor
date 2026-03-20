# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

llm-shield is an open-core LLM prompt security analysis tool. It detects prompt injections, jailbreaks, and other attacks against LLMs. The Lite engine runs 4 analysis layers in parallel, fuses scores via a trained meta-classifier, and returns decisions in ~19ms offline.

## Commands

```bash
# Install (editable, with all extras)
pip install -e ".[dev,mcp]"

# Run tests
pytest tests/ -v
pytest tests/unit/ -v                    # unit only
pytest tests/unit/test_l1_regex.py -v    # single file
pytest -k "test_detects_injection" -v    # single test by name

# Lint & format
ruff check src/ tests/
ruff format src/ tests/
mypy src/llm_shield/

# CLI
llm-shield analyze "some prompt"
llm-shield analyze --file prompt.txt --json
llm-shield scan --dir ./prompts/ --format table

# Benchmark
python tests/benchmark/run_benchmark.py

# MCP Server
llm-shield-mcp

# Retrain fusion meta-classifier (after changing layers or dataset)
python scripts/dump_layer_scores.py
python scripts/train_fusion.py

# Rebuild attack database from public sources
python scripts/build_attack_db.py
```

## Architecture

```
INPUT → NORMALIZE → SEGMENT (if >150 words) → [L1 | L2 | L3 | L4] → META-CLASSIFIER → GATE → OUTPUT
```

The core pipeline runs 4 analysis layers **in parallel** via `ThreadPoolExecutor`, feeds scores into a trained logistic regression meta-classifier, and applies decision thresholds:

- **`engine.py` (LiteEngine)** — Orchestrates: Unicode normalization, sliding window segmentation, parallel layer dispatch, per-layer timeout (2s) with fail-open.
- **`layers/l1_regex.py`** — 40+ English + 20 multilingual (DE/ES/FR/PT) weighted regex rules. Context modifier exploit hardened (high scores not dampened).
- **`layers/l2_classifier.py`** — DeBERTa-v3-xsmall (22M params, ONNX) with score calibration. Auto-downloads from HuggingFace on first use. Falls back to keyword heuristic.
- **`layers/l3_similarity.py`** — paraphrase-multilingual-MiniLM-L12-v2 + FAISS cosine similarity against 1,151 known attacks.
- **`layers/l4_structural.py`** — Deterministic: imperative verb ratios, delimiter injection, encoding tricks, expanded role assignment with benign whitelist.
- **`fusion.py`** — Trained LogisticRegression meta-classifier (9 features: 4 layer scores + max + min + interactions + n_above_0.1). L3/L4 coefficients clamped to 0 to prevent exploitation.
- **`models.py`** — Frozen dataclasses: `ShieldResult`, `LayerResult`, `Evidence`, `Decision`, `Category`.
- **`config.py`** — Pydantic models for YAML config (`.llm-shield.yml`).

### Key conventions

- **dataclass for output types, Pydantic for config only**
- **Layers are CPU-bound** — ThreadPoolExecutor (not asyncio) because ONNX/FAISS/numpy release the GIL
- **Public API is `llm_shield.analyze()`** — lazy-initialized in `__init__.py`
- **CLI exit codes** — 0=allow, 1=warn, 2=block, 3=error
- **MCP server is Python** — Uses `mcp` SDK (FastMCP)
- **Meta-classifier coefficients are hardcoded in fusion.py** — retrain via `scripts/train_fusion.py` if layers or dataset change
- **L2 model auto-downloads** — from HuggingFace Hub on first use (~83MB)

### Data files

- `data/rules/default_rules.yml` — L1 regex rules (EN + DE/ES/FR/PT)
- `data/attacks/known_attacks.jsonl` — L3 attack DB (1,151 entries)
- `data/models/` — L2 ONNX model (auto-downloaded, not in git)
