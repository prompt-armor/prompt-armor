# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

prompt-armor is an open-core LLM prompt security analysis tool. It detects prompt injections, jailbreaks, and other attacks against LLMs. The Lite engine runs 4 analysis layers in parallel, fuses scores via a trained meta-classifier, and returns decisions in ~19ms offline.

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
mypy src/prompt_armor/

# CLI
prompt-armor analyze "some prompt"
prompt-armor analyze --file prompt.txt --json
prompt-armor scan --dir ./prompts/ --format table

# Benchmark
python tests/benchmark/run_benchmark.py

# MCP Server
prompt-armor-mcp

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
- **`config.py`** — Pydantic models for YAML config (`.prompt-armor.yml`).

### Key conventions

- **dataclass for output types, Pydantic for config only**
- **Layers are CPU-bound** — ThreadPoolExecutor (not asyncio) because ONNX/FAISS/numpy release the GIL
- **Public API is `prompt_armor.analyze()`** — lazy-initialized in `__init__.py`
- **CLI exit codes** — 0=allow, 1=warn, 2=block, 3=error
- **MCP server is Python** — Uses `mcp` SDK (FastMCP)
- **Meta-classifier coefficients are hardcoded in fusion.py** — retrain via `scripts/train_fusion.py` if layers or dataset change
- **L2 model auto-downloads** — from HuggingFace Hub on first use (~83MB)

### Data files

- `data/rules/default_rules.yml` — L1 regex rules (EN + DE/ES/FR/PT)
- `data/attacks/known_attacks.jsonl` — L3 attack DB (1,151 entries)
- `data/models/` — L2 ONNX model (auto-downloaded, not in git)

## Git Workflow (MANDATORY)

### Branches
| Branch | Role |
|--------|------|
| `main` | Production — never commit directly |
| `dev` | Staging — receives merges from feature branches via PR |
| `feature/*`, `fix/*`, `refactor/*`, `chore/*`, `docs/*` | Work branches — always branch from `dev` |
| `hotfix/*` | Emergency fixes — branch from `main`, PR to `main`, then sync `dev` |

### Flow
1. Branch from `dev`: `git checkout dev && git pull && git checkout -b feature/name`
2. Atomic commits with Conventional Commits: `type(scope): description`
3. Push and PR to `dev`: `git push -u origin feature/name && gh pr create --base dev`
4. Squash merge feature → dev
5. When ready for release: PR `dev` → `main` with merge commit (not squash)
6. Tag on `main`: `git tag -a vX.Y.Z -m "..."` && `git push origin vX.Y.Z`

### Commit Format
```
type(scope): description in English, imperative mood, no period
```
Types: `feat`, `fix`, `refactor`, `style`, `docs`, `test`, `chore`, `perf`, `ci`

### Strict Rules
- NEVER commit directly to `main` or `dev`
- NEVER force-push to `main`
- NEVER PR a feature directly to `main` (only hotfix)
- Squash merge: `feature/*` → `dev`
- Merge commit: `dev` → `main`
- One commit = one logical change
