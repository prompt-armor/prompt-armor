# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

prompt-armor is an open-core LLM prompt security analysis tool. It detects prompt injections, jailbreaks, and other attacks against LLMs. The Lite engine runs 5 analysis layers in parallel, fuses scores via a trained meta-classifier, and returns decisions in ~27ms offline. F1: 93.5% on 515-sample benchmark.

## Commands

```bash
# Install (editable, with all extras)
pip install -e ".[dev,ml,mcp]"

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

# Rebuild attack database from public sources (25K+ entries)
python scripts/build_attack_db.py --max-per-source 20000

# Contrastive fine-tune L3 embeddings (~50min on CPU)
python scripts/train_l3_contrastive.py
```

## Architecture

```
INPUT → NORMALIZE → SEGMENT (if >150 words) → [L1 | L2 | L3 | L4 | L5] → META-CLASSIFIER → GATE (+jitter) → OUTPUT
                                                                                  ↑                        ↓
                                                                          inflammation cascade      Council (optional)
```

The core pipeline runs 5 analysis layers **in parallel** via `ThreadPoolExecutor`, feeds scores into a trained logistic regression meta-classifier, and applies decision thresholds with per-request jitter:

- **`engine.py` (LiteEngine)** — Orchestrates: Unicode normalization, sliding window segmentation, parallel layer dispatch, per-layer timeout (2s) with fail-open. **Inflammation cascade**: session-level threat awareness with exponential decay.
- **`layers/l1_regex.py`** — 40+ English + 20 multilingual (DE/ES/FR/PT) weighted regex rules. Context modifier exploit hardened (high scores not dampened).
- **`layers/l2_classifier.py`** — DeBERTa-v3-xsmall (22M params, ONNX) with score calibration. Auto-downloads from HuggingFace on first use. Falls back to keyword heuristic.
- **`layers/l3_similarity.py`** — **Contrastive fine-tuned** MiniLM-L12-v2 + FAISS IVF cosine similarity against 25,160 known attacks. Intent-based matching (not topic-based).
- **`layers/l4_structural.py`** — Instruction-data boundary detection, manipulation stack (Cialdini's 6 principles), Shannon entropy, delimiter injection, encoding tricks, role assignment.
- **`layers/l5_negative_selection.py`** — Isolation Forest anomaly detection trained on 5K benign prompts. Catches zero-day attacks via deviation from normal text patterns.
- **`fusion.py`** — Trained LogisticRegression meta-classifier (9 features). Threshold jitter (σ=0.03) prevents adversarial optimization. L3/L4 raw coefficients clamped to 0.
- **`models.py`** — Frozen dataclasses: `ShieldResult`, `LayerResult`, `Evidence`, `Decision`, `Category`.
- **`config.py`** — Pydantic models for YAML config (`.prompt-armor.yml`).
- **`collector.py`** — SQLite analytics writer with WAL mode, background thread, non-blocking queue.
- **`council.py`** — Optional LLM judge for uncertain cases. Provider abstraction (ollama v1, OpenRouter future). Anti-injection hardened prompt template.

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
- `data/attacks/known_attacks.jsonl` — L3 attack DB (25,160 entries)
- `data/models/` — L2 ONNX model (auto-downloaded) + L3 contrastive model (trained locally, not in git)

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
