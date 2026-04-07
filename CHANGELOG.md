# Changelog

All notable changes to prompt-armor will be documented in this file.

## [Unreleased] — dev

### Added
- **Auto-download models from HuggingFace Hub** — L3 ONNX (contrastive embeddings, 113MB) and L5 (IsolationForest pickle) auto-download on first use via `huggingface-hub`. Zero manual setup.
- **Dockerfile** — `python:3.12-slim` with all 5 layers pre-loaded. `docker build -t prompt-armor . && docker run prompt-armor analyze "test"`.
- **Autoexperiment runner** (`scripts/autoexperiment.py`) — autonomous parameter optimization inspired by karpathy/autoresearch. Random search over fusion coefficients, thresholds, and L1 regex weights. ~300 experiments/hr, JSONL logging, resumable state, graceful shutdown.
- **Strategic reports** — commercialization vs open-source market analysis and complete project status/roadmap (`docs/reports/`).
- **`AnalyticsCollector.flush()`** — deterministic queue drain for reliable testing.

### Changed
- Meta-classifier `n_above_0.1` coefficient optimized 0.7463 → 0.6936 via 500-experiment autoexperiment run
- F1: 0.9222 → **0.9353** (+1.31%), precision 0.8649 → **0.8933** (+2.84%), 6 fewer FPs

### Fixed
- Dockerfile installs from source (not PyPI) for full 5-layer auto-download support
- Collector test flaky on CI — replaced `time.sleep()` with deterministic `flush()` calls

## [0.6.0] - 2026-03-23

### Added
- **L3 ONNX export** — eliminates PyTorch (~2GB) from runtime. Model quantized INT8 (449MB → 113MB). Runtime uses onnxruntime + tokenizers only.
- **Adversarial test suite** — 46 evasion prompts across 8 categories (regex, classifier, similarity, structural, anomaly, compound, council meta-injection, benign controls). 94.4% adversarial recall.
- **28 new unit tests** — test_council.py (19): parser, sanitizer, veto logic, config. test_collector.py (9): write, schema, migration, council fields.
- `scripts/export_l3_onnx.py` — one-time ONNX export + INT8 quantization

### Changed
- Meta-classifier retrained with L5 as proper feature (10 features, was 9)
- F1: 91.38% → **91.69%**
- Recall: 98.15% → **98.77%** (only 2 FN!)
- Latency: ~34ms → **~27ms** (ONNX L3 is faster than sentence-transformers)
- Install size: ~2.3GB → **~50MB** (torch eliminated from runtime)
- Cold start: ~5s → **~1s**
- `sentence-transformers` moved from `[ml]` to `[dev]` deps (training only)

### Fixed
- All ruff lint errors (variable naming, import sort, f-strings)
- All mypy type errors (0 errors in strict mode)

## [0.5.1] - 2026-03-22

### Fixed
- **Security**: SQL interpolation eliminated in dashboard timeline query
- **Security**: Council prompt meta-injection hardened (hash nonce + sanitize)
- **Security**: Inflammation state thread-safe (threading.Lock)
- **Security**: atexit handler dedup (WeakSet, single registration)
- **Performance**: Collector batched commits (every 100 records)
- **CI**: Split lint/test jobs, add timeouts, small attack DB for CI
- **CI**: All mypy errors resolved (35 → 0)
- **CI**: All ruff format/lint errors resolved
- **CI**: L3 detection tests skip on truncated DB
- **CI**: L2 test thresholds relaxed for cross-platform compat
- **Docs**: CLAUDE.md 4→5 layers, CONTRIBUTING.md PRs target dev

## [0.5.0] - 2026-03-22

### Added
- **Council mode** — optional LLM judge (ollama/phi3:mini) for uncertain cases with veto power, configurable fallback (warn/block), provider abstraction for future OpenRouter
- **L5 Negative Selection** — Isolation Forest anomaly detection trained on 5,000 benign prompts, catches zero-day attacks via text pattern deviation, <1ms inference
- **Attack DB 4.5x expansion** — 5,540 → 25,160 entries from 10 sources (SaTML CTF, LLMail-Inject, SafeGuard, jackhhao)
- **FAISS IVFFlat** — O(sqrt(n)) search for 25K+ vectors, keeps latency <20ms
- **Dashboard: council verdicts** — council judgment, reasoning, model, latency in all views
- **Dashboard: configurable refresh** — off/1s/2s/5s/10s/30s/60s, starts paused
- **Dashboard: local timezone** — timestamps converted to user's browser timezone
- **Dashboard: council transitions** — shows actual decision changes (e.g., warn → block)
- `lite_decision` field tracks original Lite decision before council override
- `scripts/train_l5_model.py` — trains L5 anomaly model (~1min)

### Changed
- F1: 89.7% → **91.1%**
- Recall: 93.8% → **98.1%** (only 3 out of 162 attacks pass)
- Precision: 85.9% → 85.0%
- L3 coefficient now positive (+3.0) in meta-classifier
- Avg latency: ~34ms (from ~27ms, 5 layers + larger DB)
- Version aligned across pyproject.toml, _version.py, dashboard (was mismatched)

### Fixed
- Missing `Decision` import in engine `_run_council` fallback (would crash)
- OllamaProvider model matching (substring → exact prefix)
- CLI config template threshold (0.3 → 0.55 matching actual default)
- Benchmark now writes to analytics dashboard (was disabled by default)

## [0.3.0] - 2026-03-21

### Added
- **Contrastive L3 fine-tuning** — embeddings match by intent, not topic. Cross-similarity (attack↔benign) reduced from 0.053 to -0.021
- **Attack DB expansion** — 1,151 → 5,540 entries from SaTML CTF 2024, LLMail-Inject, ProtectAI validation set
- **Instruction-data boundary detection** (L4) — parses sentences as INSTRUCTION/DATA, detects injections in data zones
- **Manipulation stack detector** (L4) — counts Cialdini's 6 persuasion principles with non-linear scoring
- **Shannon entropy** (L4) — detects encoding tricks via character distribution anomaly
- **Threshold jitter** — per-request gaussian noise (σ=0.03) prevents adversarial threshold optimization
- **Inflammation cascade** — session-level threat awareness with exponential decay catches iterative probing
- **Analytics dashboard** — Next.js + SQLite with terminal CRT theme (real-time feed, timeline, detail view)
- **OpenClaw integration** — skill for ClawHub + plugin with hooks, tool, and skill dual-stack
- **Benchmark expanded** — 355 → 515 samples (353 benign + 162 malicious) with held-out evaluation
- `scripts/train_l3_contrastive.py` — contrastive fine-tuning pipeline (~50min CPU)
- `engine.reset_session()` — clears inflammation state for new sessions

### Changed
- F1: 85% → **89.7%** (+4.7 points)
- Recall: 88% → **93.8%** (+5.5 points)
- Precision: 82% → **85.9%** (+3.7 points)
- L3 uses fine-tuned model when available, falls back to base
- Meta-classifier threshold: 0.56 (with per-request jitter)
- Avg latency: ~27ms (from ~19ms, due to larger attack DB)

## [0.1.1] - 2026-03-20

### Security
- Thread-safe singleton initialization (double-checked locking) — fixes race condition
- Context manager support on LiteEngine (`with LiteEngine() as engine:`)
- atexit handler for ThreadPoolExecutor cleanup — prevents thread leaks
- Fail-open layer setup — broken layers are disabled instead of crashing the engine
- Fix `concurrent.futures.TimeoutError` handling on Python 3.10
- Pin L2 model download by commit SHA — supply chain hardening
- Remove `trust_remote_code=True` from all dataset scripts
- Path traversal validation on `rules_path` / `attacks_path` in config
- Scrub PII from known_attacks.jsonl (emails, usernames)
- Fix ReDoS patterns (JB-003 bounded quantifier, DE-003 backtracking)
- Fix overly broad ML-ES-003 Spanish pattern (require 'ahora' prefix)

### Changed
- Frozen dataclasses now use `tuple` instead of `list` for true immutability
- Shared `CATEGORY_MAP` in models.py (DRY: was duplicated in L1 and L3)
- Shared `ShieldResult.to_dict()` method (DRY: was duplicated in CLI and MCP)
- Pre-compiled fiction/educational context patterns in L1 (was recompiling per call)
- Replace `assert isinstance` with proper `TypeError` raises
- CI triggers on `dev` branch, uses correct Python version from matrix
- Catch `Exception` (not just `ImportError`) when loading optional layers

### Added
- `ShieldResult.to_dict()` method for JSON serialization
- `LiteEngine.__enter__` / `__exit__` context manager protocol
- Input type validation (`TypeError` on non-str input)
- Git workflow documentation in CLAUDE.md

## [0.1.0] - 2026-03-19

### Added
- 4-layer parallel analysis engine (L1 Regex, L2 DeBERTa Classifier, L3 Semantic Similarity, L4 Structural)
- Trained logistic regression meta-classifier for score fusion
- Sliding window segmentation for compound injection detection
- Unicode NFKC normalization + zero-width character stripping
- Multilingual regex rules (DE, ES, FR, PT)
- Multilingual embedding model (paraphrase-multilingual-MiniLM-L12-v2) for L3
- CLI with `analyze`, `scan`, `config` commands and semantic exit codes
- MCP Server with `analyze_prompt` tool
- Per-layer timeout (2s) and fail-open error handling
- Input length guard (50K chars) and segment cap (10)
- Public benchmark dataset (258 benign + 97 malicious from deepset, TrustAIRLab, Lakera Gandalf)
- YAML configuration (`.prompt-armor.yml`)
- 103 tests (unit + integration)
- GitHub Actions CI (tests, benchmark, publish)

### Benchmark Results
- Held-out F1: 93.0% (30% test set, never seen during training)
- Full dataset: Precision 79.8%, Recall 93.8%, F1 86.3%
- Average latency: ~19ms
