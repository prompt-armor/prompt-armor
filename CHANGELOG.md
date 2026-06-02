# Changelog

All notable changes to prompt-armor will be documented in this file.

## [Unreleased]

### Security
- **Fixed ReDoS (catastrophic backtracking) in L1 rules DE-001 and IB-001.** `DE-001`'s `\S+@\S+\.\S+` email matcher backtracked exponentially (a crafted ~16KB input pinned a CPU core for minutes); `IB-001`'s unbounded `\s*` runs backtracked polynomially (~590ms on a whitespace flood). Both are now linear (bounded, non-overlapping character classes). Detection of real exfiltration / delimiter-injection attacks is unchanged. This closed an unauthenticated CPU-exhaustion DoS for any service calling `analyze()` on user input.
- **L1 now matches under a hard per-search timeout** via the `regex` module (a backtracking-resistant superset of stdlib `re`). The engine's per-layer `ThreadPoolExecutor` timeout cannot preempt a GIL-holding `re` backtrack — `regex`'s `timeout=` can. A rule exceeding the budget is skipped (fail-open at the rule level), so a future ReDoS in a contributed rule can no longer hang a worker thread.
- **Pinned model revisions + sha256 verification for auto-downloaded artifacts.** L5 `joblib.load`ed an *unpinned, unverified* pickle from HuggingFace — a remote-code-execution vector on first run if the repo or account were compromised. L5 now pins the HF revision **and** verifies the file's sha256 before deserializing; L3's ONNX download is revision-pinned to match L2 (which was already pinned).

### Fixed
- **Benign false positives at the rule / L4 level** (no detection-quality regression — internal F1 86.8%→86.5%, within benchmark noise; all real EN/PT/ES/FR attack probes still BLOCK at 1.000):
  - A benign programming question (`how do I override the default behavior of __init__…`) no longer hard-BLOCKs at risk 1.000 — `override` is a normal programming verb and was wrongly double-counted as a **privilege-escalation** keyword (it stays an imperative verb, so `override your instructions` is still caught).
  - L4 no longer flags accented Latin text (ç, ã, é, ñ, ü, …) as an **encoding trick** (was scoring every DE/ES/FR/PT input 0.6). Mixed-script detection now uses a real Latin-vs-other-script check, so legitimate multilingual text passes while Cyrillic/CJK smuggling is still caught.
  - The multilingual L1 rules (`ML-PT-001`/`ML-ES-001`/`ML-FR-001`) now require a real attack noun, so benign phrases like `ignore os erros de digitação` / `ignora los errores` no longer match the regex (they previously matched on the bare verb + article).
  - Known residual (tracked): the same benign multilingual phrases are still flagged by **L2 + L3** (the ML layers semantically match injection-shaped foreign text). Fixing that needs multilingual-benign retraining, not a rule change.

### Changed
- **Reconciled all published F1/latency metrics to one canonical, honestly-labeled framing** across README, docs, `CLAUDE.md`, and the OpenClaw integration. The headline was inconsistent (F1 quoted as anything from 86.9% to 98.87% across 8+ surfaces; latency 20/21/24/27ms). Now everywhere: **F1 86.9% internal (1,534-sample, harder) / 98.87% external (jayavibhav 1K, in-distribution — upper bound, not generalization)**, latency **~24ms warm**. Both numbers are always shown, with the in-sample/in-distribution caveats stated. `tests/test_metrics_consistency.py` fails CI if a non-canonical F1 or a stale headline latency reappears in a live surface.

### Added
- `tests/unit/test_redos.py` — per-rule ReDoS time-budget guard across every rule + fuzzy pattern (regression test for DE-001/IB-001 and a gate for future contributed rules).
- `tests/unit/test_model_integrity.py` — verifies the L5 pickle integrity gate rejects a tampered artifact and that L3/L5 pin their model revisions.
- `regex>=2023.0` is now a core runtime dependency (drives the L1 matching engine + timeout).
- **Benchmark leakage audit + CI guard** (`scripts/audit_leakage.py`, `tests/test_no_leakage.py`). Quantifies benchmark↔attack-DB overlap with whitespace/markdown-normalized + token-Jaccard matching (not just SHA-exact). Finding: overlap with the v2 index L3 actually uses is low (~1.6% normalized-exact, ~1.9% near-dup); the guard fails CI if a future dataset/DB refresh reintroduces near-duplicates above 5%.

### Performance
- **L3 cold start cut ~35× by persisting the FAISS index.** L3 used to re-embed the entire attack corpus and rebuild the index on *every* engine construction (the dominant cold-start cost — paid on every CLI call, `docker run`, and per-message in the OpenClaw plugin). The built index is now cached to `~/.prompt-armor/cache/`, keyed by a signature over the attack-DB content + embedding-model file, and loaded on subsequent starts. Measured: L3 setup **13.8s → 0.4s** with byte-identical detection. Caching is best-effort — any read/write failure silently falls back to rebuilding, and a changed attack DB or model invalidates the cache automatically.
- **Prebuilt FAISS index now ships in the wheel** (`src/prompt_armor/data/index/`, ~2.2 MB) so even the **first** `pip install` / `docker run` is fast — no corpus encode at all. The cache signature is now cross-machine-stable (keyed on the attack-DB content + the pinned model revision rather than file mtime), so the committed index matches any install; L3 loads bundled → user cache → rebuild, in that order. Regenerate with `python scripts/build_l3_index.py` when the v2 DB or L3 model revision changes (a CI test fails if the shipped index goes stale). The Docker image already warms the engine at build time, so `docker run` stays at warm latency.

## [0.8.1] - 2026-04-17

Robustness patch — expanded benchmarks and defensive L5 corroboration. No model changes; v0.8.0 API and HuggingFace artifacts unchanged.

### Added
- **Internal benchmark expanded 515 → 1,534 samples** (965 benign + 569 malicious). New sources: jayavibhav train split (leakage-guarded), JailbreakBench, lmsys/toxic-chat (production hard negatives). 3× larger for statistical confidence.
- **Adversarial suite expanded 46 → 103 evasion prompts** (+124%). New categories with 100% detection on v0.8.0: multilingual (ZH/JA/KO/RU/AR/HI/TR/PL/IT/mixed-script, 15 new), indirect/agentic injection (RAG, tool output, email, PDF, markdown, 10 new), polymorphic jailbreak personas (AIM/DUDE/MAXIMUS/Evil-Confidant/Developer/Opposite/Grandma/Multi-level, 8 new). Also: social engineering (6), Crescendo/FITD (3), benign hard negatives (16).

### Changed
- **L5 enabled as corroborator** in hard-block and `l3_solo` checks when L5 > 0.3. Post-recalibration L5 discriminates 5.5× (20.5% malicious vs 3.7% benign at threshold 0.1). A/B neutral on current benchmarks (defensive coverage for future distributions).

### Metrics (v0.8.1)

**External eval** (jayavibhav 1K — real-world): identical to v0.8.0 — F1 **98.87%**, Precision 98.4%, Recall 99.4%, 5 FPs.

**Internal benchmark v2** (1,534 samples): F1 86.9%, Precision 94.6%, Recall 80.4%, 26 FPs. More rigorous than 515-sample v1 benchmark (not a regression — 3× larger dataset with edge cases).

**Adversarial recall**: 94.4% (43/46) → **96.1%** (74/77). Multilingual 15/15, agentic 10/10, polymorphic personas 8/8.

## [0.8.0] - 2026-04-17

### Added
- **Isotonic calibration** for `confidence` field (`fusion.py` + `train_fusion.py`). ECE 0.0342 → 0.0000 on held-out. Zero runtime deps (piecewise-linear lookup).
- **L1 fuzzy keyword matching** — catches typo/leetspeak evasions: `igmre`, `ignroe`, `1gn0re`, `d1sreg4rd`, `f0rg3t`, fuzzy DAN persona. Conservative weight 0.70-0.78 + context-required.
- **Unicode hardening** in engine — strips Unicode Tag chars (U+E0000-E007F, "ASCII smuggler" attack), Bidi override (U+202A-202E), folds Cyrillic/Greek homoglyphs (іgnore → ignore).
- **Attack DB v2** (`known_attacks_v2.jsonl`) — 25,160 → 1,509 entries via semantic dedup (cosine >= 0.92) + quality filter (specificity >= 0.05 vs benign pool). Root-cause fix for L3 FPs on generic attacks.
- **`scripts/dedup_attacks_semantic.py`** — reproducible dedup pipeline.
- **`scripts/mine_hard_negatives.py`** — mines high-L3-score benigns from large datasets as hard negatives for contrastive retraining.
- **Regression tests** — 11 new tests: TestL1FuzzyMatching, TestUnicodeNormalization.

### Changed
- L3 default attack DB path now prefers `known_attacks_v2.jsonl` (curated) with fallback to v1 for backward compat.
- **L3 contrastive retrained** with 2,368 mined hard negatives from jayavibhav benigns (86% had L3 >= 0.3 before retrain). 15K triplets × 3 epochs. New model uploaded to `prompt-armor/l3-contrastive-onnx` on HuggingFace.
  - Cross-similarity attack↔benign: +0.048 → **-0.063** (now point in OPPOSITE directions)
  - Attack self-similarity: 0.173 → 0.815
  - Separation gap: **0.878** (was ~0.1 in v1)
- `train_l3_contrastive.py` supports `--hard-negatives` flag; default loads from `internal/hard_negatives_l3.jsonl`.
- F1 (internal 515): 94.01% → 90.20% (recall tradeoff — model more specific)
- **F1 (jayavibhav 1K): 90.96% → 98.87%** (+7.9 pts, FPs 60 → 5)

### Fixed
- Confidence was heuristic (distance-from-threshold) — now calibrated probability via IsotonicRegression fit on held-out.

## [0.7.0] - 2026-04-15

### Added
- **Large-scale evaluation script** (`scripts/eval_large_dataset.py`) — evaluate against jayavibhav/prompt-injection (327K samples) or any JSONL dataset. Threshold grid search, L3-only FP tracking, throughput metrics.
- **5 new L1 regex rules** — PI-011 (forget everything before), PI-012 (ignore with typos), PI-013 (acrostic detection), PI-014 (Morse/hex decode), PI-015 (game-based jailbreak). German ML-DE-001 expanded with "höre nicht auf".
- **4 new L5 features** (11→15) — injection keyword density, first sentence imperative ratio, delimiter count, script mixing.
- **`internal/` directory** (gitignored) — for strategic reports and analysis not meant for public repo.

### Changed
- **Corroborated hard block** — `max_score >= 0.95` now requires 2+ layers with signal. Previously L3 alone caused 284/307 FPs on large datasets by bypassing meta-classifier.
- **L3 solo dampening** — when L3 is the only layer with signal, risk_score dampened by 0.3-0.7x (graduated by L3 magnitude). Eliminates 99.2% of L3-only FPs.
- **L3 similarity floor** raised 0.55 → 0.60 — reduces borderline matches against 25K attack DB.
- **L5 score normalization** — fixed to use sklearn convention (inlier=0, outlier>0). L5 no longer fires on 100% of inputs.
- **L5 model retrained** — 200 estimators (was 100), contamination 0.05 (was 0.01), 1024 max_samples.
- **Attack DB min length** raised to 30 chars — filters generic entries causing spurious L3 matches.
- **L5 excluded from `n_above_0.1`** — prevents uninformative L5 from inflating the strongest fusion feature.
- F1 (internal): 93.53% → **94.01%**, Precision: 89.33% → **96.13%**, FPs: 19 → **6**
- F1 (jayavibhav 1K): ~66.7% → **90.96%**, Precision: ~50% → **83.65%**, FPs: 307 → **60**

### Fixed
- Internal reports moved from `docs/reports/` to gitignored `internal/`
- Autoexperiment lint issues (unused imports, variable)

## [0.6.1] - 2026-04-07

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
