# Changelog

All notable changes to prompt-armor will be documented in this file.

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
