# Changelog

All notable changes to llm-shield will be documented in this file.

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
- YAML configuration (`.llm-shield.yml`)
- 103 tests (unit + integration)
- GitHub Actions CI (tests, benchmark, publish)

### Benchmark Results
- Held-out F1: 93.0% (30% test set, never seen during training)
- Full dataset: Precision 79.8%, Recall 93.8%, F1 86.3%
- Average latency: ~19ms
