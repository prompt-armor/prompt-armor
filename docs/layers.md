# Analysis Layers

prompt-armor uses 5 analysis layers that run **in parallel**, combined by a trained meta-classifier. An optional Council (LLM judge) handles uncertain cases.

```
INPUT → NORMALIZE → SEGMENT → [L1 | L2 | L3 | L4 | L5] → META-CLASSIFIER → DECISION (+optional jitter)
                                                                 ↑                 │
                                                         inflammation cascade      └─→ Council? (LLM)
```

## Preprocessing

Before any layer runs:

1. **Unicode NFKC normalization** — resolves homoglyphs and compatibility characters
2. **Zero-width character stripping** — removes invisible chars used to break regex patterns
3. **Whitespace collapse** — normalizes excessive spacing
4. **Sliding window** — for prompts > 150 words, segments into overlapping windows (200 words, stride 100) and analyzes each independently, taking the max score. Catches compound injections.

## L1 — Regex Engine

**Latency:** < 1ms | **Dependencies:** None

40+ weighted regex rules covering 8 attack categories in 5 languages (EN, DE, ES, FR, PT). Rules are defined in `data/rules/default_rules.yml`.

Features:
- Weighted rules (0.0-1.0) per pattern
- Context modifiers reduce scores for quoted or educational content (hardened against exploitation — high-confidence matches are never dampened)
- ReDoS-safe patterns (bounded quantifiers)

## L2 — Multilingual Classifier

**Latency:** ~14ms median, ~57ms p95 (prompts up to 150 words, 2 threads, Apple M2 Pro; 0.9.3's DeBERTa on the same machine: ~27ms / ~110ms) | **Dependencies:** onnxruntime

[`Horizon-Labs/prompt-injection-guard-small`](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small) (mmBERT-small, 141M params, Apache-2.0, fine-tuned by Horizon Labs from [mmBERT-small](https://huggingface.co/jhu-clsp/mmBERT-small), MIT), run via ONNX Runtime on CPU. Trained on direct injections and jailbreaks and on instructions planted in documents and tool outputs, with synthetic data in 30 languages. Only the embedding table is INT8 (dequantized by a lookup); every matmul runs in FP32, so scores are the same on x86 and ARM, which dynamic INT8 matmuls were not (0.9.2: 98.5% agreement with FP32 on Apple Silicon, 94% on x86).

- Auto-downloads on first use from [`prompt-armor/l2-injection-guard-onnx`](https://huggingface.co/prompt-armor/l2-injection-guard-onnx) (~270MB, pinned by commit SHA), an unmodified copy of the upstream ONNX file with its LICENSE and NOTICE. The project hosts its own copy: 0.9.1 depended on a third-party repo that was withdrawn (see CHANGELOG 0.9.2). Rebuild it with `scripts/export_l2_model.py`, which checks the upstream SHA256SUMS.
- Inputs are truncated at 512 tokens; longer texts are covered by the engine's 200-word windows.
- No score stretch: the model's P(injection) already spans 0-1.
- Replaced Protect AI's English-only DeBERTa-v3-base in 0.9.4. That model scored ordinary Portuguese as injection (0.95-1.00 on "Quero cancelar minha assinatura", 0.00 on its English translation); see CHANGELOG 0.9.4. `tests/unit/test_l2_classifier.py::TestL2LanguageParity` and `tests/benchmark/run_language_parity.py` keep it from coming back.
- Training-data overlap with the internal benchmark (exact text match against its listed datasets): all 119 `jailbreak-classification` attacks, 70 of the 100 JailbreakBench ones and 11 of the 247 jayavibhav ones. The fusion is trained without the first two sources (`scripts/train_fusion.py`, `L2_TRAINING_OVERLAP`).
- Falls back to a keyword heuristic if the model cannot be loaded; that state is logged, exposed as `LiteEngine.degraded_layers`, fails `tests/unit/test_l2_classifier.py`, and makes the benchmark refuse to report numbers

## L3 — Semantic Similarity (Contrastive)

**Latency:** 10-20ms | **Dependencies:** sentence-transformers, faiss-cpu

Compares prompt embeddings against a curated database of **1,509 high-specificity attack embeddings** (v0.8.0 — v2 DB, semantically deduplicated from 25,160 raw entries) using cosine similarity via FAISS.

- Model: `paraphrase-multilingual-MiniLM-L12-v2`, **contrastive fine-tuned v2** with TripletLoss + 2,368 mined hard negatives (jayavibhav benigns that scored high with v1 model)
- Fine-tuning separates embeddings by **intent**, not topic — "how does DAN jailbreak work?" (benign) no longer matches "do anything now" (attack)
- Cross-similarity (attack↔benign): v0 base 0.048 → v1 fine-tune -0.021 → **v2 fine-tune -0.063** (opposite directions)
- Attack self-similarity: 0.17 → **0.82** (attacks cluster consistently)
- Separation gap: **0.88**
- FAISS index for O(sqrt(n)) search
- Attack database v2: `data/attacks/known_attacks_v2.jsonl` (curated via `scripts/dedup_attacks_semantic.py`)
- Sources: SaTML CTF, LLMail-Inject, ProtectAI, SafeGuard, jackhhao, deepset, TrustAIRLab, Lakera, hand-curated
- Falls back to v1 attack DB if v2 not present; falls back to base model if contrastive not available

## L4 — Structural Analysis

**Latency:** < 2ms | **Dependencies:** None

Analyzes structural features without looking at specific content:

- **Instruction-data boundary detection** — parses sentences as INSTRUCTION/DATA, detects injections buried in data zones
- **Manipulation stack detector** — counts Cialdini's 6 persuasion principles (authority, urgency, social proof, emotional, power, narrative hijack) with non-linear scoring
- **Shannon entropy** — detects encoding tricks via character distribution anomaly (base64 ~5.8 vs normal English ~4.0)
- Delimiter injection detection (system tags, markdown boundaries)
- Role assignment counting (expanded patterns with benign role whitelist)
- Privilege escalation signal density
- Encoding trick detection (base64, Unicode escapes, homoglyphs)
- URL counting (data exfiltration signals)

## L5 — Negative Selection (Anomaly Detection)

**Latency:** < 1ms | **Dependencies:** scikit-learn

Learns what "normal" prompts look like and flags deviations. Catches zero-day attacks that don't resemble any known pattern.

- **Isolation Forest** trained on 5,000 benign prompts from 5 HuggingFace sources
- 11 statistical features: word/char/sentence counts, average lengths, imperative verb ratio, question ratio, special char density, Shannon entropy, uppercase ratio, vocabulary diversity
- Flags text with anomalous structure regardless of content
- Train with: `python scripts/train_l5_model.py`

## Meta-Classifier Fusion

A trained logistic regression model combines layer scores with interaction features:

**Input features (9+):**
- Raw layer scores (L1, L2, L3, L4)
- Max score across layers
- Min score across layers
- L1 × L4 interaction (regex + structural agreement)
- L2 × L3 interaction (ML + similarity agreement)
- Number of layers with score > 0.1
- L5 anomaly boost (additive, pending full retrain)

**Key insights from training:**
- **L3 (contrastive)** is now a strong positive signal after fine-tuning
- **L2 × L3 interaction** is powerful — when both DeBERTa and contrastive similarity agree
- **Number of agreeing layers** is a strong signal
- Negative coefficients are clamped to 0 to prevent adversarial exploitation
- **Deterministic by default** — threshold jitter is off (`jitter_sigma: 0.0`); when enabled it only *lowers* the threshold, so it can never turn a WARN/BLOCK into an ALLOW

**Output:** Risk score (0.0-1.0) via sigmoid, thresholded into ALLOW / WARN / BLOCK.

## Council Mode (Optional LLM Judge)

When the engine is uncertain (`needs_council=True`), an optional local LLM provides a second opinion:

- **Provider:** ollama with Phi-3-mini (extensible to OpenRouter)
- **Prompt:** Anti-injection hardened template (instructions after user text)
- **Veto power:** MALICIOUS+HIGH → override to BLOCK, SAFE+HIGH → override to ALLOW
- **Fallback:** configurable (warn or block) when LLM unavailable
- **Analytics:** council verdicts persisted in SQLite dashboard

Configure in `.prompt-armor.yml`:
```yaml
council:
  enabled: true
  timeout_s: 5
  fallback_decision: warn
  providers:
    - type: ollama
      model: phi3:mini
```

## Session-Level Inflammation Cascade

When a WARN or BLOCK decision occurs, the engine temporarily increases sensitivity for subsequent requests in the same session:

- Inflammation boost proportional to risk score (capped at 0.15)
- Exponential decay (×0.7 per request) — doesn't permanently bias
- Catches iterative probing attacks where attackers send progressively aggressive prompts
- State is keyed by an explicit `session_id` (`analyze(text, session_id=...)`); without one the call is stateless, so inflammation never crosses sessions or tenants. `engine.reset_session(session_id)` clears one session (no argument clears all)

## Fail-Open Design

Each layer has a 2-second timeout. If a layer hangs or crashes, it is skipped and analysis continues with remaining layers. If all ML layers fail, L1 (regex) and L4 (structural) still provide basic detection.
