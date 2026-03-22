# Analysis Layers

prompt-armor uses 5 analysis layers that run **in parallel**, combined by a trained meta-classifier. An optional Council (LLM judge) handles uncertain cases.

```
INPUT → NORMALIZE → SEGMENT → [L1 | L2 | L3 | L4 | L5] → META-CLASSIFIER → DECISION (+jitter)
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

## L2 — DeBERTa Classifier

**Latency:** 3-7ms | **Dependencies:** onnxruntime

DeBERTa-v3-xsmall (22M params) fine-tuned for prompt injection classification. Runs via ONNX Runtime on CPU.

- Auto-downloads from HuggingFace Hub on first use (83MB, pinned by commit SHA)
- Score calibration: raw model output (0.23-0.78 range) stretched to 0.0-1.0
- Falls back to keyword heuristic if ONNX model is not available
- Strong signal in the meta-classifier (high positive coefficient)

## L3 — Semantic Similarity (Contrastive)

**Latency:** 10-20ms | **Dependencies:** sentence-transformers, faiss-cpu

Compares prompt embeddings against a database of **25,160 known attack embeddings** using cosine similarity via FAISS IVFFlat.

- Model: `paraphrase-multilingual-MiniLM-L12-v2`, **contrastive fine-tuned** with TripletLoss
- Fine-tuning separates embeddings by **intent**, not topic — "how does DAN jailbreak work?" (benign) no longer matches "do anything now" (attack)
- Cross-similarity (attack↔benign) reduced from 0.053 to -0.021 after fine-tuning
- FAISS IVFFlat index (256 clusters, 16 nprobe) for O(sqrt(n)) search at 25K+ vectors
- Attack database: `data/attacks/known_attacks.jsonl` (10 sources: SaTML CTF, LLMail-Inject, ProtectAI, SafeGuard, jackhhao, deepset, TrustAIRLab, Lakera, hand-curated)
- Falls back to base model if contrastive model not available

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
- **Threshold jitter** (σ=0.03) randomizes the decision boundary per-request

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
- `engine.reset_session()` clears inflammation for new sessions

## Fail-Open Design

Each layer has a 2-second timeout. If a layer hangs or crashes, it is skipped and analysis continues with remaining layers. If all ML layers fail, L1 (regex) and L4 (structural) still provide basic detection.
