# Analysis Layers

prompt-armor uses 4 analysis layers that run **in parallel**, combined by a trained meta-classifier.

```
INPUT → NORMALIZE → SEGMENT → [L1 | L2 | L3 | L4] → META-CLASSIFIER → DECISION (+jitter)
                                                            ↑
                                                    inflammation cascade
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

Compares prompt embeddings against a database of **5,540 known attack embeddings** using cosine similarity via FAISS.

- Model: `paraphrase-multilingual-MiniLM-L12-v2`, **contrastive fine-tuned** with TripletLoss
- Fine-tuning separates embeddings by **intent**, not topic — "how does DAN jailbreak work?" (benign) no longer matches "do anything now" (attack)
- Cross-similarity (attack↔benign) reduced from 0.053 to -0.021 after fine-tuning
- Attack database: `data/attacks/known_attacks.jsonl` (SaTML CTF, LLMail-Inject, ProtectAI, deepset, TrustAIRLab, Lakera, hand-curated)
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

## Meta-Classifier Fusion

A trained logistic regression model combines all 4 layer scores with interaction features:

**Input features (9):**
- 4 raw layer scores (L1, L2, L3, L4)
- Max score across layers
- Min score across layers
- L1 × L4 interaction (regex + structural agreement)
- L2 × L3 interaction (ML + similarity agreement)
- Number of layers with score > 0.1

**Key insights from training:**
- **L2 × L3 interaction** is a powerful signal — when both DeBERTa and contrastive similarity agree, confidence is very high
- **Number of agreeing layers** is the second strongest signal
- L3/L4 raw coefficients are clamped to non-negative to prevent adversarial exploitation
- **Threshold jitter** (σ=0.03) randomizes the decision boundary per-request, preventing attackers from binary-searching the exact threshold

**Output:** Risk score (0.0-1.0) via sigmoid, thresholded into ALLOW / WARN / BLOCK.

## Session-Level Inflammation Cascade

When a WARN or BLOCK decision occurs, the engine temporarily increases sensitivity for subsequent requests in the same session:

- Inflammation boost proportional to risk score (capped at 0.15)
- Exponential decay (×0.7 per request) — doesn't permanently bias
- Catches iterative probing attacks where attackers send progressively aggressive prompts
- `engine.reset_session()` clears inflammation for new sessions

## Fail-Open Design

Each layer has a 2-second timeout. If a layer hangs or crashes, it is skipped and analysis continues with remaining layers. If all ML layers fail, L1 (regex) and L4 (structural) still provide basic detection.
