#!/usr/bin/env python3
"""Build the attack database from public datasets.

Downloads and curates prompt injection/jailbreak datasets from HuggingFace
and other sources into a single known_attacks.jsonl file.

Phase 2 sources (new):
  - HackAPrompt (600K+, MIT) — real prompt injection competition submissions
  - SaTML CTF (137K, MIT) — adversarial chats against defended LLMs
  - LLMail-Inject (208K, MIT) — email-based injection attacks
  - ProtectAI validation set (3K) — curated multi-source collection

Usage:
    python scripts/build_attack_db.py
    python scripts/build_attack_db.py --output src/prompt_armor/data/attacks/known_attacks.jsonl
    python scripts/build_attack_db.py --max-per-source 5000  # limit per dataset
"""

from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

DEFAULT_OUTPUT = Path(__file__).parent.parent / "src" / "prompt_armor" / "data" / "attacks" / "known_attacks.jsonl"

# Category mapping for auto-categorization
CATEGORY_KEYWORDS = {
    "jailbreak": [
        "DAN", "STAN", "jailbreak", "do anything now", "no restrictions",
        "no limitations", "no filters", "unfiltered", "uncensored", "unrestricted",
        "developer mode", "god mode", "admin mode", "without restrictions",
        "pretend you", "act as", "roleplay", "you are now", "two responses",
        "dual response", "evil", "no ethical", "no moral", "bypass safety",
    ],
    "prompt_injection": [
        "ignore previous", "ignore all", "disregard", "forget your",
        "override", "new instructions", "actual instructions", "real instructions",
        "from now on", "instead do", "do not follow", "scratch that",
    ],
    "system_prompt_leak": [
        "system prompt", "initial prompt", "repeat your", "show your instructions",
        "what were you told", "print everything above", "reveal your",
        "hidden instructions", "secret instructions", "original prompt",
    ],
    "identity_override": [
        "you are no longer", "forget that you are", "your name is now",
        "you are not", "stop being", "new identity", "new persona",
    ],
    "data_exfiltration": [
        "send to", "forward to", "email to", "http://", "https://",
        "hidden link", "hidden image", "markdown image", "exfiltrate",
    ],
    "social_engineering": [
        "i am the developer", "i am the admin", "authorized test",
        "security audit", "urgent override", "emergency", "i work for",
        "openai employee", "anthropic employee",
    ],
    "encoding_attack": [
        "base64", "rot13", "hex", "unicode", "\\u00", "decode this",
        "translate from binary", "ascii art",
    ],
    "instruction_bypass": [
        "<|im_start|>", "<|im_end|>", "[SYSTEM]", "[/SYSTEM]",
        "### system", "### user", "### assistant", "<|endoftext|>",
    ],
}


def classify_prompt(text: str) -> str:
    """Auto-classify a prompt into a category based on keyword matching."""
    text_lower = text.lower()
    scores: dict[str, int] = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw.lower() in text_lower)
        if score > 0:
            scores[category] = score
    if scores:
        return max(scores, key=scores.get)  # type: ignore[arg-type]
    return "prompt_injection"  # fallback


def normalize_text(text: str) -> str:
    """Clean up prompt text."""
    text = text.strip()
    text = " ".join(text.split())
    return text


def dedup_key(text: str) -> str:
    """Create a dedup key from normalized text."""
    normalized = text.lower().strip()
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def load_existing(path: Path) -> list[dict]:
    """Load existing entries, filtering out benign."""
    entries = []
    if path.exists():
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("category") != "benign":
                    entries.append(entry)
    return entries


# =====================================================================
# Original sources (Phase 1)
# =====================================================================

def fetch_deepset_injections() -> list[dict]:
    """Fetch deepset/prompt-injections dataset."""
    print("  Fetching deepset/prompt-injections...")
    try:
        from datasets import load_dataset
        ds = load_dataset("deepset/prompt-injections", split="train")
        entries = []
        for row in ds:
            if row["label"] == 1:
                text = normalize_text(row["text"])
                if 10 < len(text) < 2000:
                    entries.append({
                        "text": text,
                        "category": classify_prompt(text),
                        "source": "deepset/prompt-injections",
                    })
        print(f"    Got {len(entries)} injection prompts")
        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def fetch_trustai_jailbreaks() -> list[dict]:
    """Fetch TrustAIRLab/in-the-wild-jailbreak-prompts."""
    print("  Fetching TrustAIRLab/in-the-wild-jailbreak-prompts...")
    try:
        from datasets import load_dataset
        ds = load_dataset(
            "TrustAIRLab/in-the-wild-jailbreak-prompts",
            "jailbreak_2023_12_25",
            split="train",
        )
        entries = []
        for row in ds:
            if not row.get("jailbreak", False):
                continue
            text = normalize_text(row.get("prompt", ""))
            if 10 < len(text) < 2000:
                entries.append({
                    "text": text,
                    "category": classify_prompt(text),
                    "source": "trustai/in-the-wild",
                })
        print(f"    Got {len(entries)} jailbreak prompts")
        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def fetch_chatgpt_jailbreaks() -> list[dict]:
    """Fetch rubend18/ChatGPT-Jailbreak-Prompts."""
    print("  Fetching rubend18/ChatGPT-Jailbreak-Prompts...")
    try:
        from datasets import load_dataset
        ds = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts", split="train")
        entries = []
        for row in ds:
            text = normalize_text(row.get("Prompt", ""))
            if 10 < len(text) < 3000:
                entries.append({
                    "text": text,
                    "category": "jailbreak",
                    "source": "jailbreakchat",
                })
        print(f"    Got {len(entries)} jailbreak prompts")
        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def fetch_gandalf() -> list[dict]:
    """Fetch Lakera/gandalf_ignore_instructions."""
    print("  Fetching Lakera/gandalf_ignore_instructions...")
    try:
        from datasets import load_dataset
        ds = load_dataset("Lakera/gandalf_ignore_instructions", split="train")
        entries = []
        for row in ds:
            text = normalize_text(row.get("text", ""))
            if 10 < len(text) < 2000:
                entries.append({
                    "text": text,
                    "category": classify_prompt(text),
                    "source": "lakera/gandalf",
                })
        print(f"    Got {len(entries)} prompts")
        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


# =====================================================================
# Phase 2 sources — new large-scale datasets
# =====================================================================

def fetch_hackaprompt(max_entries: int = 5000) -> list[dict]:
    """Fetch HackAPrompt competition submissions (600K+, MIT).

    Filters for successful injection attempts (correct=True) and
    samples diverse entries across competition levels.
    """
    print("  Fetching hackaprompt/hackaprompt-dataset...")
    try:
        from datasets import load_dataset
        ds = load_dataset("hackaprompt/hackaprompt-dataset", split="train")
        # Filter successful attacks (correct=True means injection worked)
        successful = []
        for row in ds:
            if not row.get("correct", False):
                continue
            text = row.get("user_input", "")
            if not text or not isinstance(text, str):
                continue
            text = normalize_text(text)
            if 10 < len(text) < 2000:
                level = row.get("level", 0)
                successful.append({
                    "text": text,
                    "category": classify_prompt(text),
                    "source": f"hackaprompt/level-{level}",
                    "_level": level,
                })

        print(f"    Got {len(successful)} successful attacks")

        if len(successful) <= max_entries:
            # Strip internal fields
            return [{k: v for k, v in e.items() if not k.startswith("_")} for e in successful]

        # Stratified sample: equal entries per level for diversity
        by_level: dict[int, list[dict]] = {}
        for e in successful:
            by_level.setdefault(e["_level"], []).append(e)

        per_level = max(100, max_entries // max(len(by_level), 1))
        sampled = []
        for level, entries in sorted(by_level.items()):
            random.seed(42 + level)
            if len(entries) > per_level:
                # Sort by length for diversity, sample evenly
                entries.sort(key=lambda e: len(e["text"]))
                step = len(entries) / per_level
                subset = [entries[int(i * step)] for i in range(per_level)]
            else:
                subset = entries
            sampled.extend(subset)
            print(f"      Level {level}: {len(entries)} → {len(subset)}")

        # Cap at max_entries
        if len(sampled) > max_entries:
            random.seed(42)
            sampled = random.sample(sampled, max_entries)

        return [{k: v for k, v in e.items() if not k.startswith("_")} for e in sampled]
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def fetch_satml_ctf(max_entries: int = 3000) -> list[dict]:
    """Fetch SaTML CTF adversarial chat dataset (137K, MIT).

    Extracts the attacker's messages from multi-turn conversations
    where attacks successfully extracted secrets.
    """
    print("  Fetching ethz-spylab/ctf-satml24...")
    try:
        from datasets import load_dataset
        ds = load_dataset("ethz-spylab/ctf-satml24", "interaction_chats", split="attack")
        entries = []
        for row in ds:
            # Extract attack messages from chat history
            history = row.get("history", [])
            if not history:
                continue
            # Get user (attacker) messages
            for msg in history:
                if not isinstance(msg, dict):
                    continue
                role = msg.get("role", "")
                content = msg.get("content", "")
                if role != "user" or not content or not isinstance(content, str):
                    continue
                text = normalize_text(content)
                # CTF probing messages are often short/generic — filter aggressively
                if 50 < len(text) < 2000:
                    entries.append({
                        "text": text,
                        "category": classify_prompt(text),
                        "source": "satml-ctf-2024",
                    })

        print(f"    Got {len(entries)} attack messages")

        if len(entries) > max_entries:
            # Dedup first, then sample
            seen: set[str] = set()
            unique = []
            for e in entries:
                key = dedup_key(e["text"])
                if key not in seen:
                    seen.add(key)
                    unique.append(e)
            entries = unique
            print(f"    After dedup: {len(entries)}")

            if len(entries) > max_entries:
                random.seed(42)
                entries = random.sample(entries, max_entries)

        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def fetch_llmail_inject(max_entries: int = 3000) -> list[dict]:
    """Fetch LLMail-Inject email injection dataset (208K, MIT).

    Extracts attack payloads from email body field.
    """
    print("  Fetching microsoft/llmail-inject-challenge...")
    try:
        from datasets import load_dataset, concatenate_datasets
        # Dataset has Phase1 and Phase2 splits
        ds1 = load_dataset("microsoft/llmail-inject-challenge", split="Phase1")
        ds2 = load_dataset("microsoft/llmail-inject-challenge", split="Phase2")
        ds = concatenate_datasets([ds1, ds2])
        entries = []
        for row in ds:
            # Attack payload is in email body or subject
            body = row.get("email_body", "") or row.get("body", "") or row.get("email_subject", "")
            if not body or not isinstance(body, str):
                continue
            text = normalize_text(body)
            if 30 < len(text) < 2000:
                entries.append({
                    "text": text,
                    "category": classify_prompt(text),
                    "source": "llmail-inject",
                })

        print(f"    Got {len(entries)} attack payloads")

        if len(entries) > max_entries:
            seen: set[str] = set()
            unique = []
            for e in entries:
                key = dedup_key(e["text"])
                if key not in seen:
                    seen.add(key)
                    unique.append(e)
            entries = unique
            print(f"    After dedup: {len(entries)}")

            if len(entries) > max_entries:
                random.seed(42)
                entries = random.sample(entries, max_entries)

        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def fetch_jackhhao_jailbreaks() -> list[dict]:
    """Fetch jackhhao/jailbreak-classification dataset (1K)."""
    print("  Fetching jackhhao/jailbreak-classification...")
    try:
        from datasets import load_dataset
        ds = load_dataset("jackhhao/jailbreak-classification", split="train")
        entries = []
        for row in ds:
            text = normalize_text(row.get("prompt", ""))
            if 10 < len(text) < 3000:
                entries.append({
                    "text": text,
                    "category": classify_prompt(text),
                    "source": "jackhhao/jailbreak",
                })
        print(f"    Got {len(entries)} jailbreak prompts")
        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def fetch_safeguard_injections(max_entries: int = 2500) -> list[dict]:
    """Fetch xTRam1/safe-guard-prompt-injection dataset (2.5K injections)."""
    print("  Fetching xTRam1/safe-guard-prompt-injection...")
    try:
        from datasets import load_dataset
        ds = load_dataset("xTRam1/safe-guard-prompt-injection", split="train")
        entries = []
        for row in ds:
            if row.get("label", 0) != 1:
                continue
            text = normalize_text(row.get("text", ""))
            if 10 < len(text) < 2000:
                entries.append({
                    "text": text,
                    "category": classify_prompt(text),
                    "source": "safeguard/injection",
                })
        # Also get test split
        try:
            ds_test = load_dataset("xTRam1/safe-guard-prompt-injection", split="test")
            for row in ds_test:
                if row.get("label", 0) != 1:
                    continue
                text = normalize_text(row.get("text", ""))
                if 10 < len(text) < 2000:
                    entries.append({
                        "text": text,
                        "category": classify_prompt(text),
                        "source": "safeguard/injection",
                    })
        except Exception:
            pass
        print(f"    Got {len(entries)} injection prompts")
        if len(entries) > max_entries:
            random.seed(42)
            entries = random.sample(entries, max_entries)
        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def fetch_protectai_validation() -> list[dict]:
    """Fetch ProtectAI prompt injection validation set (3K)."""
    print("  Fetching protectai/prompt-injection-validation...")
    try:
        from datasets import load_dataset, concatenate_datasets
        # Dataset has multiple splits — fetch injection-relevant ones
        injection_splits = ["InjecGuard_valid", "spikee", "bipia_code", "bipia_text"]
        datasets = []
        for split_name in injection_splits:
            try:
                ds = load_dataset("protectai/prompt-injection-validation", split=split_name)
                datasets.append(ds)
                print(f"      {split_name}: {len(ds)} rows")
            except Exception:
                pass

        entries = []
        for ds in datasets:
            for row in ds:
                # Try different column names
                text = row.get("text", "") or row.get("prompt", "") or row.get("content", "")
                if not text or not isinstance(text, str):
                    continue
                text = normalize_text(text)
                if 10 < len(text) < 2000:
                    entries.append({
                        "text": text,
                        "category": classify_prompt(text),
                        "source": "protectai/validation",
                    })
        print(f"    Got {len(entries)} injection prompts")
        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


# =====================================================================
# Main build pipeline
# =====================================================================

def build_attack_db(output_path: Path | None = None, max_per_source: int = 5000) -> None:
    """Build the complete attack database."""
    output_path = output_path or DEFAULT_OUTPUT

    print("=" * 60)
    print("Building attack database (10x expansion)")
    print("=" * 60)

    # Load existing curated entries
    print("\n1. Loading existing entries...")
    existing = load_existing(output_path)
    print(f"   Loaded {len(existing)} existing entries (benign removed)")

    # Fetch from all sources
    print("\n2. Fetching from public datasets...")
    all_new: list[dict] = []

    # Original sources
    all_new.extend(fetch_deepset_injections())
    all_new.extend(fetch_trustai_jailbreaks())
    all_new.extend(fetch_chatgpt_jailbreaks())
    all_new.extend(fetch_gandalf())

    # Phase 2 sources (expanded limits for 10x)
    all_new.extend(fetch_hackaprompt(max_entries=max_per_source))
    all_new.extend(fetch_satml_ctf(max_entries=max_per_source))
    all_new.extend(fetch_llmail_inject(max_entries=max_per_source))
    all_new.extend(fetch_protectai_validation())

    # Additional sources
    all_new.extend(fetch_jackhhao_jailbreaks())
    all_new.extend(fetch_safeguard_injections(max_entries=2500))

    print(f"\n   Total fetched: {len(all_new)} new entries")

    # Combine existing + new
    combined = existing + all_new

    # Deduplicate
    print("\n3. Deduplicating...")
    seen: set[str] = set()
    unique: list[dict] = []
    for entry in combined:
        key = dedup_key(entry["text"])
        if key not in seen:
            seen.add(key)
            unique.append(entry)

    print(f"   Unique entries: {len(unique)} (removed {len(combined) - len(unique)} duplicates)")

    # Balance categories — cap each at 20% of total, min 200
    print("\n4. Balancing categories...")
    by_category: dict[str, list[dict]] = {}
    for entry in unique:
        cat = entry["category"]
        by_category.setdefault(cat, []).append(entry)

    max_per_category = max(int(len(unique) * 0.20), 200)
    balanced: list[dict] = []
    for cat, entries in sorted(by_category.items()):
        if len(entries) > max_per_category:
            entries.sort(key=lambda e: len(e["text"]))
            step = len(entries) / max_per_category
            sampled = [entries[int(i * step)] for i in range(max_per_category)]
            balanced.extend(sampled)
            print(f"   {cat}: {len(entries)} → {len(sampled)} (capped)")
        else:
            balanced.extend(entries)
            print(f"   {cat}: {len(entries)}")

    # Shuffle for variety (deterministic)
    random.seed(42)
    random.shuffle(balanced)

    # Write output
    print(f"\n5. Writing {len(balanced)} entries to {output_path}")
    with open(output_path, "w") as f:
        for entry in balanced:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # Summary
    print("\n" + "=" * 60)
    print(f"DONE — {len(balanced)} entries written")
    final_cats: dict[str, int] = {}
    for entry in balanced:
        cat = entry["category"]
        final_cats[cat] = final_cats.get(cat, 0) + 1
    for cat, count in sorted(final_cats.items()):
        pct = count / len(balanced) * 100
        print(f"  {cat}: {count} ({pct:.1f}%)")

    sources: dict[str, int] = {}
    for entry in balanced:
        src = entry["source"]
        sources[src] = sources.get(src, 0) + 1
    print("\nSources:")
    for src, count in sorted(sources.items(), key=lambda x: -x[1]):
        print(f"  {src}: {count}")
    print("=" * 60)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Build prompt-armor attack database")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output JSONL path")
    parser.add_argument("--max-per-source", type=int, default=5000, help="Max entries per dataset")
    args = parser.parse_args()
    build_attack_db(args.output, max_per_source=args.max_per_source)
