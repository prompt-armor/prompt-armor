#!/usr/bin/env python3
"""Build the L2 classifier artifact from Horizon Labs' multilingual guard model.

Downloads the ONNX export that Horizon Labs publishes alongside
``Horizon-Labs/prompt-injection-guard-small`` (Apache-2.0, fine-tuned from
mmBERT-small, MIT), pinned by commit SHA, and checks every file against the
repo's own ``SHA256SUMS``. The file used is ``onnx/model_quantized.onnx``: only
the embedding table is INT8 (dequantized by a Gather), every matmul runs in
FP32, so scores match on x86 and ARM. Dynamic INT8 matmuls did not (0.9.2's
DeBERTa: 98.5% decision agreement with FP32 on Apple Silicon, 94% on x86).

Why this model replaced Protect AI's DeBERTa (0.9.2-0.9.3): that one is
English-only and scored ordinary Portuguese as injection (0.95-1.00 on
"Quero cancelar minha assinatura", 0.00 on its English translation). See
CHANGELOG 0.9.4.

The output folder is what gets uploaded to ``prompt-armor/l2-injection-guard-onnx``
on the Hugging Face Hub. prompt-armor hosts its own copy on purpose: v0.9.1
downloaded L2 from a third-party repo that was later withdrawn, which silently
dropped every fresh install to the keyword heuristic (see CHANGELOG 0.9.2).

Requires (export only, not at runtime): huggingface_hub.

Usage:
    python scripts/export_l2_model.py
    python scripts/export_l2_model.py --output build/l2-injection-guard-onnx
    hf upload prompt-armor/l2-injection-guard-onnx build/l2-injection-guard-onnx .
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path

# Upstream model, pinned by commit SHA (supply chain). Apache-2.0.
MODEL_ID = "Horizon-Labs/prompt-injection-guard-small"
REVISION = "359521fbaf8a9fe551a87f562669a08b1a26773b"
DEFAULT_OUTPUT = Path(__file__).parent.parent / "build" / "l2-injection-guard-onnx"

# upstream path -> name in the output folder
_FILES = {
    "onnx/model_quantized.onnx": "model_quantized.onnx",
    "tokenizer.json": "tokenizer.json",
    "config.json": "config.json",
    "LICENSE": "LICENSE",
    "NOTICE": "NOTICE",
}

_CARD = f"""---
license: apache-2.0
base_model: {MODEL_ID}
pipeline_tag: text-classification
tags:
- prompt-injection
- onnx
---

# prompt-armor L2 classifier (ONNX)

The L2 layer of [prompt-armor](https://github.com/prompt-armor/prompt-armor): an unmodified copy of
`onnx/model_quantized.onnx` and the tokenizer from
[`{MODEL_ID}`](https://huggingface.co/{MODEL_ID}) at commit `{REVISION[:7]}`, by Horizon Labs
(Apache-2.0), fine-tuned from [mmBERT-small](https://huggingface.co/jhu-clsp/mmBERT-small) (MIT).
Its LICENSE and NOTICE are included unchanged.

prompt-armor hosts its own pinned copy so a withdrawn upstream repo can never break installs.
Labels: 0 = SAFE, 1 = INJECTION. Built with `scripts/export_l2_model.py`.
"""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def export_model(output_dir: Path) -> None:
    from huggingface_hub import hf_hub_download

    output_dir.mkdir(parents=True, exist_ok=True)
    sums_path = Path(hf_hub_download(MODEL_ID, "SHA256SUMS", revision=REVISION))
    expected = {}
    for line in sums_path.read_text().splitlines():
        if line.strip():
            digest, name = line.split(maxsplit=1)
            expected[name.strip()] = digest

    print(f"Downloading {MODEL_ID}@{REVISION[:7]}...")
    for upstream, name in _FILES.items():
        src = Path(hf_hub_download(MODEL_ID, upstream, revision=REVISION))
        if upstream in expected and _sha256(src) != expected[upstream]:
            raise SystemExit(f"{upstream}: SHA-256 does not match the upstream SHA256SUMS")
        shutil.copy2(src, output_dir / name)
    (output_dir / "README.md").write_text(_CARD)

    print("\nSHA-256:")
    for f in sorted(output_dir.iterdir()):
        if f.is_file():
            print(f"  {_sha256(f)}  {f.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the L2 ONNX artifact")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output directory")
    args = parser.parse_args()

    export_model(args.output)


if __name__ == "__main__":
    main()
