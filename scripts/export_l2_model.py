#!/usr/bin/env python3
"""Build the L2 classifier artifact (ONNX INT8) from ProtectAI's DeBERTa model.

Downloads the ONNX export that ProtectAI publishes alongside
``protectai/deberta-v3-base-prompt-injection-v2`` (Apache-2.0), pinned by commit
SHA, and dynamically quantizes it to INT8 with ONNX Runtime. No torch needed.

The output folder is what gets uploaded to ``prompt-armor/l2-deberta-onnx`` on
the Hugging Face Hub. prompt-armor hosts its own copy on purpose: v0.9.1
downloaded L2 from a third-party repo that was later withdrawn, which silently
dropped every fresh install to the keyword heuristic (see CHANGELOG 0.9.2).

Usage:
    python scripts/export_l2_model.py
    python scripts/export_l2_model.py --output build/l2-deberta-onnx
    python scripts/export_l2_model.py --variant small   # gated upstream, needs HF token
    hf upload prompt-armor/l2-deberta-onnx build/l2-deberta-onnx .
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path

# Upstream models, pinned by commit SHA (supply chain). Both Apache-2.0.
UPSTREAM = {
    "base": ("protectai/deberta-v3-base-prompt-injection-v2", "90c9989b1a342275dd0d1a95aad283c04e075671"),
    "small": ("protectai/deberta-v3-small-prompt-injection-v2", "d7c8842daf06de3179cc3aca76b7b3a057acc5e7"),
}
DEFAULT_OUTPUT = Path(__file__).parent.parent / "build" / "l2-deberta-onnx"

# Files copied verbatim from the upstream ``onnx/`` folder.
_TOKENIZER_FILES = ["tokenizer.json", "config.json"]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def export_model(variant: str, output_dir: Path, keep_fp32: bool = False) -> None:
    from huggingface_hub import hf_hub_download
    from onnxruntime.quantization import QuantType, quantize_dynamic

    model_id, revision = UPSTREAM[variant]
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Downloading {model_id}@{revision[:7]} (ONNX FP32 export)...")
    fp32 = Path(hf_hub_download(model_id, "onnx/model.onnx", revision=revision))
    for name in _TOKENIZER_FILES:
        src = Path(hf_hub_download(model_id, f"onnx/{name}", revision=revision))
        shutil.copy2(src, output_dir / name)
    try:
        lic = Path(hf_hub_download(model_id, "LICENSE", revision=revision))
        shutil.copy2(lic, output_dir / "LICENSE")
    except Exception:
        print("  (upstream has no LICENSE file; the card still states Apache-2.0)")

    # Per-channel weights are not optional for DeBERTa-v3: plain per-tensor
    # dynamic INT8 collapses it (benchmark AUC 0.92 -> 0.65). Per-channel keeps
    # 98.5% decision agreement with FP32 (AUC 0.914) at a third of the size.
    print("Quantizing to INT8 (dynamic, per-channel QInt8 weights)...")
    target = output_dir / "model_quant.onnx"
    quantize_dynamic(
        str(fp32),
        str(target),
        weight_type=QuantType.QInt8,
        per_channel=True,
        op_types_to_quantize=["MatMul", "Gather"],
        extra_options={"MatMulConstBOnly": True},
    )
    print(f"  {target} ({target.stat().st_size / 1024 / 1024:.1f}MB)")

    if keep_fp32:
        shutil.copy2(fp32, output_dir / "model_fp32.onnx")

    print("\nSHA-256:")
    for f in sorted(output_dir.iterdir()):
        if f.is_file():
            print(f"  {_sha256(f)}  {f.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the L2 ONNX INT8 artifact")
    parser.add_argument("--variant", choices=sorted(UPSTREAM), default="base")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output directory")
    parser.add_argument("--keep-fp32", action="store_true", help="Also keep the FP32 model (for parity checks)")
    args = parser.parse_args()

    export_model(args.variant, args.output, args.keep_fp32)


if __name__ == "__main__":
    main()
