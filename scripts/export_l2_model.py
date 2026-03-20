#!/usr/bin/env python3
"""Export DeBERTa prompt injection classifier to ONNX.

Downloads protectai/deberta-v3-small-prompt-injection-v2 from HuggingFace,
exports to ONNX format, and optionally quantizes to INT8.

Usage:
    python scripts/export_l2_model.py
    python scripts/export_l2_model.py --quantize
    python scripts/export_l2_model.py --output src/prompt_armor/data/models/
"""

from __future__ import annotations

import shutil
from pathlib import Path

MODEL_ID = "aldenb/scout-prompt-injection-classifier-22m"
DEFAULT_OUTPUT = Path(__file__).parent.parent / "src" / "prompt_armor" / "data" / "models"


def export_model(output_dir: Path, quantize: bool = False) -> None:
    """Export the model to ONNX and optionally quantize."""
    from optimum.onnxruntime import ORTModelForSequenceClassification, ORTQuantizer
    from optimum.onnxruntime.configuration import AutoQuantizationConfig
    from transformers import AutoTokenizer

    output_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = output_dir / "_tmp_export"

    print(f"Downloading and exporting {MODEL_ID}...")
    print(f"Output: {output_dir}")

    # Export to ONNX
    model = ORTModelForSequenceClassification.from_pretrained(
        MODEL_ID,
        export=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)

    # Save to temp dir first
    model.save_pretrained(tmp_dir)
    tokenizer.save_pretrained(tmp_dir)

    if quantize:
        print("Quantizing to INT8...")
        quantizer = ORTQuantizer.from_pretrained(tmp_dir)
        qconfig = AutoQuantizationConfig.avx2(is_static=False)
        quantizer.quantize(save_dir=tmp_dir, quantization_config=qconfig)

    # Move the important files to output dir
    # ONNX model
    onnx_file = tmp_dir / "model.onnx"
    if quantize:
        quantized = tmp_dir / "model_quantized.onnx"
        if quantized.exists():
            onnx_file = quantized

    target_onnx = output_dir / "classifier.onnx"
    shutil.copy2(onnx_file, target_onnx)
    print(f"  Model: {target_onnx} ({target_onnx.stat().st_size / 1024 / 1024:.1f}MB)")

    # Tokenizer - save the fast tokenizer json
    tokenizer_json = tmp_dir / "tokenizer.json"
    if tokenizer_json.exists():
        target_tok = output_dir / "tokenizer.json"
        shutil.copy2(tokenizer_json, target_tok)
        print(f"  Tokenizer: {target_tok}")

    # Config for label mapping
    config_file = tmp_dir / "config.json"
    if config_file.exists():
        target_cfg = output_dir / "config.json"
        shutil.copy2(config_file, target_cfg)

    # Cleanup temp dir
    shutil.rmtree(tmp_dir, ignore_errors=True)

    print("\nDone! Model exported successfully.")
    print(f"Files in {output_dir}:")
    for f in sorted(output_dir.iterdir()):
        if f.name.startswith("."):
            continue
        size = f.stat().st_size / 1024 / 1024
        print(f"  {f.name}: {size:.1f}MB")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Export DeBERTa model to ONNX")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output directory")
    parser.add_argument("--quantize", action="store_true", help="Quantize to INT8")
    args = parser.parse_args()

    export_model(args.output, args.quantize)


if __name__ == "__main__":
    main()
