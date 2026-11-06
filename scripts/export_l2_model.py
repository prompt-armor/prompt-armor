#!/usr/bin/env python3
"""Build the L2 classifier artifact (ONNX, FP16 weights) from ProtectAI's DeBERTa model.

Downloads the ONNX export that ProtectAI publishes alongside
``protectai/deberta-v3-base-prompt-injection-v2`` (Apache-2.0), pinned by commit
SHA, and stores its large weight matrices as FP16 behind ``Cast`` nodes. ONNX
Runtime folds those casts when the session loads, so inference runs in FP32 and
matches the upstream model on any CPU, at about half the download size.

Why not INT8: dynamic INT8 (``MatMulInteger``) gives different answers on x86
and ARM for this model. Per-channel INT8 matched FP32 on Apple Silicon (98.5%
decision agreement) but not on x86 (94%), and the CI benchmark on x86 dropped to
F1 79.2% where the Mac scored 82.7% with the same INT8 file. FP16 storage agrees with FP32 on 99.9% of the
benchmark on both.

The output folder is what gets uploaded to ``prompt-armor/l2-deberta-onnx`` on
the Hugging Face Hub. prompt-armor hosts its own copy on purpose: v0.9.1
downloaded L2 from a third-party repo that was later withdrawn, which silently
dropped every fresh install to the keyword heuristic (see CHANGELOG 0.9.2).

Requires (export only, not at runtime): onnx, huggingface_hub, numpy.

Usage:
    python scripts/export_l2_model.py
    python scripts/export_l2_model.py --output build/l2-deberta-onnx
    hf upload prompt-armor/l2-deberta-onnx build/l2-deberta-onnx .
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path

# Upstream model, pinned by commit SHA (supply chain). Apache-2.0.
MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"
DEFAULT_OUTPUT = Path(__file__).parent.parent / "build" / "l2-deberta-onnx"
OUTPUT_MODEL = "model_fp16.onnx"

# Files copied verbatim from the upstream ``onnx/`` folder.
_TOKENIZER_FILES = ["tokenizer.json", "config.json"]
# Only matrices this large are stored as FP16 (weights of MatMul / embedding Gather).
_MIN_ELEMENTS = 4096


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fp16_weights(src: Path, dst: Path) -> int:
    """Store 2-D MatMul/Gather weights as FP16 + Cast-to-FP32. Returns how many were converted."""
    import numpy as np
    import onnx
    from onnx import TensorProto, helper, numpy_helper

    model = onnx.load(str(src))
    graph = model.graph
    inits = {i.name: i for i in graph.initializer}
    uses: dict[str, list[tuple[str, int]]] = {}
    for node in graph.node:
        for idx, name in enumerate(node.input):
            if name in inits:
                uses.setdefault(name, []).append((node.op_type, idx))

    casts, converted, dropped = [], [], set()
    for name, init in inits.items():
        if init.data_type != TensorProto.FLOAT or len(init.dims) != 2 or init.dims[0] * init.dims[1] < _MIN_ELEMENTS:
            continue
        consumers = uses.get(name, [])
        if not consumers or not all((op, i) in {("MatMul", 1), ("Gather", 0)} for op, i in consumers):
            continue
        weights = numpy_helper.to_array(init).astype(np.float16)
        converted.append(numpy_helper.from_array(weights, f"{name}_fp16"))
        casts.append(helper.make_node("Cast", [f"{name}_fp16"], [name], to=TensorProto.FLOAT))
        dropped.add(name)

    kept = [i for i in graph.initializer if i.name not in dropped]
    del graph.initializer[:]
    graph.initializer.extend(kept + converted)
    nodes = list(graph.node)
    del graph.node[:]
    graph.node.extend(casts + nodes)
    onnx.save(model, str(dst))
    return len(dropped)


def export_model(output_dir: Path) -> None:
    from huggingface_hub import hf_hub_download

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Downloading {MODEL_ID}@{REVISION[:7]} (ONNX FP32 export)...")
    fp32 = Path(hf_hub_download(MODEL_ID, "onnx/model.onnx", revision=REVISION))
    for name in _TOKENIZER_FILES:
        src = Path(hf_hub_download(MODEL_ID, f"onnx/{name}", revision=REVISION))
        shutil.copy2(src, output_dir / name)
    lic = Path(hf_hub_download(MODEL_ID, "LICENSE", revision=REVISION))
    shutil.copy2(lic, output_dir / "LICENSE")

    print("Storing weight matrices as FP16 (Cast to FP32 at load)...")
    target = output_dir / OUTPUT_MODEL
    n = fp16_weights(fp32, target)
    print(f"  {n} matrices converted -> {target} ({target.stat().st_size / 1024 / 1024:.1f}MB)")

    print("\nSHA-256:")
    for f in sorted(output_dir.iterdir()):
        if f.is_file():
            print(f"  {_sha256(f)}  {f.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the L2 ONNX artifact (FP16 weights)")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output directory")
    args = parser.parse_args()

    export_model(args.output)


if __name__ == "__main__":
    main()
