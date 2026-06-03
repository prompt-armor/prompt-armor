"""Build the prebuilt L3 FAISS index that ships in the wheel.

Re-embedding the attack corpus on first run is the dominant cold start. Shipping
a prebuilt index in the package (`src/prompt_armor/data/index/`) makes even the
first `pip install` / `docker run` fast — L3 loads it instead of encoding.

The index is keyed by a cross-machine-stable signature (attack-DB content +
pinned `_ONNX_MODEL_REVISION`), so the committed artifact matches any install.

RUN THIS whenever the v2 attack DB or the pinned L3 model revision changes:
    python scripts/build_l3_index.py
then commit the regenerated src/prompt_armor/data/index/* files.
"""

from __future__ import annotations

import shutil
import sys

from prompt_armor.layers.l3_similarity import (
    _BUNDLED_INDEX_PATH,
    _BUNDLED_META_PATH,
    _USER_INDEX_PATH,
    _USER_META_PATH,
    L3SimilarityLayer,
)


def main() -> int:
    # Force a fresh build: clear both the bundled and user copies so setup()
    # cannot short-circuit by loading an existing index.
    for p in (_BUNDLED_INDEX_PATH, _BUNDLED_META_PATH, _USER_INDEX_PATH, _USER_META_PATH):
        p.unlink(missing_ok=True)

    layer = L3SimilarityLayer()
    layer.setup()  # encodes the corpus, builds the index, writes the user cache

    if not layer._use_onnx:
        print("ERROR: ONNX L3 model not available — cannot build a portable bundled index.", file=sys.stderr)
        print("Install the model (it auto-downloads on first L3 setup) and retry.", file=sys.stderr)
        return 1
    if not _USER_INDEX_PATH.exists() or not _USER_META_PATH.exists():
        print("ERROR: setup() did not produce a user-cache index to bundle.", file=sys.stderr)
        return 1

    _BUNDLED_INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_USER_INDEX_PATH, _BUNDLED_INDEX_PATH)
    shutil.copy2(_USER_META_PATH, _BUNDLED_META_PATH)

    size_kb = _BUNDLED_INDEX_PATH.stat().st_size / 1024
    print(f"Bundled L3 index written:\n  {_BUNDLED_INDEX_PATH} ({size_kb:.0f} KB, {layer._index.ntotal} vectors)")
    print(f"  {_BUNDLED_META_PATH}")
    print("Commit these two files. They ship in the wheel and make first-run L3 setup fast.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
