"""Abstract base class for all analysis layers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from prompt_armor.models import LayerResult


def onnx_session_options() -> Any:
    """Single-threaded ONNX Runtime session options for the ML layers.

    The engine already runs the layers in parallel, so letting each ONNX session
    also claim every core oversubscribes the CPU: L1's regex searches (wall-clock
    budget, see l1_regex._REGEX_TIMEOUT_S) then time out and skip rules, which made
    results vary between runs. Measured on the 1,534-sample benchmark (Apple M4):
    one thread per session cut those timeouts from 123 to 0 and lowered median
    latency; long multi-segment inputs pay a little at p95.
    """
    import onnxruntime as ort

    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    return options


class BaseLayer(ABC):
    """Base interface that all analysis layers must implement.

    Each layer runs independently and must be thread-safe since the engine
    dispatches all layers in parallel via ThreadPoolExecutor.
    """

    name: str = "base"

    @property
    def degraded(self) -> bool:
        """True when the layer runs a fallback instead of its real model.

        A degraded layer still returns scores, but the fusion meta-classifier
        was trained on the real model's output, so detection quality no longer
        matches the published metrics. Surfaced via ``LiteEngine.degraded_layers``.
        """
        return False

    @abstractmethod
    def setup(self) -> None:
        """Load models, rules, or other resources. Called once at engine init."""
        ...

    @abstractmethod
    def analyze(self, text: str) -> LayerResult:
        """Analyze a prompt text and return a LayerResult.

        Must be thread-safe. Called from ThreadPoolExecutor.
        """
        ...
