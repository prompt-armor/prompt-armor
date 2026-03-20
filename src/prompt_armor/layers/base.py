"""Abstract base class for all analysis layers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from prompt_armor.models import LayerResult


class BaseLayer(ABC):
    """Base interface that all analysis layers must implement.

    Each layer runs independently and must be thread-safe since the engine
    dispatches all layers in parallel via ThreadPoolExecutor.
    """

    name: str = "base"

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
