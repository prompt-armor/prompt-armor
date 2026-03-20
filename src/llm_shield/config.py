"""Configuration loading and validation for llm-shield."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator


class LayerWeights(BaseModel):
    """Weights for each analysis layer in the fusion step."""

    l1_regex: float = Field(default=0.20, ge=0.0, le=1.0)
    l2_classifier: float = Field(default=0.30, ge=0.0, le=1.0)
    l3_similarity: float = Field(default=0.30, ge=0.0, le=1.0)
    l4_structural: float = Field(default=0.20, ge=0.0, le=1.0)


class ThresholdConfig(BaseModel):
    """Decision thresholds for the gate."""

    allow_below: float = Field(default=0.55, ge=0.0, le=1.0)
    block_above: float = Field(default=0.7, ge=0.0, le=1.0)
    hard_block: float = Field(default=0.95, ge=0.0, le=1.0)
    min_confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class ShieldConfig(BaseModel):
    """Top-level configuration for llm-shield."""

    weights: LayerWeights = Field(default_factory=LayerWeights)
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    convergence_boost: float = Field(default=0.10, ge=0.0, le=1.0)
    divergence_penalty: float = Field(default=0.15, ge=0.0, le=1.0)
    rules_path: Path | None = None
    attacks_path: Path | None = None

    @field_validator("rules_path", "attacks_path", mode="before")
    @classmethod
    def _validate_paths(cls, v: str | Path | None) -> Path | None:
        """Reject path traversal attempts."""
        if v is None:
            return None
        p = Path(v)
        if ".." in p.parts:
            raise ValueError(f"Path traversal not allowed: {v}")
        return p


_CONFIG_FILENAMES = [".llm-shield.yml", ".llm-shield.yaml"]


def _find_config_file() -> Path | None:
    """Search for config file in CWD, then home directory."""
    for name in _CONFIG_FILENAMES:
        # CWD
        p = Path.cwd() / name
        if p.is_file():
            return p
        # Home config dir
        p = Path.home() / ".config" / "llm-shield" / name
        if p.is_file():
            return p
    return None


def load_config(path: Path | None = None) -> ShieldConfig:
    """Load configuration from a YAML file, falling back to defaults.

    Discovery order: explicit path > .llm-shield.yml in CWD > ~/.config/llm-shield/ > defaults.
    """
    if path is None:
        path = _find_config_file()

    if path is None or not path.is_file():
        return ShieldConfig()

    with open(path) as f:
        raw = yaml.safe_load(f)

    if not raw or not isinstance(raw, dict):
        return ShieldConfig()

    return ShieldConfig.model_validate(raw)
