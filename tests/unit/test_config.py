"""Tests for configuration loading."""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

import yaml

from prompt_armor.config import ShieldConfig, load_config


class TestShieldConfig:
    def test_default_config(self) -> None:
        config = ShieldConfig()
        assert config.weights.l1_regex == 0.20
        assert config.weights.l2_classifier == 0.30
        assert config.weights.l3_similarity == 0.30
        assert config.weights.l4_structural == 0.20
        assert config.thresholds.allow_below == 0.55
        assert config.thresholds.block_above == 0.7
        assert config.thresholds.hard_block == 0.95
        assert config.convergence_boost == 0.10
        assert config.divergence_penalty == 0.15

    def test_custom_weights(self) -> None:
        config = ShieldConfig(
            weights={"l1_regex": 0.5, "l2_classifier": 0.2, "l3_similarity": 0.2, "l4_structural": 0.1}  # type: ignore[arg-type]
        )
        assert config.weights.l1_regex == 0.5


class TestLoadConfig:
    def test_load_defaults_when_no_file(self) -> None:
        config = load_config(Path("/nonexistent/path.yml"))
        assert config == ShieldConfig()

    def test_load_from_yaml(self) -> None:
        data = {
            "weights": {"l1_regex": 0.4, "l4_structural": 0.1},
            "thresholds": {"block_above": 0.9},
        }
        with NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(data, f)
            f.flush()
            config = load_config(Path(f.name))

        assert config.weights.l1_regex == 0.4
        assert config.weights.l4_structural == 0.1
        # Defaults for unspecified fields
        assert config.weights.l2_classifier == 0.30
        assert config.thresholds.block_above == 0.9

    def test_load_empty_yaml(self) -> None:
        with NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("")
            f.flush()
            config = load_config(Path(f.name))

        assert config == ShieldConfig()
