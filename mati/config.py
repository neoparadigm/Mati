"""Mati configuration.

All settings are controlled through MatiConfig. Sensible defaults
ship out of the box — override only what you need.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class MatiConfig:
    """Central configuration for the Mati threat intelligence proxy."""

    # --- LLM backend (where Mati forwards requests) ---
    llm_provider: str = "openrouter"
    llm_api_base: str = "https://openrouter.ai/api/v1"
    llm_api_key: str = field(default_factory=lambda: os.getenv("MATI_LLM_API_KEY", ""))
    llm_model: str = "openrouter/auto"

    # --- Proxy settings ---
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 30100
    proxy_api_key: str = ""  # optional bearer token for the local proxy

    # --- Agent framework ---
    claw_type: str = "openclaw"  # openclaw | copaw | ironclaw | none

    # --- Skills ---
    skills_enabled: bool = True
    skills_dir: str = field(
        default_factory=lambda: str(Path.home() / ".mati" / "skills")
    )
    skills_top_k: int = 6
    auto_evolve: bool = True

    # --- Threat intelligence feeds ---
    nvd_api_key: str = field(default_factory=lambda: os.getenv("NVD_API_KEY", ""))
    github_token: str = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    shodan_api_key: str = field(default_factory=lambda: os.getenv("SHODAN_API_KEY", ""))
    otx_api_key: str = field(default_factory=lambda: os.getenv("OTX_API_KEY", ""))
    hibp_api_key: str = field(default_factory=lambda: os.getenv("HIBP_API_KEY", ""))

    # --- Watchlist ---
    watchlist_path: str = field(
        default_factory=lambda: str(Path.home() / ".mati" / "watchlist.json")
    )

    # --- Data directories ---
    data_dir: str = field(
        default_factory=lambda: str(Path.home() / ".mati" / "data")
    )

    # --- Evolution engine ---
    evolution_enabled: bool = True
    evolution_min_failures: int = 3  # min failures of same root cause before synthesis
    evolution_max_skills_per_cycle: int = 2
    evolution_judge_model: str = ""  # LLM used for failure analysis; empty = use llm_model

    # --- Scoring ---
    scoring_resolution_days: int = 30  # days before marking unresolved as "not exploited"

    # --- Logging ---
    log_level: str = "INFO"

    # --- Derived paths (computed, not user-set) ---
    @property
    def predictions_path(self) -> Path:
        return Path(self.data_dir) / "predictions.jsonl"

    @property
    def ground_truth_path(self) -> Path:
        return Path(self.data_dir) / "ground_truth.jsonl"

    @property
    def scores_dir(self) -> Path:
        return Path(self.data_dir) / "scores"

    @property
    def evolution_log_path(self) -> Path:
        return Path(self.data_dir) / "evolution_log.jsonl"

    def ensure_dirs(self) -> None:
        """Create all required directories."""
        for p in [
            Path(self.data_dir),
            self.scores_dir,
            Path(self.skills_dir),
            Path(self.skills_dir) / "base",
            Path(self.skills_dir) / "evolved",
        ]:
            p.mkdir(parents=True, exist_ok=True)
