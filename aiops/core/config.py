"""Shared settings for all aiops tools, read from the environment / repo-level .env."""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(REPO_ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    anthropic_model: str
    anthropic_effort: str
    ollama_host: str
    ollama_model: str
    lang: str
    cache_dir: Path
    report_dir: Path


def load_settings() -> Settings:
    return Settings(
        anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-opus-5-5"),
        anthropic_effort=os.getenv("ANTHROPIC_EFFORT", "low"),
        ollama_host=os.getenv("OLLAMA_HOST_URL", "http://localhost:11434"),
        ollama_model=os.getenv("OLLAMA_MODEL", "gemma4:e4b"),
        lang=os.getenv("AIOPS_LANG", "bg"),
        cache_dir=Path(os.getenv("AIOPS_CACHE_DIR", REPO_ROOT / ".cache")),
        report_dir=Path(os.getenv("AIOPS_REPORT_DIR", REPO_ROOT / "reports")),
    )
