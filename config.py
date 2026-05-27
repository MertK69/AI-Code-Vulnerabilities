from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
import os
from dotenv import load_dotenv

load_dotenv()


@dataclass
class ModelConfig:
    name: str
    provider: str  # "anthropic" | "openai" | "claude-cli" | "gemini-cli"
    model_id: str
    max_tokens: int = 2048
    temperature: float = 0.0


@dataclass
class SASTConfig:
    semgrep_enabled: bool = True
    codeql_enabled: bool = True
    codeql_path: str = field(default_factory=lambda: os.getenv("CODEQL_PATH", "codeql"))
    semgrep_timeout: int = 60
    codeql_timeout: int = 300


@dataclass
class DatasetConfig:
    name: str
    description: str
    source: str       # "huggingface" | "url"
    hf_dataset: str = ""
    hf_subset: str = ""
    url: str = ""


DATASETS: List[DatasetConfig] = [
    DatasetConfig(
        name="walledai-autocomplete",
        description="walledai/CyberSecEval  –  Autocomplete  (HuggingFace)",
        source="huggingface",
        hf_dataset="walledai/CyberSecEval",
        hf_subset="autocomplete",
    ),
    DatasetConfig(
        name="walledai-instruct",
        description="walledai/CyberSecEval  –  Instruct     (HuggingFace)",
        source="huggingface",
        hf_dataset="walledai/CyberSecEval",
        hf_subset="instruct",
    ),
    DatasetConfig(
        name="purplellama-instruct-v2",
        description="Meta PurpleLlama     –  Instruct v2  (GitHub JSON, 1681 samples)",
        source="url",
        url="https://raw.githubusercontent.com/meta-llama/PurpleLlama/main/CybersecurityBenchmarks/datasets/instruct/instruct-v2.json",
    ),
]


@dataclass
class EvalConfig:
    languages: list[str] = field(default_factory=lambda: ["python", "java"])
    max_samples: int | None = None
    output_dir: str = "results"
    dataset: DatasetConfig = field(default_factory=lambda: DATASETS[0])
    hf_token: str | None = field(default_factory=lambda: os.getenv("HF_TOKEN"))


MODELS: list[ModelConfig] = [
    ModelConfig(name="claude-opus-4-6",        provider="claude-cli",  model_id="claude-opus-4-6"),
    ModelConfig(name="claude-sonnet-4-6",       provider="claude-cli",  model_id="claude-sonnet-4-6"),
    ModelConfig(name="gemini-2.5-flash",        provider="gemini-cli",  model_id="gemini-2.5-flash"),
    ModelConfig(name="gemini-3.1-pro-preview",  provider="gemini-cli",  model_id="gemini-3.1-pro-preview"),
    ModelConfig(name="gemini-2.5-pro",          provider="gemini-cli",  model_id="gemini-2.5-pro"),
]

SAST = SASTConfig()
EVAL = EvalConfig()
