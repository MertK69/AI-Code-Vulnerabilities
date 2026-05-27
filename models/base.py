from __future__ import annotations
from abc import ABC, abstractmethod
from config import ModelConfig


class BaseModel(ABC):
    def __init__(self, config: ModelConfig) -> None:
        self.config = config

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Send prompt and return raw response text."""

    @property
    def name(self) -> str:
        return self.config.name
