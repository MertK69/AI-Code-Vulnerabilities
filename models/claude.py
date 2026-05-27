import os
import anthropic
from config import ModelConfig
from .base import BaseModel


class ClaudeModel(BaseModel):
    def __init__(self, config: ModelConfig) -> None:
        super().__init__(config)
        self._client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    def generate(self, prompt: str) -> str:
        message = self._client.messages.create(
            model=self.config.model_id,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text
