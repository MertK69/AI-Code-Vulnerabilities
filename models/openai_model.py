import os
from openai import OpenAI
from config import ModelConfig
from .base import BaseModel


class OpenAIModel(BaseModel):
    def __init__(self, config: ModelConfig) -> None:
        super().__init__(config)
        self._client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    def generate(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self.config.model_id,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content or ""
