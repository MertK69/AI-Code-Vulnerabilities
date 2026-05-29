import os
from openai import OpenAI
from config import ModelConfig
from .base import BaseModel

class GeminiAPIModel(BaseModel):
    def __init__(self, config: ModelConfig) -> None:
        super().__init__(config)
        kwargs: dict = {"api_key": os.getenv("GEMINI_API_KEY")}
        if config.api_base_url:
            kwargs["base_url"] = config.api_base_url
        self._client = OpenAI(**kwargs)

    def generate(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self.config.model_id,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content or ""
