from __future__ import annotations

import shutil
import subprocess
from config import ModelConfig
from .base import BaseModel


class GeminiCLIModel(BaseModel):
    """Uses the local Gemini CLI (subscription-based, no API key needed)."""

    def __init__(self, config: ModelConfig) -> None:
        super().__init__(config)
        self._bin = shutil.which("gemini") or "gemini"

    def generate(self, prompt: str) -> str:
        # Gemini appends --prompt value to stdin; passing prompt via stdin is cleaner
        cmd = [self._bin, "--output-format", "text", "--skip-trust"]
        if self.config.model_id:
            cmd += ["--model", self.config.model_id]

        proc = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip() or "(no output)"
            raise RuntimeError(f"gemini CLI rc={proc.returncode}: {detail[:300]}")
        return proc.stdout.strip()
