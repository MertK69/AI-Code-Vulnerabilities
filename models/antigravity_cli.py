from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from config import ModelConfig
from .base import BaseModel

_SETTINGS_PATH = Path.home() / ".gemini" / "antigravity-cli" / "settings.json"


class AntigravityCLIModel(BaseModel):
    """Uses the local Antigravity CLI (agy) — model is set via settings.json before each call."""

    def __init__(self, config: ModelConfig) -> None:
        super().__init__(config)
        self._bin = shutil.which("agy") or "agy"

    def _set_model(self) -> None:
        settings = {}
        if _SETTINGS_PATH.exists():
            try:
                settings = json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        settings["model"] = self.config.model_id
        _SETTINGS_PATH.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")

    def generate(self, prompt: str) -> str:
        self._set_model()
        cmd = [self._bin, "--print", prompt]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=360,
        )
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip() or "(no output)"
            raise RuntimeError(f"agy CLI rc={proc.returncode}: {detail[:300]}")
        return proc.stdout.strip()
