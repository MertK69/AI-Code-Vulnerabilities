from __future__ import annotations

import os
import shutil
import subprocess
from config import ModelConfig
from .base import BaseModel

# Keys that must not be forwarded to the CLI subprocess —
# the CLI uses its own keychain/OAuth auth, not these env vars.
_STRIP_KEYS = {"ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"}


class ClaudeCLIModel(BaseModel):
    """Uses the local Claude Code CLI (subscription-based, no API key needed)."""

    def __init__(self, config: ModelConfig) -> None:
        super().__init__(config)
        self._bin = shutil.which("claude") or "claude"
        self._env = {k: v for k, v in os.environ.items() if k not in _STRIP_KEYS}

    def generate(self, prompt: str) -> str:
        cmd = [self._bin, "--print"]
        if self.config.model_id:
            cmd += ["--model", self.config.model_id]
        cmd.append(prompt)

        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
            env=self._env,
        )
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip() or "(no output)"
            raise RuntimeError(f"claude CLI rc={proc.returncode}: {detail[:300]}")
        return proc.stdout.strip()
