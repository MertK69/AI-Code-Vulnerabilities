"""Bearer SAST runner.

Requires Bearer CLI installed and on PATH (or BEARER_PATH env var).
Install: https://docs.bearer.com/reference/installation
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .base import BaseSastRunner, SastFinding

logger = logging.getLogger(__name__)

_LANG_EXT = {
    "python":     ".py",
    "java":       ".java",
    "javascript": ".js",
    "typescript": ".ts",
    "php":        ".php",
    "ruby":       ".rb",
    "go":         ".go",
}

# Bearer severity levels (JSON keys) → normalised severity string
_SEVERITIES = ["critical", "high", "medium", "low", "warning"]


def _find_bearer() -> Optional[str]:
    return shutil.which("bearer")


class BearerRunner(BaseSastRunner):
    def __init__(self, bearer_path: str = "bearer", timeout: int = 120) -> None:
        self._bin = bearer_path if shutil.which(bearer_path) else _find_bearer()
        self._timeout = timeout

    def is_available(self) -> bool:
        if self._bin is None:
            return False
        try:
            proc = subprocess.run(
                [self._bin, "version"],
                capture_output=True,
                timeout=10,
            )
            return proc.returncode == 0
        except Exception:
            return False

    def analyze(self, code: str, language: str, **kwargs) -> list[SastFinding]:
        if language not in _LANG_EXT:
            logger.debug("Bearer: unsupported language %s", language)
            return []

        ext = _LANG_EXT[language]

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / f"target{ext}"
            src.write_text(code, encoding="utf-8")

            cmd = [
                self._bin, "scan",
                "--format", "json",
                "--exit-code", "0",
                "--quiet",
                "--disable-version-check",
                str(src),
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                )
            except subprocess.TimeoutExpired:
                logger.warning("Bearer timed out after %ds", self._timeout)
                return []
            except FileNotFoundError:
                logger.error("bearer binary not found at: %s", self._bin)
                return []

            if proc.returncode != 0:
                logger.debug("Bearer non-zero exit (%d): %s", proc.returncode, proc.stderr[:300])

            # Bearer may emit warnings/progress on stdout before JSON; find the JSON object
            stdout = proc.stdout.strip()
            json_start = stdout.find("{")
            if json_start == -1:
                logger.debug("Bearer: no JSON in output")
                return []
            stdout = stdout[json_start:]

            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                logger.debug("Bearer: failed to parse JSON output")
                return []

            return self._parse(data)

    @staticmethod
    def _parse(data: dict) -> list[SastFinding]:
        findings: list[SastFinding] = []
        seen: set[tuple] = set()

        for severity in _SEVERITIES:
            for item in data.get(severity, []):
                rule_id = item.get("rule_id") or item.get("id") or "unknown"
                message = item.get("description") or item.get("title") or ""
                line = item.get("line_number") or 0

                cwe_ids: list[str] = item.get("cwe_ids") or []
                cwe = cwe_ids[0] if cwe_ids else ""

                key = (rule_id, line)
                if key in seen:
                    continue
                seen.add(key)

                findings.append(SastFinding(
                    tool="bearer",
                    rule_id=rule_id,
                    severity=severity.upper(),
                    message=message,
                    line=int(line),
                    cwe=cwe,
                ))

        return findings
