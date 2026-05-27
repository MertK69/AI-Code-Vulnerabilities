from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

from .base import BaseSastRunner, SastFinding

logger = logging.getLogger(__name__)

# Language-specific security packs (no login required)
_LANG_CONFIG = {
    "python": "p/python",
    "java": "p/java",
    "javascript": "p/javascript",
    "typescript": "p/typescript",
    "c": "p/c",
    "cpp": "p/cpp",
}

_LANG_EXT = {
    "python": ".py",
    "java": ".java",
    "javascript": ".js",
    "typescript": ".ts",
    "c": ".c",
    "cpp": ".cpp",
}


def _find_semgrep() -> Optional[str]:
    found = shutil.which("semgrep")
    if found:
        return found
    venv_bin = Path(sys.executable).parent / "semgrep"
    if venv_bin.exists():
        return str(venv_bin)
    return None


class SemgrepRunner(BaseSastRunner):
    def __init__(self, timeout: int = 60) -> None:
        self._timeout = timeout
        self._bin = _find_semgrep()

    def is_available(self) -> bool:
        return self._bin is not None

    def analyze(self, code: str, language: str, extra_rule: Optional[str] = None) -> list[SastFinding]:
        ext = _LANG_EXT.get(language, ".txt")
        config = _LANG_CONFIG.get(language, "p/security-audit")

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / f"target{ext}"
            src.write_text(code, encoding="utf-8")

            # Run language pack; optionally also run a dataset-specific rule
            configs = [config]
            if extra_rule:
                configs.append(extra_rule)

            all_findings: list[SastFinding] = []
            for cfg in configs:
                findings = self._run_config(src, cfg, language)
                all_findings.extend(findings)

            return all_findings

    def _run_config(self, src: Path, config: str, language: str) -> list[SastFinding]:
        cmd = [
            self._bin,
            "--config", config,
            "--json",
            "--no-git-ignore",
            "--quiet",
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
            logger.warning("Semgrep timed out after %ds (config=%s)", self._timeout, config)
            return []
        except FileNotFoundError:
            logger.error("semgrep binary not found at: %s", self._bin)
            return []

        if proc.returncode not in (0, 1):
            logger.debug("semgrep stderr (config=%s): %s", config, proc.stderr[:300])

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            logger.debug("semgrep non-JSON output (config=%s)", config)
            return []

        findings: list[SastFinding] = []
        for result in data.get("results", []):
            rule_id = result.get("check_id", "unknown")
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            cwes = metadata.get("cwe", [])
            cwe = cwes[0] if isinstance(cwes, list) and cwes else (cwes if isinstance(cwes, str) else "")
            severity = (extra.get("severity") or metadata.get("confidence") or "INFO").upper()
            message = extra.get("message", "")
            line = result.get("start", {}).get("line", 0)

            findings.append(SastFinding(
                tool="semgrep",
                rule_id=rule_id,
                severity=severity,
                message=message,
                line=line,
                cwe=cwe,
            ))

        return findings
