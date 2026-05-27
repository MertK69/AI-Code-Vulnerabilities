"""CodeQL SAST runner.

Requires CodeQL CLI installed and on PATH (or CODEQL_PATH env var).
Download from: https://github.com/github/codeql-action/releases
"""
from __future__ import annotations

import csv
import io
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from .base import BaseSastRunner, SastFinding

logger = logging.getLogger(__name__)

_LANG_EXT = {
    "python": ".py",
    "java": ".java",
}

_CODEQL_LANG = {
    "python": "python",
    "java": "java",
}

# Security query suites shipped with CodeQL
_QUERY_SUITE = {
    "python": "python-security-and-quality.qls",
    "java": "java-security-and-quality.qls",
}


class CodeQLRunner(BaseSastRunner):
    def __init__(self, codeql_path: str = "codeql", timeout: int = 300) -> None:
        self._bin = codeql_path
        self._timeout = timeout

    def is_available(self) -> bool:
        binary = shutil.which(self._bin) or shutil.which("codeql")
        if binary is None:
            return False
        try:
            subprocess.run([binary, "version"], capture_output=True, timeout=10)
            return True
        except Exception:
            return False

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self._timeout,
        )

    def analyze(self, code: str, language: str, **kwargs) -> list[SastFinding]:
        if language not in _CODEQL_LANG:
            logger.debug("CodeQL: unsupported language %s", language)
            return []

        ext = _LANG_EXT[language]
        codeql_lang = _CODEQL_LANG[language]
        suite = _QUERY_SUITE[language]

        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = Path(tmpdir) / "src"
            db_dir = Path(tmpdir) / "db"
            results_file = Path(tmpdir) / "results.csv"

            src_dir.mkdir()
            src_file = src_dir / f"target{ext}"
            src_file.write_text(code, encoding="utf-8")

            # Step 1: create database
            try:
                proc = self._run([
                    self._bin, "database", "create",
                    str(db_dir),
                    f"--language={codeql_lang}",
                    f"--source-root={src_dir}",
                    "--overwrite",
                ])
            except subprocess.TimeoutExpired:
                logger.warning("CodeQL database creation timed out")
                return []
            except FileNotFoundError:
                logger.error("codeql binary not found at: %s", self._bin)
                return []

            if proc.returncode != 0:
                logger.debug("CodeQL db create failed: %s", proc.stderr[:300])
                return []

            # Step 2: run analysis
            try:
                proc = self._run([
                    self._bin, "database", "analyze",
                    str(db_dir),
                    suite,
                    "--format=csv",
                    f"--output={results_file}",
                    "--no-print-diagnostics-summary",
                ])
            except subprocess.TimeoutExpired:
                logger.warning("CodeQL analysis timed out")
                return []

            if proc.returncode != 0:
                logger.debug("CodeQL analyze failed: %s", proc.stderr[:300])
                return []

            if not results_file.exists():
                return []

            return self._parse_csv(results_file.read_text(encoding="utf-8"))

    @staticmethod
    def _parse_csv(content: str) -> list[SastFinding]:
        # CodeQL CSV format: name, description, severity, message, path, start_line, ...
        findings: list[SastFinding] = []
        reader = csv.reader(io.StringIO(content))
        for row in reader:
            if len(row) < 6:
                continue
            name, description, severity, message, _path, start_line, *_ = row
            try:
                line = int(start_line)
            except ValueError:
                line = 0
            findings.append(SastFinding(
                tool="codeql",
                rule_id=name,
                severity=severity.upper(),
                message=message or description,
                line=line,
                cwe="",
            ))
        return findings
