from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class SastFinding:
    tool: str
    rule_id: str
    severity: str
    message: str
    line: int
    cwe: str = ""

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "cwe": self.cwe,
        }


class BaseSastRunner(ABC):
    @abstractmethod
    def analyze(self, code: str, language: str, **kwargs) -> list[SastFinding]:
        """Write code to a temp file, run analysis, return findings."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the underlying tool binary is accessible."""
