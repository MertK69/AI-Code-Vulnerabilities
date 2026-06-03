"""Core evaluation orchestrator."""

from __future__ import annotations

import csv
import json
import logging
import re
from datetime import datetime
from pathlib import Path

from tqdm import tqdm

from config import EvalConfig, ModelConfig, SASTConfig, apply_security_wrapper
from models import BaseModel, ClaudeModel, GeminiAPIModel, ClaudeCLIModel, GeminiCLIModel, AntigravityCLIModel
from sast import BaseSastRunner, CodeQLRunner, SemgrepRunner, BearerRunner, SastFinding

logger = logging.getLogger(__name__)

_CODE_FENCE = re.compile(
    r"```(?:\w+)?\s*\n(.*?)```",
    re.DOTALL,
)


def _extract_code(text: str) -> str:
    """Pull the first fenced code block, or return the whole text."""
    match = _CODE_FENCE.search(text)
    return match.group(1).strip() if match else text.strip()


def _build_model(cfg: ModelConfig) -> BaseModel:
    if cfg.provider == "anthropic":
        return ClaudeModel(cfg)
    if cfg.provider in ("openai", "gemini-api"):
        return GeminiAPIModel(cfg)
    if cfg.provider == "claude-cli":
        return ClaudeCLIModel(cfg)
    if cfg.provider == "gemini-cli":
        return GeminiCLIModel(cfg)
    if cfg.provider == "agy-cli":
        return AntigravityCLIModel(cfg)
    raise ValueError(f"Unknown provider: {cfg.provider}")


_LANG_DISPLAY = {
    "python": "Python", "java": "Java", "javascript": "JavaScript",
    "typescript": "TypeScript", "c": "C", "cpp": "C++",
    "csharp": "C#", "rust": "Rust", "php": "PHP",
}


def _inject_language(prompt: str, language: str) -> str:
    """Prepend a one-line language hint so the model never generates the wrong language."""
    lang_name = _LANG_DISPLAY.get(language, language.upper())
    return f"[IMPORTANT: Your response must be {lang_name} code only.]\n\n{prompt}"



def _cwe_detected(findings: list[SastFinding], expected_cwe: str) -> bool:
    if not expected_cwe:
        return False
    target = expected_cwe.upper().replace(" ", "")
    for f in findings:
        # Extract all CWE-NNN tokens to avoid CWE-32 matching CWE-326
        cwe_ids = re.findall(r"CWE-\d+", f.cwe.upper())
        if target in cwe_ids:
            return True
    return False


class Evaluator:
    def __init__(
        self,
        model_configs: list[ModelConfig],
        eval_cfg: EvalConfig,
        sast_cfg: SASTConfig,
    ) -> None:
        self._eval_cfg = eval_cfg
        self._sast_cfg = sast_cfg
        self._models = [_build_model(c) for c in model_configs]
        self._sast_runners = self._init_sast(sast_cfg)
        self._output_dir = Path(eval_cfg.output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def _init_sast(self, cfg: SASTConfig) -> list[BaseSastRunner]:
        runners: list[BaseSastRunner] = []
        if cfg.semgrep_enabled:
            r = SemgrepRunner(timeout=cfg.semgrep_timeout)
            if r.is_available():
                runners.append(r)
            else:
                logger.warning("semgrep not found on PATH – skipping")
        if cfg.codeql_enabled:
            r = CodeQLRunner(codeql_path=cfg.codeql_path, timeout=cfg.codeql_timeout)
            if r.is_available():
                runners.append(r)
            else:
                logger.warning("codeql not found at '%s' – skipping", cfg.codeql_path)
        if cfg.bearer_enabled:
            r = BearerRunner(bearer_path=cfg.bearer_path, timeout=cfg.bearer_timeout)
            if r.is_available():
                runners.append(r)
            else:
                logger.warning("bearer not found at '%s' – skipping", cfg.bearer_path)
        return runners

    def run(self, prompts: list[dict]) -> Path:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        all_results: list[dict] = []

        for model in self._models:
            logger.info("Evaluating model: %s  (%d prompts)", model.name, len(prompts))
            model_results = self._eval_model(model, prompts)
            all_results.extend(model_results)
            self._save_json(all_results, run_id)  # incremental – survive mid-run crashes

        self._save_csv(all_results, run_id)
        self._print_summary(all_results)
        return self._output_dir / f"results_{run_id}.json"

    def _eval_model(self, model: BaseModel, prompts: list[dict]) -> list[dict]:
        results = []
        for row in tqdm(prompts, desc=model.name, unit="prompt"):
            result = self._eval_single(model, row)
            results.append(result)
        return results

    def _eval_single(self, model: BaseModel, row: dict) -> dict:
        prompt_id = row["id"]
        language = row["language"]
        expected_cwe = row["cwe"]
        security_prompt_used = self._eval_cfg.use_security_prompt

        prompt = _inject_language(row["prompt"], language)
        if security_prompt_used:
            prompt = apply_security_wrapper(prompt)

        # Generate code
        try:
            raw_response = model.generate(prompt)
            generated_code = _extract_code(raw_response)
            generation_error = None
        except Exception as exc:
            logger.warning("Model %s failed on prompt %s: %s", model.name, prompt_id, exc)
            raw_response = ""
            generated_code = ""
            generation_error = str(exc)

        # Run SAST
        findings_by_tool: dict[str, list[SastFinding]] = {}
        sast_errors: list[str] = []

        if generated_code:
            for runner in self._sast_runners:
                try:
                    tool_findings = runner.analyze(generated_code, language)
                    tool_name = tool_findings[0].tool if tool_findings else runner.__class__.__name__.replace("Runner", "").lower()
                    findings_by_tool[tool_name] = tool_findings
                except Exception as exc:
                    sast_errors.append(f"{runner.__class__.__name__}: {exc}")

        all_findings: list[SastFinding] = [f for fs in findings_by_tool.values() for f in fs]
        expected_cwe_hit = _cwe_detected(all_findings, expected_cwe)

        return {
            "run_timestamp": datetime.now().isoformat(),
            "model": model.name,
            "prompt_id": prompt_id,
            "language": language,
            "expected_cwe": expected_cwe,
            "expected_rule": row.get("rule", ""),
            "security_prompt_used": security_prompt_used,
            "prompt_sent": prompt,
            "generated_code": generated_code,
            "generated_loc": len(generated_code.splitlines()) if generated_code else 0,
            "raw_response": raw_response,
            "generation_error": generation_error,
            "findings": {
                tool: [f.to_dict() for f in fs]
                for tool, fs in findings_by_tool.items()
            },
            "finding_count": len(all_findings),
            "any_vulnerability_detected": len(all_findings) > 0,
            "per_tool": {
                tool: {
                    "finding_count": len(fs),
                    "any_vulnerability_detected": len(fs) > 0,
                }
                for tool, fs in findings_by_tool.items()
            },
            "expected_cwe_detected": expected_cwe_hit,
            "sast_errors": sast_errors,
        }

    def _save_json(self, results: list[dict], run_id: str) -> None:
        path = self._output_dir / f"results_{run_id}.json"
        path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("JSON results saved to %s", path)

    def _save_csv(self, results: list[dict], run_id: str) -> None:
        if not results:
            return
        path = self._output_dir / f"results_{run_id}.csv"
        # Flatten for CSV – exclude large text fields
        flat_fields = [
            "run_timestamp", "model", "prompt_id", "language",
            "expected_cwe", "expected_rule", "security_prompt_used",
            "finding_count", "any_vulnerability_detected", "expected_cwe_detected",
            "generation_error",
        ]
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=flat_fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)
        logger.info("CSV results saved to %s", path)

    @staticmethod
    def _print_summary(results: list[dict]) -> None:
        from collections import defaultdict
        by_model: dict[str, list[dict]] = defaultdict(list)
        for r in results:
            by_model[r["model"]].append(r)

        print("\n" + "=" * 60)
        print("EVALUATION SUMMARY")
        print("=" * 60)

        for model_name, rows in by_model.items():
            total = len(rows)
            any_vuln = sum(1 for r in rows if r["any_vulnerability_detected"])
            cwe_hit = sum(1 for r in rows if r["expected_cwe_detected"])
            errors = sum(1 for r in rows if r["generation_error"])

            print(f"\nModel: {model_name}")
            print(f"  Prompts evaluated:         {total}")
            print(f"  Any vulnerability found:   {any_vuln}/{total} ({any_vuln/total*100:.1f}%)")
            print(f"  Expected CWE detected:     {cwe_hit}/{total} ({cwe_hit/total*100:.1f}%)")
            print(f"  Generation errors:         {errors}")

        print("=" * 60)
