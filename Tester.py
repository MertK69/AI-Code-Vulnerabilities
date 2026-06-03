#!/usr/bin/env python3
"""CyberSecEval AI Code Vulnerability Framework

Usage examples:
  # Interactive model selection (default)
  python Tester.py

  # Skip interactive selection, run specific models directly
  python Tester.py --models claude-sonnet-4-6 gemini-2.5-flash

  # Limit samples, specific language
  python Tester.py --max-samples 50 --languages python

  # Dry run: show dataset stats without evaluation
  python Tester.py --dry-run
"""

from __future__ import annotations

import argparse
import logging
import sys

import dataclasses
import os

from config import API_MODELS, CLI_MODELS, DATASETS, EVAL, SAST, DatasetConfig, EvalConfig, ModelConfig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CyberSecEval SAST-based evaluation framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--all-samples", action="store_true",
        help="Test all samples in the dataset (skips interactive question)",
    )
    parser.add_argument(
        "--max-samples", type=int, default=None,
        help="Maximum number of prompts per language",
    )
    parser.add_argument(
        "--sample-offset", type=int, default=0,
        help="Skip the first N samples per language (use with --max-samples for a range, e.g. --sample-offset 50 --max-samples 50 = samples 50-99)",
    )
    parser.add_argument(
        "--languages", nargs="+", default=None,
        choices=["python", "java", "javascript", "typescript", "c", "cpp"],
        help="Languages to include (default: python java)",
    )
    parser.add_argument(
        "--models", nargs="+", default=None,
        help="Skip interactive selection and use these model names directly",
    )
    parser.add_argument(
        "--local-data", type=str, default=None,
        help="Path to local JSON/JSONL dataset file or directory",
    )
    parser.add_argument(
        "--dataset", default=None,
        help=f"Dataset name to skip interactive selection (choices: {[d.name for d in DATASETS]})",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help=f"Output directory for results (default: {EVAL.output_dir})",
    )
    parser.add_argument(
        "--security-prompt", action="store_true", default=None,
        help="Enable security wrapper prompt (skips interactive question)",
    )
    parser.add_argument(
        "--no-security-prompt", action="store_true",
        help="Disable security wrapper prompt (skips interactive question)",
    )
    parser.add_argument(
        "--no-semgrep", action="store_true",
        help="Disable Semgrep analysis",
    )
    parser.add_argument(
        "--no-codeql", action="store_true",
        help="Disable CodeQL analysis",
    )
    parser.add_argument(
        "--no-bearer", action="store_true",
        help="Disable Bearer analysis",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Load dataset and print stats, but skip evaluation",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def select_dataset_interactive() -> DatasetConfig:
    """Show dataset options and return the chosen DatasetConfig."""
    print("┌─ Dataset ───────────────────────────────────────────────┐")
    for i, ds in enumerate(DATASETS, 1):
        print(f"│  [{i}] {ds.description}")
    print("└─────────────────────────────────────────────────────────┘")

    while True:
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)

        if raw.isdigit() and 1 <= int(raw) <= len(DATASETS):
            chosen = DATASETS[int(raw) - 1]
            print(f"  Using: {chosen.description.strip()}\n")
            return chosen

        print(f"  Enter a number between 1 and {len(DATASETS)}.")


def select_security_prompt_interactive() -> bool:
    """Ask whether to wrap prompts with the security system prompt."""
    print("┌─ Security Prompt ───────────────────────────────────────┐")
    print("│  Wrap every prompt with a security-hardening prefix?    │")
    print("│  [1] Yes  –  Enhance with Security Prompt               │")
    print("│  [2] No   –  Send original prompts as-is                │")
    print("└─────────────────────────────────────────────────────────┘")

    while True:
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)

        if raw == "1":
            print("  Security prompt enabled.\n")
            return True
        if raw == "2":
            print("  Security prompt disabled.\n")
            return False
        print("  Enter 1 or 2.")


def select_sast_interactive() -> tuple[bool, bool, bool]:
    """Ask which SAST tools to use. Returns (semgrep, codeql, bearer)."""
    options = [
        ("All tools  (Semgrep + CodeQL + Bearer)", True,  True,  True),
        ("Semgrep + Bearer",                       True,  False, True),
        ("Semgrep only",                           True,  False, False),
        ("CodeQL only",                            False, True,  False),
        ("Bearer only",                            False, False, True),
    ]
    print("┌─ SAST Tools ────────────────────────────────────────────┐")
    for i, (label, *_) in enumerate(options, 1):
        print(f"│  [{i}] {label}")
    print("└─────────────────────────────────────────────────────────┘")

    valid = {str(i) for i in range(1, len(options) + 1)}
    while True:
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)

        if raw in valid:
            label, semgrep, codeql, bearer = options[int(raw) - 1]
            print(f"  Using: {label}\n")
            return semgrep, codeql, bearer

        print(f"  Enter a number between 1 and {len(options)}.")


def select_languages_interactive() -> list[str]:
    """Show available languages and return the chosen ones."""
    available = [
        ("Python",     "python"),
        ("Java",       "java")
    ]
    print("┌─ Languages ─────────────────────────────────────────────┐")
    for i, (label, _) in enumerate(available, 1):
        print(f"│  [{i}] {label}")
    print("│")
    print("│  Enter numbers separated by spaces, or 'all'")
    print("└─────────────────────────────────────────────────────────┘")

    while True:
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)

        if not raw:
            print("  Please select at least one language.")
            continue

        if raw.lower() == "all":
            selected = [code for _, code in available]
            print(f"  Selected: {selected}\n")
            return selected

        try:
            indices = [int(x) for x in raw.replace(",", " ").split()]
        except ValueError:
            print("  Invalid input – enter numbers or 'all'.")
            continue

        invalid = [i for i in indices if not (1 <= i <= len(available))]
        if invalid:
            print(f"  Out of range: {invalid}. Valid: 1–{len(available)}")
            continue

        selected = [available[i - 1][1] for i in indices]
        print(f"  Selected: {selected}\n")
        return selected


def _read_int(prompt: str, min_val: int = 0, default: int | None = None) -> int:
    """Read a non-negative integer from stdin, with optional default."""
    while True:
        try:
            suffix = f" [{default}]" if default is not None else ""
            raw = input(f"  {prompt}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)
        if not raw and default is not None:
            return default
        try:
            n = int(raw)
        except ValueError:
            print("  Invalid input – enter a number.")
            continue
        if n < min_val:
            print(f"  Must be >= {min_val}.")
            continue
        return n


def select_samples_interactive() -> tuple[int, int | None]:
    """Ask which sample range to test. Returns (offset, max_samples)."""
    print("┌─ Sample Range ──────────────────────────────────────────┐")
    print("│  Which prompts per language?                            │")
    print("│  [1] All samples                                        │")
    print("│  [2] Custom range  (start index + count)                │")
    print("└─────────────────────────────────────────────────────────┘")

    while True:
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)

        if raw == "1":
            print("  Running with all samples.\n")
            return 0, None

        if raw == "2":
            offset = _read_int("Start index (0-based)", min_val=0, default=0)
            count  = _read_int("Number of samples", min_val=1)
            end = offset + count - 1
            print(f"  Running samples {offset}–{end} ({count} per language).\n")
            return offset, count

        print("  Enter 1 or 2.")


def select_run_mode_interactive() -> str:
    """Ask whether to run via API key or CLI/subscription. Returns 'api' or 'cli'."""
    print("┌─ Run Mode ──────────────────────────────────────────────┐")
    print("│  [1] CLI / Subscription  –  claude / gemini CLI tools   │")
    print("│  [2] API Key             –  Anthropic / Gemini REST API  │")
    print("└─────────────────────────────────────────────────────────┘")

    while True:
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)

        if raw == "1":
            print("  Mode: CLI / Subscription\n")
            return "cli"
        if raw == "2":
            print("  Mode: API Key\n")
            return "api"
        print("  Enter 1 or 2.")


def select_api_params_interactive() -> tuple[float, int]:
    """Ask for temperature and max_tokens. Returns (temperature, max_tokens)."""
    print("┌─ API Parameters ────────────────────────────────────────┐")
    print("│  Configure generation parameters (press Enter = default)│")
    print("└─────────────────────────────────────────────────────────┘")

    # Temperature
    while True:
        try:
            raw = input("  Temperature [0.0 – 1.0, default 0.0]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)
        if not raw:
            temperature = 0.0
            break
        try:
            temperature = float(raw)
            if 0.0 <= temperature <= 1.0:
                break
            print("  Must be between 0.0 and 1.0.")
        except ValueError:
            print("  Invalid number.")

    # Max tokens
    while True:
        try:
            raw = input("  Max tokens [default 2048]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)
        if not raw:
            max_tokens = 2048
            break
        try:
            max_tokens = int(raw)
            if max_tokens > 0:
                break
            print("  Must be greater than 0.")
        except ValueError:
            print("  Invalid number.")

    print(f"  temperature={temperature}  max_tokens={max_tokens}\n")
    return temperature, max_tokens


def _is_placeholder(value: str) -> bool:
    v = value.lower().strip()
    return not v or v.startswith("your_") or v == "placeholder"


def _check_api_keys(model_configs: list[ModelConfig]) -> None:
    """Print key status for all required API keys."""
    needed: dict[str, str] = {}
    for m in model_configs:
        if m.provider == "anthropic":
            needed["ANTHROPIC_API_KEY"] = "Anthropic (Claude)"
        elif m.provider == "gemini-api":
            needed["GEMINI_API_KEY"] = "Gemini API"
    print("┌─ API Keys ──────────────────────────────────────────────┐")
    any_missing = False
    for env_var, label in needed.items():
        value = os.getenv(env_var, "")
        if value and not _is_placeholder(value):
            print(f"│  OK      {env_var} ({label})")
        else:
            reason = "placeholder" if value else "not set"
            print(f"│  MISSING  {env_var} ({reason}) – {label} calls will fail!")
            any_missing = True
    print("└─────────────────────────────────────────────────────────┘")
    if any_missing:
        print("  Set missing keys in your .env file and restart.\n")
    else:
        print()


def select_models_interactive(models: list[ModelConfig]) -> list[ModelConfig]:
    """Show a numbered checklist and return the chosen ModelConfigs."""
    print("\n┌─ Model Selection ───────────────────────────────────────┐")
    for i, m in enumerate(models, 1):
        if m.provider in ("claude-cli", "anthropic"):
            tag = "Claude"
        else:
            tag = "Gemini"
        print(f"│  [{i}] {m.name:<30}  ({tag})")
    print("│")
    print("│  Enter numbers separated by spaces, or 'all'")
    print("└─────────────────────────────────────────────────────────┘")

    while True:
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)

        if not raw:
            print("  Please enter at least one number.")
            continue

        if raw.lower() == "all":
            return list(models)

        try:
            indices = [int(x) for x in raw.replace(",", " ").split()]
        except ValueError:
            print("  Invalid input – enter numbers or 'all'.")
            continue

        invalid = [i for i in indices if not (1 <= i <= len(models))]
        if invalid:
            print(f"  Out of range: {invalid}. Valid: 1–{len(models)}")
            continue

        selected = [models[i - 1] for i in indices]
        print(f"\n  Selected: {[m.name for m in selected]}\n")
        return selected


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s  %(levelname)-8s  %(name)s - %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)

    # Run mode: API key vs CLI/subscription
    if args.models:
        # Infer mode from provided model names: check both lists
        all_known = {m.name: m for m in CLI_MODELS + API_MODELS}
        model_configs = [all_known[n] for n in args.models if n in all_known]
        if not model_configs:
            names = sorted({m.name for m in CLI_MODELS + API_MODELS})
            print(f"ERROR: no matching models. Available: {names}")
            return 1
        run_mode = "api" if any(m.provider not in ("claude-cli", "gemini-cli") for m in model_configs) else "cli"
    else:
        run_mode = select_run_mode_interactive()
        available_models = API_MODELS if run_mode == "api" else CLI_MODELS
        model_configs = select_models_interactive(available_models)

    # API params: only relevant (and asked) in API mode
    if run_mode == "api":
        _check_api_keys(model_configs)
        temperature, max_tokens = select_api_params_interactive()
        model_configs = [
            dataclasses.replace(m, temperature=temperature, max_tokens=max_tokens)
            for m in model_configs
        ]

    # Dataset selection: --dataset flag skips interactive menu
    if args.dataset:
        dataset_cfg = next((d for d in DATASETS if d.name == args.dataset), None)
        if not dataset_cfg:
            print(f"ERROR: unknown dataset '{args.dataset}'. Available: {[d.name for d in DATASETS]}")
            return 1
    else:
        dataset_cfg = select_dataset_interactive()

    # Language selection: --languages flag skips interactive menu
    languages = args.languages if args.languages else select_languages_interactive()

    # Sample count: --all-samples or --max-samples skip interactive prompt
    if args.all_samples:
        sample_offset = 0
        max_samples = None
        print("  Running with all samples.\n")
    elif args.max_samples is not None or args.sample_offset:
        sample_offset = args.sample_offset
        max_samples = args.max_samples
    else:
        sample_offset, max_samples = select_samples_interactive()

    # SAST selection: CLI flags skip interactive menu
    if args.no_semgrep or args.no_codeql or args.no_bearer:
        SAST.semgrep_enabled = not args.no_semgrep
        SAST.codeql_enabled = not args.no_codeql
        SAST.bearer_enabled = not args.no_bearer
    else:
        SAST.semgrep_enabled, SAST.codeql_enabled, SAST.bearer_enabled = select_sast_interactive()

    # Security prompt: CLI flags skip interactive question
    if args.security_prompt and args.no_security_prompt:
        print("ERROR: --security-prompt and --no-security-prompt are mutually exclusive.")
        return 1
    if args.security_prompt:
        use_security_prompt = True
    elif args.no_security_prompt:
        use_security_prompt = False
    else:
        use_security_prompt = select_security_prompt_interactive()

    # Build effective config
    eval_cfg = EvalConfig(
        languages=languages,
        max_samples=max_samples,
        sample_offset=sample_offset,
        output_dir=args.output_dir or EVAL.output_dir,
        dataset=dataset_cfg,
        hf_token=EVAL.hf_token,
        use_security_prompt=use_security_prompt,
    )

    # Load dataset
    if args.local_data:
        from dataset_loader import load_from_local
        prompts = load_from_local(args.local_data, eval_cfg.languages, eval_cfg.max_samples, eval_cfg.sample_offset)
    elif dataset_cfg.source == "url":
        from dataset_loader import load_from_url
        prompts = load_from_url(
            url=dataset_cfg.url,
            languages=eval_cfg.languages,
            max_samples=eval_cfg.max_samples,
            sample_offset=eval_cfg.sample_offset,
        )
    else:
        from dataset_loader import load_from_huggingface
        prompts = load_from_huggingface(
            dataset_name=dataset_cfg.hf_dataset,
            subset=dataset_cfg.hf_subset,
            languages=eval_cfg.languages,
            max_samples=eval_cfg.max_samples,
            sample_offset=eval_cfg.sample_offset,
            token=eval_cfg.hf_token,
            cache_dir="data",
        )

    if not prompts:
        print("ERROR: no prompts loaded. Check your dataset path / HuggingFace token.")
        return 1

    # Stats
    from collections import Counter
    lang_dist = Counter(p["language"] for p in prompts)
    cwe_dist = Counter(p["cwe"] for p in prompts)
    offset_info = f"  (offset {eval_cfg.sample_offset})" if eval_cfg.sample_offset else ""
    print(f"Dataset loaded: {len(prompts)} prompts{offset_info}")
    print(f"  Languages:   {dict(lang_dist)}")
    print(f"  Unique CWEs: {len(cwe_dist)}")
    print(f"  Top 5 CWEs:  {cwe_dist.most_common(5)}")
    print(f"  Models:      {[m.name for m in model_configs]}")
    print(f"  SAST:        semgrep={'on' if SAST.semgrep_enabled else 'off'}  "
          f"codeql={'on' if SAST.codeql_enabled else 'off'}  "
          f"bearer={'on' if SAST.bearer_enabled else 'off'}")
    print(f"  Sec. Prompt: {'on' if eval_cfg.use_security_prompt else 'off'}")

    if args.dry_run:
        print("\nDry run - exiting without evaluation.")
        return 0

    from evaluator import Evaluator
    evaluator = Evaluator(model_configs, eval_cfg, SAST)
    result_path = evaluator.run(prompts)

    from analyzer import summarize, print_summary
    import json
    data = json.loads(result_path.read_text(encoding="utf-8"))
    print("\n" + "═" * 72)
    print("  ANALYZER RESULTS")
    print("═" * 72)
    print_summary(summarize(data))

    return 0


if __name__ == "__main__":
    sys.exit(main())
