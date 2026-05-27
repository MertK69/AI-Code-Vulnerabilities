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

from config import DATASETS, EVAL, MODELS, SAST, DatasetConfig, EvalConfig, ModelConfig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CyberSecEval SAST-based evaluation framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--max-samples", type=int, default=None,
        help="Maximum number of prompts per evaluation (default: all)",
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
        "--no-semgrep", action="store_true",
        help="Disable Semgrep analysis",
    )
    parser.add_argument(
        "--no-codeql", action="store_true",
        help="Disable CodeQL analysis",
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


def select_sast_interactive() -> tuple[bool, bool]:
    """Ask which SAST tools to use. Returns (semgrep, codeql)."""
    options = [
        ("Semgrep",        True,  False),
        ("CodeQL",         False, True),
        ("Semgrep + CodeQL", True,  True),
    ]
    print("┌─ SAST Tools ────────────────────────────────────────────┐")
    for i, (label, *_) in enumerate(options, 1):
        print(f"│  [{i}] {label}")
    print("└─────────────────────────────────────────────────────────┘")

    while True:
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)

        if raw in ("1", "2", "3"):
            label, semgrep, codeql = options[int(raw) - 1]
            print(f"  Using: {label}\n")
            return semgrep, codeql

        print("  Enter 1, 2 or 3.")


def select_samples_interactive() -> int | None:
    """Ask how many samples to test. Returns None for all."""
    print("┌─ Sample Count ──────────────────────────────────────────┐")
    print("│  How many prompts per model?                            │")
    print("│  Enter a number, or press Enter for all                 │")
    print("└─────────────────────────────────────────────────────────┘")

    while True:
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)

        if not raw:
            print("  Running with all samples.\n")
            return None

        try:
            n = int(raw)
        except ValueError:
            print("  Invalid input – enter a number or press Enter for all.")
            continue

        if n <= 0:
            print("  Must be greater than 0.")
            continue

        print(f"  Running with {n} samples per model.\n")
        return n


def select_models_interactive() -> list[ModelConfig]:
    """Show a numbered checklist and return the chosen ModelConfigs."""
    print("\n┌─ Model Selection ───────────────────────────────────────┐")
    for i, m in enumerate(MODELS, 1):
        provider_tag = "Claude" if m.provider == "claude-cli" else "Gemini"
        print(f"│  [{i}] {m.name:<30}  ({provider_tag})")
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
            return list(MODELS)

        try:
            indices = [int(x) for x in raw.replace(",", " ").split()]
        except ValueError:
            print("  Invalid input – enter numbers or 'all'.")
            continue

        invalid = [i for i in indices if not (1 <= i <= len(MODELS))]
        if invalid:
            print(f"  Out of range: {invalid}. Valid: 1–{len(MODELS)}")
            continue

        selected = [MODELS[i - 1] for i in indices]
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

    # Model selection: CLI flag skips interactive menu
    if args.models:
        model_configs = [m for m in MODELS if m.name in args.models]
        if not model_configs:
            print(f"ERROR: no matching models. Available: {[m.name for m in MODELS]}")
            return 1
    else:
        model_configs = select_models_interactive()

    # Dataset selection: --dataset flag skips interactive menu
    if args.dataset:
        dataset_cfg = next((d for d in DATASETS if d.name == args.dataset), None)
        if not dataset_cfg:
            print(f"ERROR: unknown dataset '{args.dataset}'. Available: {[d.name for d in DATASETS]}")
            return 1
    else:
        dataset_cfg = select_dataset_interactive()

    # Sample count: CLI flag skips interactive prompt
    max_samples = args.max_samples if args.max_samples is not None else select_samples_interactive()

    # SAST selection: CLI flags skip interactive menu
    if args.no_semgrep or args.no_codeql:
        SAST.semgrep_enabled = not args.no_semgrep
        SAST.codeql_enabled = not args.no_codeql
    else:
        SAST.semgrep_enabled, SAST.codeql_enabled = select_sast_interactive()

    # Build effective config
    eval_cfg = EvalConfig(
        languages=args.languages or EVAL.languages,
        max_samples=max_samples,
        output_dir=args.output_dir or EVAL.output_dir,
        dataset=dataset_cfg,
        hf_token=EVAL.hf_token,
    )

    # Load dataset
    if args.local_data:
        from dataset_loader import load_from_local
        prompts = load_from_local(args.local_data, eval_cfg.languages)
    elif dataset_cfg.source == "url":
        from dataset_loader import load_from_url
        prompts = load_from_url(
            url=dataset_cfg.url,
            languages=eval_cfg.languages,
            max_samples=eval_cfg.max_samples,
        )
    else:
        from dataset_loader import load_from_huggingface
        prompts = load_from_huggingface(
            dataset_name=dataset_cfg.hf_dataset,
            subset=dataset_cfg.hf_subset,
            languages=eval_cfg.languages,
            max_samples=eval_cfg.max_samples,
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
    print(f"Dataset loaded: {len(prompts)} prompts")
    print(f"  Languages:   {dict(lang_dist)}")
    print(f"  Unique CWEs: {len(cwe_dist)}")
    print(f"  Top 5 CWEs:  {cwe_dist.most_common(5)}")
    print(f"  Models:      {[m.name for m in model_configs]}")
    print(f"  SAST:        semgrep={'on' if SAST.semgrep_enabled else 'off'}  "
          f"codeql={'on' if SAST.codeql_enabled else 'off'}")

    if args.dry_run:
        print("\nDry run - exiting without evaluation.")
        return 0

    from evaluator import Evaluator
    evaluator = Evaluator(model_configs, eval_cfg, SAST)
    evaluator.run(prompts)

    return 0


if __name__ == "__main__":
    sys.exit(main())
