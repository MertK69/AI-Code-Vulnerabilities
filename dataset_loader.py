"""Loads CyberSecEval prompts from HuggingFace, a URL, or local JSON files."""

from __future__ import annotations

import json
import logging
import urllib.request
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


def _normalize(row: dict, language: str) -> dict:
    # "test_case_prompt" (Meta/PurpleLlama) and "prompt" (walledai) are both supported
    prompt = row.get("prompt") or row.get("test_case_prompt") or ""
    return {
        "id": row.get("pattern_id") or str(row.get("prompt_id") or ""),
        "language": language,
        "cwe": row.get("cwe_identifier", ""),
        "prompt": prompt,
        "rule": row.get("rule", ""),
        "pattern_desc": row.get("pattern_desc", ""),
        "origin_code": row.get("origin_code", ""),
        "repo": row.get("repo", ""),
        "variant": row.get("variant", ""),
    }


def load_from_huggingface(
    dataset_name: str,
    subset: str,
    languages: List[str],
    max_samples: int | None = None,
    token: str | None = None,
    cache_dir: str = "data",
) -> List[dict]:
    try:
        from datasets import load_dataset
    except ImportError:
        raise ImportError("Run: pip install datasets")

    logger.info("Loading %s / %s from HuggingFace...", dataset_name, subset)

    try:
        ds = load_dataset(dataset_name, subset, token=token, cache_dir=cache_dir)
    except Exception as e:
        msg = str(e).lower()
        if "401" in msg or "unauthorized" in msg or "cannot be accessed" in msg:
            logger.error(
                "Cannot access '%s'. Accept terms at huggingface.co/datasets/%s "
                "and set HF_TOKEN in .env",
                dataset_name, dataset_name,
            )
        raise

    available = set(ds.keys())
    selected = [lang for lang in languages if lang in available]
    missing = [lang for lang in languages if lang not in available]
    if missing:
        logger.warning("Languages not in dataset: %s  (available: %s)", missing, sorted(available))

    rows: List[dict] = []
    for lang in selected:
        lang_rows = [_normalize(row, lang) for row in ds[lang]]
        if max_samples is not None:
            lang_rows = lang_rows[:max_samples]
        rows.extend(lang_rows)

    lang_counts: dict[str, int] = {}
    for r in rows:
        lang_counts[r["language"]] = lang_counts.get(r["language"], 0) + 1
    logger.info("Loaded %d samples: %s", len(rows), lang_counts)
    return rows


def load_from_url(
    url: str,
    languages: List[str],
    max_samples: int | None = None,
) -> List[dict]:
    logger.info("Downloading dataset from %s ...", url)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.load(resp)
    except Exception as e:
        raise RuntimeError(f"Failed to download dataset from {url}: {e}")

    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON array, got {type(data).__name__}")

    by_lang: dict[str, List[dict]] = {lang: [] for lang in languages}
    for row in data:
        lang = (row.get("language") or "").lower()
        if lang in by_lang:
            by_lang[lang].append(_normalize(row, lang))

    rows: List[dict] = []
    for lang_rows in by_lang.values():
        rows.extend(lang_rows[:max_samples] if max_samples is not None else lang_rows)

    lang_counts: dict[str, int] = {}
    for r in rows:
        lang_counts[r["language"]] = lang_counts.get(r["language"], 0) + 1
    logger.info("Loaded %d samples: %s", len(rows), lang_counts)
    return rows


def load_from_local(
    path: str | Path,
    languages: List[str],
    max_samples: int | None = None,
) -> List[dict]:
    path = Path(path)
    files = [path] if path.is_file() else list(path.glob("*.json")) + list(path.glob("*.jsonl"))

    by_lang: dict[str, List[dict]] = {lang: [] for lang in languages}
    for f in files:
        content = f.read_text(encoding="utf-8")
        if f.suffix == ".jsonl":
            data = [json.loads(line) for line in content.splitlines() if line.strip()]
        else:
            data = json.loads(content)
            if isinstance(data, dict):
                data = list(data.values()) if all(isinstance(v, dict) for v in data.values()) else [data]

        for row in data:
            lang = (row.get("language") or "").lower()
            if lang in by_lang:
                by_lang[lang].append(_normalize(row, lang))

    rows: List[dict] = []
    for lang_rows in by_lang.values():
        rows.extend(lang_rows[:max_samples] if max_samples is not None else lang_rows)

    logger.info("Loaded %d samples from local files", len(rows))
    return rows
