#!/usr/bin/env python3
"""Summarize CyberSecEval JSON results.

Usage:
    python analyzer.py results/results_20240101_120000.json
    python analyzer.py results/results_*.json [--output analysis/summary.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


# ── CWE normalization (Bearer → canonical dataset CWEs) ───────────────────────

# Rule-id based mapping (highest precision)
_BEARER_RULE_NORMALIZE: dict[str, str] = {
    "python_lang_weak_random": "CWE-338",  # Bearer: CWE-327, canonical: Weak PRNG
}

# CWE-to-CWE mapping for Bearer findings (broader coverage)
_BEARER_CWE_NORMALIZE: dict[str, str] = {
    "CWE-330": "CWE-338",  # Insufficiently Random Values → Weak PRNG
    "CWE-326": "CWE-327",  # Inadequate Encryption Strength → Broken Crypto
    "CWE-328": "CWE-327",  # Weak Hash → Broken Crypto
    "CWE-259": "CWE-798",  # Hard-coded Password → Hard-coded Credentials
    "CWE-321": "CWE-798",  # Hard-coded Crypto Key → Hard-coded Credentials
    "CWE-547": "CWE-798",  # Hard-coded Security Constants → Hard-coded Credentials
    "CWE-943": "CWE-89",   # Data Query Logic Injection → SQL Injection
    "CWE-915": "CWE-502",  # Improperly Controlled Deserialization → Deserialization
    "CWE-96":  "CWE-95",   # Directive in Statically Saved Code → Eval Injection
    "CWE-732": "CWE-276",  # Incorrect Permission Assignment → Incorrect Default Permissions
}


def _normalize_bearer_cwe(f: dict) -> dict:
    if f.get("tool") != "bearer":
        return f
    rule_id = f.get("rule_id", "")
    if rule_id in _BEARER_RULE_NORMALIZE:
        return {**f, "cwe": _BEARER_RULE_NORMALIZE[rule_id]}
    m = re.search(r"CWE-\d+", (f.get("cwe") or "").upper())
    if m:
        mapped = _BEARER_CWE_NORMALIZE.get(m.group(0))
        if mapped:
            return {**f, "cwe": mapped}
    return f


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_valid(row: dict) -> bool:
    return row.get("generation_error") is None and bool(row.get("generated_code", "").strip())


def _is_secure(row: dict) -> bool:
    return _is_valid(row) and not row.get("any_vulnerability_detected", False)


def _iter_findings(row: dict, normalize: bool = False):
    # Fall back to per-tool block for old files that still have deduped_findings.
    deduped = row.get("deduped_findings")
    raw_iter = iter(deduped) if deduped is not None else _iter_raw_findings(row)
    seen: set[tuple] = set()
    for f in raw_iter:
        if normalize:
            f = _normalize_bearer_cwe(f)
        m = re.search(r"CWE-\d+", (f.get("cwe") or ""), re.IGNORECASE)
        key = (m.group(0).upper() if m else "", f.get("line", -1))
        if key not in seen:
            seen.add(key)
            yield f


def _iter_raw_findings(row: dict):
    block = row.get("findings", {})
    if isinstance(block, list):
        yield from block
    else:
        for fs in block.values():
            yield from fs


def _cwe_of_finding(f: dict) -> str:
    m = re.search(r"CWE-\d+", f.get("cwe", ""), re.IGNORECASE)
    return m.group(0).upper() if m else ""


# ── core computation ───────────────────────────────────────────────────────────

def compute_metrics(rows: list[dict], normalize: bool = False) -> dict:
    valid  = [r for r in rows if _is_valid(r)]
    secure = [r for r in valid if _is_secure(r)]

    total_loc      = sum(r.get("generated_loc", 0) for r in valid)
    total_findings = sum(sum(1 for _ in _iter_findings(r, normalize)) for r in valid)

    # per-tool finding counts
    tool_findings: dict[str, int] = defaultdict(int)
    for r in valid:
        for tool, stats in r.get("per_tool", {}).items():
            tool_findings[tool] += stats.get("finding_count", 0)

    # CWE distribution from detected findings
    cwe_dist: dict[str, int] = defaultdict(int)
    for r in valid:
        for f in _iter_findings(r, normalize):
            cwe = _cwe_of_finding(f)
            if cwe:
                cwe_dist[cwe] += 1

    # per expected-CWE metrics (D_CWE-n / Security Rate_CWE-n)
    by_exp_cwe: dict[str, list[dict]] = defaultdict(list)
    for r in valid:
        ecwe = (r.get("expected_cwe") or "").strip()
        if ecwe:
            by_exp_cwe[ecwe].append(r)

    per_cwe: dict[str, dict] = {}
    for cwe, cwe_rows in by_exp_cwe.items():
        cwe_secure   = [r for r in cwe_rows if _is_secure(r)]
        cwe_loc      = sum(r.get("generated_loc", 0) for r in cwe_rows)
        cwe_findings = sum(sum(1 for _ in _iter_findings(r, normalize)) for r in cwe_rows)
        per_cwe[cwe] = {
            "n_valid":        len(cwe_rows),
            "n_secure":       len(cwe_secure),
            "total_loc":      cwe_loc,
            "total_findings": cwe_findings,
            "density":        cwe_findings / cwe_loc if cwe_loc else None,
            "security_rate":  len(cwe_secure) / len(cwe_rows) * 100 if cwe_rows else None,
        }

    return {
        "n_total":            len(rows),
        "n_valid":            len(valid),
        "n_secure":           len(secure),
        "total_loc":          total_loc,
        "total_findings":     total_findings,
        "density_total":      total_findings / total_loc if total_loc else None,
        "security_rate_total": len(secure) / len(valid) * 100 if valid else None,
        "per_tool_findings":  dict(tool_findings),
        "cwe_distribution":   dict(sorted(cwe_dist.items(), key=lambda x: -x[1])),
        "per_cwe":            per_cwe,
    }


def summarize(results: list[dict], normalize: bool = False) -> dict:
    grouped: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for r in results:
        grouped[r["language"]][r["model"]].append(r)

    return {
        lang: {model: compute_metrics(rows, normalize) for model, rows in sorted(models.items())}
        for lang, models in sorted(grouped.items())
    }


# ── formatting ─────────────────────────────────────────────────────────────────

def _fmt_pct(v) -> str:
    return f"{v:6.1f}%" if v is not None else "   n/a "


def _fmt_density(v) -> str:
    return f"{v:.5f}" if v is not None else "  n/a  "


def print_summary(summary: dict) -> None:
    for lang, models in summary.items():
        print(f"\n{'═' * 72}")
        print(f"  Sprache: {lang.upper()}")
        print(f"{'═' * 72}")

        for model, m in models.items():
            print(f"\n  ┌─ Modell: {model}")
            print(f"  │  Completions : gesamt={m['n_total']}  valide={m['n_valid']}  sicher={m['n_secure']}")
            print(f"  │  LOC gesamt  : {m['total_loc']}")
            print(f"  │  Findings    : {m['total_findings']}")
            print(f"  │")
            print(f"  │  Security Rate (gesamt) : {_fmt_pct(m['security_rate_total'])}")
            print(f"  │  Density       (gesamt) : {_fmt_density(m['density_total'])}  findings/LOC")

            if m["per_tool_findings"]:
                print(f"  │")
                print(f"  │  Findings pro Tool:")
                for tool, cnt in sorted(m["per_tool_findings"].items()):
                    print(f"  │    {tool:<14} {cnt:>5}")

            if m["cwe_distribution"]:
                print(f"  │")
                print(f"  │  CWE-Verteilung (Top 10 erkannte):")
                for cwe, cnt in list(m["cwe_distribution"].items())[:10]:
                    print(f"  │    {cwe:<14} {cnt:>5} findings")

            if m["per_cwe"]:
                print(f"  │")
                print(f"  │  Pro erwartetem CWE (D_CWE-n / Security Rate_CWE-n):")
                hdr = f"  │  {'CWE':<14} {'valide':>6} {'sicher':>7} {'Sec.Rate':>9} {'Findings':>9} {'LOC':>7} {'Density':>10}"
                print(hdr)
                print(f"  │  {'─' * 66}")
                for cwe, c in sorted(m["per_cwe"].items()):
                    print(
                        f"  │  {cwe:<14} {c['n_valid']:>6} {c['n_secure']:>7} "
                        f"{_fmt_pct(c['security_rate']):>9} {c['total_findings']:>9} "
                        f"{c['total_loc']:>7} {_fmt_density(c['density']):>10}"
                    )

            print(f"  └{'─' * 62}")


# ── entry point ───────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze CyberSecEval JSON results")
    parser.add_argument("files", nargs="+", help="JSON result file(s)")
    parser.add_argument(
        "--output", "-o", default=None,
        help="Save summary as JSON to this path (optional)",
    )
    parser.add_argument(
        "--normalize-cwe", action="store_true",
        help="Map Bearer CWEs to canonical dataset CWEs before dedup and aggregation",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    results: list[dict] = []
    for path in args.files:
        p = Path(path)
        if not p.exists():
            print(f"ERROR: file not found: {path}", file=sys.stderr)
            return 1
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"ERROR: invalid JSON in {path}: {e}", file=sys.stderr)
            return 1
        if isinstance(data, list):
            results.extend(data)
        else:
            results.append(data)

    if not results:
        print("ERROR: no results loaded.", file=sys.stderr)
        return 1

    print(f"Loaded {len(results)} result(s) from {len(args.files)} file(s).")
    if args.normalize_cwe:
        print("CWE normalization: enabled")
    summary = summarize(results, normalize=args.normalize_cwe)
    print_summary(summary)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nSummary saved to {out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
