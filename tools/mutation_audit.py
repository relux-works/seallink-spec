#!/usr/bin/env python3
"""
Exhaustive Multi-Core Mutation Auditor for SealLink Reference Verifier Core.

Enumerates EVERY single-line refusal return statement in `tools/seallink_verifier.py`,
replaces each one individually with `pass  # MUTANT`, and runs
`tools/speclint.py --require-jsonschema` in an isolated temporary working copy
to verify that the conformance suite catches the removed check.

Usage:
    python3 tools/mutation_audit.py [--workers 12] [--json-out path.json]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REFUSAL_CODE_RE = re.compile(r'"([A-Z]{3,}_[A-Z0-9_]{3,})"')


def enumerate_sites(verifier_path: Path) -> list[dict[str, Any]]:
    """Enumerate all single-line refusal return statements in seallink_verifier.py."""
    lines = verifier_path.read_text(encoding="utf-8").splitlines()
    sites: list[dict[str, Any]] = []
    cur_fn = "<module>"
    for idx, line in enumerate(lines):
        stripped_l = line.lstrip()
        if stripped_l.startswith("def "):
            cur_fn = stripped_l.split("(")[0][4:]
        s = line.strip()
        if not s.startswith("return "):
            continue
        m = REFUSAL_CODE_RE.search(s)
        if not m:
            continue
        if s.count("(") != s.count(")") or s.count("[") != s.count("]"):
            continue
        sites.append({
            "line": idx + 1,
            "function": cur_fn,
            "code": m.group(1),
            "prev": lines[idx - 1].strip()[:100] if idx > 0 else "",
            "text": s[:110],
        })
    return sites


def _worker_run(args: tuple[int, list[dict[str, Any]], str]) -> list[dict[str, Any]]:
    wid, chunk, py_exe = args
    if not chunk:
        return []
    tmp_dir = Path(tempfile.mkdtemp(prefix=f"seallink-mut-{wid}-"))
    try:
        repo_copy = tmp_dir / "repo"
        shutil.copytree(
            ROOT,
            repo_copy,
            ignore=shutil.ignore_patterns(".git", "site", "__pycache__", "*.pyc", "dist"),
        )
        vf = repo_copy / "tools" / "seallink_verifier.py"
        orig = vf.read_text(encoding="utf-8")
        orig_lines = orig.splitlines()
        results: list[dict[str, Any]] = []
        for s in chunk:
            lidx = s["line"] - 1
            orig_line = orig_lines[lidx]
            indent = orig_line[: len(orig_line) - len(orig_line.lstrip())]
            mut_lines = list(orig_lines)
            mut_lines[lidx] = indent + "pass  # MUTANT"
            vf.write_text("\n".join(mut_lines) + "\n", encoding="utf-8")
            try:
                proc = subprocess.run(
                    [py_exe, "tools/speclint.py", "--require-jsonschema"],
                    cwd=str(repo_copy),
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                killed = proc.returncode != 0
                tail = (proc.stdout + proc.stderr).strip().splitlines()[-1][:140] if (proc.stdout or proc.stderr).strip() else ""
            except subprocess.TimeoutExpired:
                killed = True
                tail = "timeout"
            results.append({**s, "killed": killed, "tail": tail})
        return results
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Exhaustive mutation audit over tools/seallink_verifier.py refusal branches.")
    parser.add_argument("--workers", type=int, default=min(12, max(1, os.cpu_count() or 4)), help="Parallel worker processes")
    parser.add_argument("--min-kill-pct", type=float, default=95.0, help="Minimum kill percentage required for exit 0")
    parser.add_argument("--json-out", help="Optional path to write full JSON mutation report")
    args = parser.parse_args()

    vf = ROOT / "tools" / "seallink_verifier.py"
    sites = enumerate_sites(vf)
    t0 = time.monotonic()
    chunks = [sites[i :: args.workers] for i in range(args.workers)]
    all_results: list[dict[str, Any]] = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as pool:
        futs = [pool.submit(_worker_run, (wid, ch, sys.executable)) for wid, ch in enumerate(chunks) if ch]
        for f in concurrent.futures.as_completed(futs):
            all_results.extend(f.result())
    all_results.sort(key=lambda r: r["line"])
    elapsed = time.monotonic() - t0

    killed = [r for r in all_results if r["killed"]]
    survived = [r for r in all_results if not r["killed"]]
    pct = (100.0 * len(killed) / len(all_results)) if all_results else 100.0
    print(f"Mutation audit complete in {elapsed:.1f}s ({args.workers} workers): {len(killed)}/{len(all_results)} killed ({pct:.1f}%), {len(survived)} survived.")
    if survived:
        print("\nSurviving refusal sites:")
        for r in survived:
            print(f"  L{r['line']:4d} [{r['function']}] {r['code']:28s} | prev={r['prev']}")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {"total": len(all_results), "killed": len(killed), "survived": len(survived), "kill_pct": round(pct, 2), "results": all_results},
                indent=2,
            ),
            encoding="utf-8",
        )
    return 0 if pct >= args.min_kill_pct else 1


if __name__ == "__main__":
    sys.exit(main())
