#!/usr/bin/env python3
"""
Exhaustive Multi-Core Mutation Auditor for SealLink Reference Verifier Core.

Supports four independent mutation operators over `tools/seallink_verifier.py`:
  - refusal-return: deletes each single-line refusal `return` statement (`pass  # MUTANT`)
  - wrong-code:     substitutes each quoted refusal code literal with a different registered code
  - boundary:       shifts comparison operators (`<` <-> `<=`, `>` <-> `>=`)
  - logic:          swaps boolean connectives (`and` <-> `or`) in conditional expressions

Every mutant outcome is classified transparently into:
  - semantic_fail: `speclint.py --require-jsonschema` completed and reported a structured check failure
  - exception:     `speclint.py --require-jsonschema` terminated with an uncaught Python exception/traceback
  - timeout:       subprocess exceeded timeout
  - survived:      `speclint.py --require-jsonschema` exited 0 (mutant undetected)

Usage:
    python3 tools/mutation_audit.py [--mode refusal-return|wrong-code|boundary|logic|all]
                                    [--workers 12] [--min-kill-pct 99.0] [--json-out path.json]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tokenize
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REFUSAL_CODE_RE = re.compile(r'"([A-Z]{3,}_[A-Z0-9_]{3,})"')
BOUNDARY_SWAP = {"<": "<=", "<=": "<", ">": ">=", ">=": ">"}


def enumerate_sites(verifier_path: Path, mode: str = "refusal-return") -> list[dict[str, Any]]:
    """Enumerate mutation sites in `verifier_path` for the requested operator mode."""
    text = verifier_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    fn_at_line: dict[int, str] = {}
    cur_fn = "<module>"
    for idx, line in enumerate(lines, start=1):
        sl = line.lstrip()
        if sl.startswith("def "):
            cur_fn = sl.split("(")[0][4:]
        fn_at_line[idx] = cur_fn

    sites: list[dict[str, Any]] = []
    modes = ["refusal-return", "wrong-code", "boundary", "logic"] if mode == "all" else [mode]

    if "refusal-return" in modes or "wrong-code" in modes:
        for idx, line in enumerate(lines):
            s = line.strip()
            if not s.startswith("return "):
                continue
            m = REFUSAL_CODE_RE.search(line)
            if not m:
                continue
            if s.count("(") != s.count(")") or s.count("[") != s.count("]"):
                continue
            ln = idx + 1
            if "refusal-return" in modes:
                sites.append({
                    "op": "refusal-return",
                    "line": ln,
                    "function": fn_at_line[ln],
                    "code": m.group(1),
                    "prev": lines[idx - 1].strip()[:100] if idx > 0 else "",
                    "text": s[:110],
                })
            if "wrong-code" in modes:
                old_c = m.group(1)
                new_c = "WIRE_JSON" if old_c != "WIRE_JSON" else "WIRE_SIZE"
                sites.append({
                    "op": "wrong-code",
                    "line": ln,
                    "c0": m.start(1),
                    "c1": m.end(1),
                    "new": new_c,
                    "function": fn_at_line[ln],
                    "code": f"{old_c}->{new_c}",
                    "prev": lines[idx - 1].strip()[:100] if idx > 0 else "",
                    "text": s[:110],
                })

    if "boundary" in modes or "logic" in modes:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
        for tok in toks:
            ln = tok.start[0]
            if ln < 1 or ln > len(lines):
                continue
            raw_line = lines[ln - 1]
            # Skip non-verifier self-test helpers or docstrings/comments
            if fn_at_line.get(ln) == "run_verifier_mutation_tests":
                continue
            if "boundary" in modes and tok.type == tokenize.OP and tok.string in BOUNDARY_SWAP:
                new_op = BOUNDARY_SWAP[tok.string]
                sites.append({
                    "op": "boundary",
                    "line": ln,
                    "c0": tok.start[1],
                    "c1": tok.end[1],
                    "new": new_op,
                    "function": fn_at_line[ln],
                    "code": f"{tok.string}->{new_op}",
                    "prev": raw_line.strip()[:100],
                    "text": raw_line.strip()[:110],
                })
            if "logic" in modes and tok.type == tokenize.NAME and tok.string in ("and", "or"):
                new_kw = "or" if tok.string == "and" else "and"
                sites.append({
                    "op": "logic",
                    "line": ln,
                    "c0": tok.start[1],
                    "c1": tok.end[1],
                    "new": new_kw,
                    "function": fn_at_line[ln],
                    "code": f"{tok.string}->{new_kw}",
                    "prev": raw_line.strip()[:100],
                    "text": raw_line.strip()[:110],
                })

    return sites


def _apply_mutation(orig_lines: list[str], site: dict[str, Any]) -> str:
    lidx = site["line"] - 1
    orig_line = orig_lines[lidx]
    mut_lines = list(orig_lines)
    if site["op"] == "refusal-return":
        indent = orig_line[: len(orig_line) - len(orig_line.lstrip())]
        mut_lines[lidx] = indent + "pass  # MUTANT"
    else:
        mut_lines[lidx] = orig_line[: site["c0"]] + site["new"] + orig_line[site["c1"] :]
    return "\n".join(mut_lines) + "\n"


def _classify_outcome(proc: subprocess.CompletedProcess[str]) -> tuple[str, str]:
    combined = (proc.stdout + "\n" + proc.stderr).strip()
    tail = combined.splitlines()[-1][:140] if combined else ""
    if proc.returncode == 0:
        return "survived", tail
    if "Traceback (most recent call last):" in combined:
        return "exception", tail
    return "semantic_fail", tail


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
        orig_lines = vf.read_text(encoding="utf-8").splitlines()
        results: list[dict[str, Any]] = []
        for s in chunk:
            vf.write_text(_apply_mutation(orig_lines, s), encoding="utf-8")
            try:
                proc = subprocess.run(
                    [py_exe, "tools/speclint.py", "--require-jsonschema"],
                    cwd=str(repo_copy),
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                outcome, tail = _classify_outcome(proc)
            except subprocess.TimeoutExpired:
                outcome, tail = "timeout", "timeout"
            results.append({**s, "outcome": outcome, "killed": outcome != "survived", "tail": tail})
        return results
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Multi-operator mutation auditor over tools/seallink_verifier.py.")
    parser.add_argument(
        "--mode",
        choices=["refusal-return", "wrong-code", "boundary", "logic", "all"],
        default="refusal-return",
        help="Mutation operator mode (default: refusal-return)",
    )
    parser.add_argument("--workers", type=int, default=min(12, max(1, os.cpu_count() or 4)), help="Parallel worker processes")
    parser.add_argument("--min-kill-pct", type=float, default=99.0, help="Minimum kill percentage required for exit 0")
    parser.add_argument("--json-out", help="Optional path to write full JSON mutation report")
    args = parser.parse_args()

    vf = ROOT / "tools" / "seallink_verifier.py"
    sites = enumerate_sites(vf, mode=args.mode)
    t0 = time.monotonic()
    chunks = [sites[i :: args.workers] for i in range(args.workers)]
    all_results: list[dict[str, Any]] = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as pool:
        futs = [pool.submit(_worker_run, (wid, ch, sys.executable)) for wid, ch in enumerate(chunks) if ch]
        for f in concurrent.futures.as_completed(futs):
            all_results.extend(f.result())
    all_results.sort(key=lambda r: (r["op"], r["line"], r.get("c0", 0)))
    elapsed = time.monotonic() - t0

    by_op: dict[str, dict[str, int]] = {}
    for r in all_results:
        st = by_op.setdefault(r["op"], {"total": 0, "semantic_fail": 0, "exception": 0, "timeout": 0, "survived": 0})
        st["total"] += 1
        st[r["outcome"]] += 1

    total = len(all_results)
    killed = sum(1 for r in all_results if r["killed"])
    survived = [r for r in all_results if not r["killed"]]
    sem_n = sum(1 for r in all_results if r["outcome"] == "semantic_fail")
    exc_n = sum(1 for r in all_results if r["outcome"] == "exception")
    tmo_n = sum(1 for r in all_results if r["outcome"] == "timeout")
    pct = (100.0 * killed / total) if total else 100.0

    print(
        f"Mutation audit [{args.mode}] complete in {elapsed:.1f}s ({args.workers} workers): "
        f"{killed}/{total} killed ({pct:.1f}%) | "
        f"semantic_fail={sem_n}, exception={exc_n}, timeout={tmo_n}, survived={len(survived)}."
    )
    if len(by_op) > 1:
        for op_name, st in by_op.items():
            op_k = st["total"] - st["survived"]
            op_pct = 100.0 * op_k / st["total"] if st["total"] else 100.0
            print(
                f"  - {op_name:15s}: {op_k:3d}/{st['total']:3d} ({op_pct:5.1f}%) "
                f"[semantic_fail={st['semantic_fail']}, exception={st['exception']}, timeout={st['timeout']}, survived={st['survived']}]"
            )
    if survived:
        print("\nSurviving sites:")
        for r in survived:
            print(f"  [{r['op']:14s}] L{r['line']:4d} [{r['function']}] {r['code']:28s} | {r['text']}")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "mode": args.mode,
                    "total": total,
                    "killed": killed,
                    "semantic_fail": sem_n,
                    "exception": exc_n,
                    "timeout": tmo_n,
                    "survived": len(survived),
                    "kill_pct": round(pct, 2),
                    "by_operator": by_op,
                    "results": all_results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    return 0 if pct >= args.min_kill_pct else 1


if __name__ == "__main__":
    sys.exit(main())
