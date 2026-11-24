#!/usr/bin/env python3
"""
Deterministic single-file Markdown bundle builder for the SealLink Specification.

Compiles the complete modular specification (SPEC-00..07, standard profiles,
conformance & open questions, SLIP template, machine-readable registries,
JSON Schemas, informative guides, and rule inventory) into one self-contained
Markdown document suitable for archival, offline reading, and LLM/agent ingestion.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def shift_headings(markdown: str, shift: int = 1) -> str:
    """Shift Markdown ATX headings outside fenced code blocks by `shift` levels (capped at 6)."""
    out: list[str] = []
    in_fence = False
    fence_char = ""
    fence_len = 0

    for line in markdown.splitlines():
        stripped = line.lstrip()
        fence_match = re.match(r"^(`{3,}|~{3,})", stripped)
        if fence_match:
            marker = fence_match.group(1)
            if not in_fence:
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_len and stripped[len(marker):].strip() == "":
                in_fence = False
            out.append(line)
            continue

        if not in_fence:
            h_match = re.match(r"^(#{1,6})(\s+.*)$", line)
            if h_match:
                level = min(6, len(h_match.group(1)) + shift)
                out.append("#" * level + h_match.group(2))
                continue

        out.append(line)

    return "\n".join(out).rstrip() + "\n"


def first_heading(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.name


def github_anchor(heading: str) -> str:
    s = heading.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"\s+", "-", s)
    return s


def build_bundle(version: str) -> str:
    spec_files = sorted((ROOT / "spec").glob("SPEC-*.md"))
    profile_files = sorted((ROOT / "profiles").glob("PROFILE-*.md"))
    governance_files = [
        p for p in (ROOT / "CONFORMANCE.md", ROOT / "OPEN-QUESTIONS.md", ROOT / "SLIP-TEMPLATE.md")
        if p.exists()
    ]
    registry_files = sorted((ROOT / "registry").glob("*.json"))
    schema_files = sorted((ROOT / "schemas").glob("*.schema.json"))
    guide_files = sorted((ROOT / "guides").glob("GUIDE-*.md"))
    inventory_file = ROOT / "archive" / "rule-inventory.md"
    vector_files = sorted((ROOT / "vectors").glob("*.json"))

    parts: list[str] = []

    # Title & front matter
    parts.append(f"# SealLink Protocol Specification ({version})\n")
    parts.append(
        "> **Single-File Release Bundle** — compiled deterministically from the modular "
        "`relux-works/seallink-spec` repository.\n"
        "> **Authors:** Ivan Oparin, Alexey Grigorev  \n"
        "> **License:** Prose under CC BY 4.0; registries, schemas, vectors, and tooling under MIT.\n"
    )

    # Table of Contents (bold part labels avoid duplicate heading anchors with Part I..VI body sections)
    toc: list[str] = ["## Table of Contents\n"]
    toc.append("**Part I — Normative Core Specifications**")
    for p in spec_files:
        title = first_heading(p)
        toc.append(f"- [{title}](#{github_anchor(title)}) (`{p.relative_to(ROOT)}`)")

    if profile_files:
        toc.append("\n**Part II — Standard Profiles**")
        for p in profile_files:
            title = first_heading(p)
            toc.append(f"- [{title}](#{github_anchor(title)}) (`{p.relative_to(ROOT)}`)")

    if governance_files:
        toc.append("\n**Part III — Conformance, Open Questions, and SLIP Governance**")
        for p in governance_files:
            title = first_heading(p)
            toc.append(f"- [{title}](#{github_anchor(title)}) (`{p.relative_to(ROOT)}`)")

    toc.append("\n**Part IV — Machine-Readable Registries (Normative SSOT)**")
    for p in registry_files:
        heading = f"Registry: {p.name}"
        toc.append(f"- [{heading}](#{github_anchor(heading)}) (`{p.relative_to(ROOT)}`)")

    toc.append("\n**Part V — Formal Wire JSON Schemas (Normative SSOT)**")
    for p in schema_files:
        heading = f"Schema: {p.name}"
        toc.append(f"- [{heading}](#{github_anchor(heading)}) (`{p.relative_to(ROOT)}`)")

    if guide_files:
        toc.append("\n**Part VI — Informative Implementation Guides**")
        for p in guide_files:
            title = first_heading(p)
            toc.append(f"- [{title}](#{github_anchor(title)}) (`{p.relative_to(ROOT)}`)")

    if inventory_file.exists():
        title = first_heading(inventory_file)
        toc.append("\n**Appendix A — Migration Traceability**")
        toc.append(f"- [{title}](#{github_anchor(title)}) (`{inventory_file.relative_to(ROOT)}`)")

    if vector_files:
        toc.append("\n**Appendix B — Conformance Vector Manifest**")
        toc.append("- [Conformance Vector Manifest](#conformance-vector-manifest) (`vectors/*.json`)")

    parts.append("\n".join(toc) + "\n")

    # Part I: Core Specs
    parts.append("---\n\n## Part I — Normative Core Specifications\n")
    for p in spec_files:
        parts.append("---\n")
        parts.append(shift_headings(p.read_text(encoding="utf-8"), shift=1))

    # Part II: Profiles
    if profile_files:
        parts.append("---\n\n## Part II — Standard Profiles\n")
        for p in profile_files:
            parts.append("---\n")
            parts.append(shift_headings(p.read_text(encoding="utf-8"), shift=1))

    # Part III: Governance
    if governance_files:
        parts.append("---\n\n## Part III — Conformance, Open Questions, and SLIP Governance\n")
        for p in governance_files:
            parts.append("---\n")
            parts.append(shift_headings(p.read_text(encoding="utf-8"), shift=1))

    # Part IV: Registries
    parts.append("---\n\n## Part IV — Machine-Readable Registries (Normative SSOT)\n")
    for p in registry_files:
        parsed = json.loads(p.read_text(encoding="utf-8"))
        pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
        parts.append(f"### Registry: {p.name}\n\n*Source:* `{p.relative_to(ROOT)}`\n\n```json\n{pretty}\n```\n")

    # Part V: Schemas
    parts.append("---\n\n## Part V — Formal Wire JSON Schemas (Normative SSOT)\n")
    for p in schema_files:
        parsed = json.loads(p.read_text(encoding="utf-8"))
        pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
        parts.append(f"### Schema: {p.name}\n\n*Source:* `{p.relative_to(ROOT)}`\n\n```json\n{pretty}\n```\n")

    # Part VI: Guides
    if guide_files:
        parts.append("---\n\n## Part VI — Informative Implementation Guides\n")
        for p in guide_files:
            parts.append("---\n")
            parts.append(shift_headings(p.read_text(encoding="utf-8"), shift=1))

    # Appendix A: Rule Inventory
    if inventory_file.exists():
        parts.append("---\n\n## Appendix A — Migration Traceability\n")
        parts.append(shift_headings(inventory_file.read_text(encoding="utf-8"), shift=1))

    # Appendix B: Vector Manifest (hashes & descriptions of machine-verified vectors/)
    if vector_files:
        parts.append("---\n\n## Appendix B — Conformance Vector Manifest\n")
        parts.append("### Conformance Vector Manifest\n")
        parts.append("Full machine-verifiable JSON vector files live under `vectors/` in the tagged repository.\n")
        parts.append("| File | Bytes | SHA-256 | Suite Description |")
        parts.append("| --- | ---: | --- | --- |")
        for vf in vector_files:
            raw = vf.read_bytes()
            sha = hashlib.sha256(raw).hexdigest()
            meta = json.loads(raw.decode("utf-8"))
            desc = meta.get("description", "")
            parts.append(f"| `vectors/{vf.name}` | {len(raw)} | `{sha}` | {desc} |")
        parts.append("")

    return "\n".join(parts).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build single-file SealLink specification Markdown bundle.")
    parser.add_argument("--version", default="v1.0.0-draft.7", help="Release version label (e.g. v1.0.0-draft.7)")
    parser.add_argument("--out", help="Output path for bundled Markdown file")
    parser.add_argument("--sha256-out", help="Optional path to write SHA-256 checksum file")
    parser.add_argument("--check", action="store_true", help="Build in memory and verify non-empty deterministic output without writing")
    args = parser.parse_args()

    bundle = build_bundle(args.version)
    bundle_bytes = bundle.encode("utf-8")
    digest = hashlib.sha256(bundle_bytes).hexdigest()

    if args.check:
        if len(bundle_bytes) < 10000:
            print(f"ERROR: Bundle unexpectedly small ({len(bundle_bytes)} bytes)", file=sys.stderr)
            return 1
        print(f"OK: bundle check passed ({len(bundle_bytes)} bytes, sha256={digest})")
        return 0

    if not args.out:
        print("ERROR: --out is required unless --check is specified", file=sys.stderr)
        return 2

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bundle_bytes)

    if args.sha256_out:
        sha_path = Path(args.sha256_out)
        sha_path.parent.mkdir(parents=True, exist_ok=True)
        sha_path.write_text(f"{digest}  {out_path.name}\n", encoding="utf-8")

    print(f"Wrote {out_path} ({len(bundle_bytes)} bytes, sha256={digest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
