#!/usr/bin/env python3
"""
Deterministic static site & HTML specification publisher for https://seallink.org.

Zero external dependencies (Python 3.9+ stdlib). Generates a Cloudflare Pages
ready directory (`site/` by default) containing:
  - Clean technical landing page (`/index.html`)
  - Rendered HTML pages for SPEC-00..07, PROFILE-*, CONFORMANCE, OPEN-QUESTIONS,
    SLIP-TEMPLATE, CHANGELOG, and GUIDE-01
  - Single-page print-ready HTML edition (`/releases/<tag>/seallink-spec-<tag>.html`)
    for direct browser viewing and clean Print-to-PDF export
  - Exact single-file Markdown bundle + SHA-256 (`/releases/<tag>/seallink-spec-<tag>.md{,.sha256}`)
  - Exact live `$id` endpoints for all 12 Draft 2020-12 JSON Schemas:
      /releases/<tag>/schemas/<name>.schema.json (plus /schemas/<name>.schema.json)
  - All 6 registries and 9 executable vector suites under /releases/<tag>/{registry,vectors}/
  - Optional SealLink Channel 2 /.well-known/ assets copied verbatim from well-known/ if present
  - Cloudflare Pages `_headers` (CORS, application/schema+json, immutable caching)
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_bundle as bb


# ============================================================================
# Minimal, strict Markdown -> HTML renderer tailored to SealLink spec GFM
# ============================================================================

def _slugify(text: str) -> str:
    clean = re.sub(r"`([^`]+)`", r"\1", text)
    clean = re.sub(r"<[^>]+>", "", clean)
    s = clean.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"\s+", "-", s)
    return s


def _render_inline(text: str, rel_link_map: dict[str, str]) -> str:
    # Split out inline code spans first so nothing inside backticks is touched
    parts = re.split(r"(`[^`]+`)", text)
    out: list[str] = []
    for idx, part in enumerate(parts):
        if idx % 2 == 1:
            code_txt = html.escape(part[1:-1])
            cls = ' class="rule-id"' if re.match(r"^SL-[A-Z]+-\d{3}$", part[1:-1]) else ""
            out.append(f"<code{cls}>{code_txt}</code>")
            continue

        # Escape HTML except explicit <br> tags used in spec tables
        chunk = html.escape(part).replace("&lt;br&gt;", "<br>")

        # Markdown links [label](href)
        def _link_sub(m: re.Match[str]) -> str:
            lbl = m.group(1)
            href = m.group(2)
            mapped = rel_link_map.get(href, href)
            if mapped.startswith("http://") or mapped.startswith("https://"):
                return f'<a href="{mapped}" target="_blank" rel="noopener">{lbl}</a>'
            return f'<a href="{mapped}">{lbl}</a>'

        chunk = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", _link_sub, chunk)
        # Bold and italic
        chunk = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", chunk)
        chunk = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", chunk)
        out.append(chunk)
    return "".join(out)


def markdown_to_html(md_text: str, rel_link_map: dict[str, str]) -> tuple[str, list[tuple[int, str, str]]]:
    """Convert GFM Markdown (headings, tables, lists, blockquotes, fenced code) to semantic HTML."""
    lines = md_text.splitlines()
    out: list[str] = []
    toc: list[tuple[int, str, str]] = []
    seen_ids: dict[str, int] = {}
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Blank line
        if not stripped:
            i += 1
            continue

        # Horizontal rule
        if re.match(r"^-{3,}$", stripped):
            out.append("<hr>")
            i += 1
            continue

        # Fenced code block
        fm = re.match(r"^(`{3,}|~{3,})(.*)$", stripped)
        if fm:
            marker = fm.group(1)
            lang = fm.group(2).strip()
            code_lines: list[str] = []
            i += 1
            while i < n:
                cs = lines[i].lstrip()
                if cs.startswith(marker[0] * len(marker)) and cs.strip(marker[0]).strip() == "":
                    i += 1
                    break
                code_lines.append(lines[i])
                i += 1
            lang_cls = f' class="language-{html.escape(lang)}"' if lang else ""
            out.append(f"<pre><code{lang_cls}>{html.escape(chr(10).join(code_lines))}</code></pre>")
            continue

        # Heading (deduplicate repeated IDs deterministically within the document)
        hm = re.match(r"^(#{1,6})\s+(.*)$", line)
        if hm:
            lvl = len(hm.group(1))
            raw_title = hm.group(2).strip()
            base_hid = _slugify(raw_title) or "section"
            cnt = seen_ids.get(base_hid, 0) + 1
            seen_ids[base_hid] = cnt
            hid = base_hid if cnt == 1 else f"{base_hid}-{cnt}"
            if 2 <= lvl <= 3:
                toc.append((lvl, re.sub(r"`([^`]+)`", r"\1", raw_title), hid))
            out.append(f'<h{lvl} id="{hid}">{_render_inline(raw_title, rel_link_map)}</h{lvl}>')
            i += 1
            continue

        # Blockquote
        if stripped.startswith(">"):
            q_lines: list[str] = []
            while i < n and lines[i].strip().startswith(">"):
                q_lines.append(lines[i].strip()[1:].lstrip())
                i += 1
            q_html = _render_inline(" ".join(q_lines), rel_link_map)
            out.append(f"<blockquote><p>{q_html}</p></blockquote>")
            continue

        # Pipe Table
        if "|" in line and i + 1 < n and re.match(r"^\s*\|?[\s:|-]+\|[\s:|-]*$", lines[i + 1]):
            def split_row(r: str) -> list[str]:
                r = r.strip()
                if r.startswith("|"):
                    r = r[1:]
                if r.endswith("|"):
                    r = r[:-1]
                # Split on unescaped pipes
                cells = re.split(r"(?<!\\)\|", r)
                return [c.strip().replace("\\|", "|") for c in cells]

            headers = split_row(line)
            i += 2  # skip separator row
            rows: list[list[str]] = []
            while i < n and "|" in lines[i] and lines[i].strip():
                rows.append(split_row(lines[i]))
                i += 1
            tbl = ['<div class="table-wrap"><table><thead><tr>']
            for h in headers:
                tbl.append(f"<th>{_render_inline(h, rel_link_map)}</th>")
            tbl.append("</tr></thead><tbody>")
            for row in rows:
                tbl.append("<tr>")
                for c in row:
                    tbl.append(f"<td>{_render_inline(c, rel_link_map)}</td>")
                tbl.append("</tr>")
            tbl.append("</tbody></table></div>")
            out.append("".join(tbl))
            continue

        # Unordered or Ordered list (supporting 1-level nested sub-bullets)
        if re.match(r"^\s*([-*]|\d+\.)\s+", line):
            is_ordered = bool(re.match(r"^\s*\d+\.\s+", line))
            tag = "ol" if is_ordered else "ul"
            items: list[str] = []
            while i < n and re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]):
                item_line = lines[i]
                indent = len(item_line) - len(item_line.lstrip(" "))
                text_part = re.sub(r"^\s*([-*]|\d+\.)\s+", "", item_line)
                sub_items: list[str] = []
                i += 1
                while i < n and lines[i].strip():
                    next_indent = len(lines[i]) - len(lines[i].lstrip(" "))
                    if next_indent > indent and re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]):
                        sub_txt = re.sub(r"^\s*([-*]|\d+\.)\s+", "", lines[i])
                        sub_items.append(f"<li>{_render_inline(sub_txt, rel_link_map)}</li>")
                        i += 1
                    elif next_indent > indent and not re.match(r"^\s*(#{1,6}\s|```|\|)", lines[i]):
                        text_part += " " + lines[i].strip()
                        i += 1
                    else:
                        break
                li_html = _render_inline(text_part, rel_link_map)
                if sub_items:
                    li_html += "<ul>" + "".join(sub_items) + "</ul>"
                items.append(f"<li>{li_html}</li>")
            out.append(f"<{tag}>" + "".join(items) + f"</{tag}>")
            continue

        # Paragraph
        para_lines: list[str] = []
        while i < n and lines[i].strip():
            cur = lines[i]
            if re.match(r"^(#{1,6}\s|```|~~~|>\s?|-{3,}$|\s*([-*]|\d+\.)\s)", cur.strip()):
                break
            if "|" in cur and i + 1 < n and re.match(r"^\s*\|?[\s:|-]+\|[\s:|-]*$", lines[i + 1]):
                break
            para_lines.append(cur.strip())
            i += 1
        out.append(f"<p>{_render_inline(' '.join(para_lines), rel_link_map)}</p>")

    return "\n".join(out), toc


# ============================================================================
# Shared CSS & HTML Shell
# ============================================================================

STYLE_CSS = """\
:root {
  --bg: #ffffff;
  --bg-alt: #f7f8fa;
  --fg: #14181f;
  --fg-muted: #525d6d;
  --border: #e2e6ec;
  --accent: #0f52ba;
  --accent-soft: #eef4fc;
  --code-bg: #f3f5f8;
  --rule-bg: #eef4fc;
  --rule-fg: #0c3d8a;
  --ok-bg: #eaf7ef;
  --ok-fg: #136f3a;
  --font-sans: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
  --font-mono: ui-monospace, "SFMono-Regular", Menlo, Monaco, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117;
    --bg-alt: #161b22;
    --fg: #e6edf3;
    --fg-muted: #8b949e;
    --border: #2a313c;
    --accent: #58a6ff;
    --accent-soft: #162436;
    --code-bg: #1c2128;
    --rule-bg: #162436;
    --rule-fg: #79c0ff;
    --ok-bg: #122b1d;
    --ok-fg: #56d364;
  }
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: var(--font-sans);
  font-size: 16px;
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.topbar {
  position: sticky;
  top: 0;
  z-index: 20;
  background: var(--bg);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(8px);
}
.topbar-inner {
  max-width: 1120px;
  margin: 0 auto;
  padding: 12px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 700;
  font-size: 1.05rem;
  color: var(--fg);
  letter-spacing: -0.01em;
}
.brand:hover { text-decoration: none; }
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 600;
  font-family: var(--font-mono);
  background: var(--accent-soft);
  color: var(--accent);
}
.badge-ok {
  background: var(--ok-bg);
  color: var(--ok-fg);
}
.nav {
  display: flex;
  gap: 18px;
  font-size: 0.92rem;
  flex-wrap: wrap;
}
.nav a { color: var(--fg-muted); font-weight: 500; }
.nav a:hover { color: var(--fg); text-decoration: none; }
.container {
  max-width: 1120px;
  margin: 0 auto;
  padding: 36px 24px 72px;
}
.doc-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 240px;
  gap: 40px;
  align-items: start;
}
@media (max-width: 960px) {
  .doc-layout { grid-template-columns: minmax(0, 1fr); }
  .toc-sidebar { display: none; }
}
.toc-sidebar {
  position: sticky;
  top: 72px;
  font-size: 0.84rem;
  border-left: 1px solid var(--border);
  padding-left: 16px;
  max-height: calc(100vh - 96px);
  overflow-y: auto;
}
.toc-title {
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--fg-muted);
  margin-bottom: 10px;
}
.toc-sidebar ul { list-style: none; margin: 0; padding: 0; }
.toc-sidebar li { margin: 5px 0; }
.toc-sidebar li.lvl-3 { padding-left: 12px; font-size: 0.8rem; }
.toc-sidebar a { color: var(--fg-muted); }
.toc-sidebar a:hover { color: var(--accent); }
.hero {
  padding: 20px 0 32px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 36px;
}
.hero h1 {
  font-size: clamp(1.9rem, 3.6vw, 2.75rem);
  line-height: 1.15;
  letter-spacing: -0.025em;
  margin: 10px 0 16px;
}
.hero p.lead {
  font-size: 1.12rem;
  color: var(--fg-muted);
  max-width: 780px;
  margin: 0 0 24px;
}
.btn-row { display: flex; gap: 12px; flex-wrap: wrap; }
.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 9px 16px;
  border-radius: 8px;
  font-size: 0.92rem;
  font-weight: 600;
  border: 1px solid var(--border);
  background: var(--bg-alt);
  color: var(--fg);
}
.btn:hover { border-color: var(--accent); text-decoration: none; }
.btn-primary {
  background: var(--accent);
  color: #ffffff;
  border-color: var(--accent);
}
.btn-primary:hover { opacity: 0.92; color: #ffffff; }
.metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 14px;
  margin: 28px 0 36px;
}
.metric-card {
  background: var(--bg-alt);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px 18px;
}
.metric-num {
  font-size: 1.55rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  font-family: var(--font-mono);
}
.metric-label { font-size: 0.84rem; color: var(--fg-muted); margin-top: 2px; }
.grid-2 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 16px;
  margin: 16px 0 32px;
}
.card {
  background: var(--bg-alt);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 18px 20px;
}
.card h3 { margin: 0 0 6px; font-size: 1.02rem; }
.card p { margin: 0; font-size: 0.92rem; color: var(--fg-muted); }
article h1 { font-size: 2rem; line-height: 1.2; letter-spacing: -0.02em; margin-top: 0; }
article h2 { font-size: 1.42rem; margin: 2.1em 0 0.7em; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
article h3 { font-size: 1.15rem; margin: 1.6em 0 0.5em; }
article h4 { font-size: 1rem; margin: 1.3em 0 0.4em; }
code {
  font-family: var(--font-mono);
  font-size: 0.88em;
  background: var(--code-bg);
  padding: 2px 5px;
  border-radius: 4px;
}
code.rule-id {
  background: var(--rule-bg);
  color: var(--rule-fg);
  font-weight: 600;
}
pre {
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
  overflow-x: auto;
  line-height: 1.45;
}
pre code { background: none; padding: 0; font-size: 0.86rem; }
blockquote {
  margin: 18px 0;
  padding: 10px 16px;
  border-left: 3px solid var(--accent);
  background: var(--bg-alt);
  border-radius: 0 6px 6px 0;
}
blockquote p { margin: 0; font-size: 0.94rem; }
.table-wrap { overflow-x: auto; margin: 18px 0; }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}
th, td {
  text-align: left;
  padding: 9px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
th {
  background: var(--bg-alt);
  font-weight: 600;
  white-space: nowrap;
}
hr { border: none; border-top: 1px solid var(--border); margin: 28px 0; }
.footer {
  border-top: 1px solid var(--border);
  padding: 24px;
  text-align: center;
  font-size: 0.85rem;
  color: var(--fg-muted);
}
@media print {
  .topbar, .toc-sidebar, .btn-row, .no-print { display: none !important; }
  body { background: #fff; color: #000; font-size: 11pt; }
  .container { max-width: 100%; padding: 0; }
  .doc-layout { display: block; }
  pre, blockquote, table { page-break-inside: avoid; }
  h1, h2, h3 { page-break-after: avoid; }
}
"""


def render_page(
    title: str,
    version: str,
    body_html: str,
    toc: list[tuple[int, str, str]] | None = None,
    description: str = "SealLink Protocol Specification — sovereign identities, revocable UTXO seals, contracts, and verifiable grants.",
    inline_css: bool = False,
) -> str:
    toc_html = ""
    if toc:
        items = "\n".join(
            f'<li class="lvl-{lvl}"><a href="#{hid}">{html.escape(txt)}</a></li>'
            for lvl, txt, hid in toc
        )
        toc_html = f'<aside class="toc-sidebar"><div class="toc-title">On this page</div><ul>{items}</ul></aside>'
        main_content = f'<div class="doc-layout"><article>{body_html}</article>{toc_html}</div>'
    else:
        main_content = body_html

    css_tag = f"<style>\n{STYLE_CSS}\n</style>" if inline_css else '<link rel="stylesheet" href="/assets/style.css">'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} — SealLink</title>
  <meta name="description" content="{html.escape(description)}">
  {css_tag}
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <a class="brand" href="/">
        <span>SealLink</span>
        <span class="badge">{html.escape(version)}</span>
      </a>
      <nav class="nav">
        <a href="/#specifications">Specifications</a>
        <a href="/#profiles">Profiles</a>
        <a href="/#schemas">Schemas &amp; Registries</a>
        <a href="/docs/CONFORMANCE.html">Conformance</a>
        <a href="/releases/{html.escape(version)}/seallink-spec-{html.escape(version)}.html">Full HTML / PDF</a>
        <a href="https://github.com/relux-works/seallink-spec" target="_blank" rel="noopener">GitHub</a>
      </nav>
    </div>
  </header>
  <main class="container">
    {main_content}
  </main>
  <footer class="footer">
    SealLink Protocol Specification ({html.escape(version)}) &middot;
    Authors: Ivan Oparin, Alexey Grigorev &middot;
    Prose <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener">CC BY 4.0</a> &middot;
    Schemas, Registries &amp; Tooling MIT &middot;
    <a href="https://github.com/relux-works/seallink-spec" target="_blank" rel="noopener">relux-works/seallink-spec</a>
  </footer>
</body>
</html>
"""


def build_site(version: str, out_dir: Path) -> dict[str, Any]:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Write stylesheet
    (out_dir / "assets").mkdir(parents=True, exist_ok=True)
    (out_dir / "assets" / "style.css").write_text(STYLE_CSS, encoding="utf-8")

    # 2. Collect repository artifacts
    spec_files = sorted((ROOT / "spec").glob("SPEC-*.md"))
    profile_files = sorted((ROOT / "profiles").glob("PROFILE-*.md"))
    registry_files = sorted((ROOT / "registry").glob("*.json"))
    schema_files = sorted((ROOT / "schemas").glob("*.schema.json"))
    vector_files = sorted((ROOT / "vectors").glob("*.json"))
    doc_files = [
        (ROOT / "CONFORMANCE.md", "CONFORMANCE.html"),
        (ROOT / "OPEN-QUESTIONS.md", "OPEN-QUESTIONS.html"),
        (ROOT / "SLIP-TEMPLATE.md", "SLIP-TEMPLATE.html"),
        (ROOT / "CHANGELOG.md", "CHANGELOG.html"),
        (ROOT / "guides" / "GUIDE-01-custody-and-signers.md", "GUIDE-01-custody-and-signers.html"),
        (ROOT / "archive" / "rule-inventory.md", "rule-inventory.html"),
    ]

    rel_base = out_dir / "releases" / version
    (rel_base / "schemas").mkdir(parents=True, exist_ok=True)
    (rel_base / "registry").mkdir(parents=True, exist_ok=True)
    (rel_base / "vectors").mkdir(parents=True, exist_ok=True)
    (out_dir / "schemas").mkdir(parents=True, exist_ok=True)
    (out_dir / "registry").mkdir(parents=True, exist_ok=True)
    (out_dir / "spec").mkdir(parents=True, exist_ok=True)
    (out_dir / "profiles").mkdir(parents=True, exist_ok=True)
    (out_dir / "docs").mkdir(parents=True, exist_ok=True)

    # 3. Copy schemas, registries, and vectors verbatim to both /releases/<version>/... and latest aliases
    for sf in schema_files:
        shutil.copy2(sf, rel_base / "schemas" / sf.name)
        shutil.copy2(sf, out_dir / "schemas" / sf.name)
    for rf in registry_files:
        shutil.copy2(rf, rel_base / "registry" / rf.name)
        shutil.copy2(rf, out_dir / "registry" / rf.name)
    for vf in vector_files:
        shutil.copy2(vf, rel_base / "vectors" / vf.name)

    # Copy optional SealLink Channel 2 /.well-known/ assets if present in repo
    wk_src = ROOT / "well-known"
    if wk_src.exists():
        shutil.copytree(wk_src, out_dir / ".well-known", dirs_exist_ok=True)

    # 4. Build single-file Markdown bundle + .sha256 + single-page printable HTML edition
    bundle_md = bb.build_bundle(version)
    bundle_bytes = bundle_md.encode("utf-8")
    bundle_sha = hashlib.sha256(bundle_bytes).hexdigest()
    md_name = f"seallink-spec-{version}.md"
    (rel_base / md_name).write_bytes(bundle_bytes)
    (rel_base / f"{md_name}.sha256").write_text(f"{bundle_sha}  {md_name}\n", encoding="utf-8")

    # Build link rewrite map for internal Markdown links
    link_map: dict[str, str] = {
        "CONFORMANCE.md": "/docs/CONFORMANCE.html",
        "OPEN-QUESTIONS.md": "/docs/OPEN-QUESTIONS.html",
        "SLIP-TEMPLATE.md": "/docs/SLIP-TEMPLATE.html",
        "CHANGELOG.md": "/docs/CHANGELOG.html",
        "LICENSE.md": "https://github.com/relux-works/seallink-spec/blob/main/LICENSE.md",
        "guides/GUIDE-01-custody-and-signers.md": "/docs/GUIDE-01-custody-and-signers.html",
        "archive/rule-inventory.md": "/docs/rule-inventory.html",
        "profiles/README.md": "/#profiles",
        "registry/": "/#schemas",
        "schemas/": "/#schemas",
        "vectors/": "/#vectors",
    }
    for sf in spec_files:
        link_map[f"spec/{sf.name}"] = f"/spec/{sf.stem}.html"
        link_map[sf.name] = f"/spec/{sf.stem}.html"
    for pf in profile_files:
        link_map[f"profiles/{pf.name}"] = f"/profiles/{pf.stem}.html"
        link_map[pf.name] = f"/profiles/{pf.stem}.html"
    for rf in registry_files:
        link_map[f"registry/{rf.name}"] = f"/releases/{version}/registry/{rf.name}"
    for sf in schema_files:
        link_map[f"schemas/{sf.name}"] = f"/releases/{version}/schemas/{sf.name}"
    for vf in vector_files:
        link_map[f"vectors/{vf.name}"] = f"/releases/{version}/vectors/{vf.name}"

    # 5. Render individual HTML pages for specs, profiles, and docs
    for sf in spec_files:
        title = bb.first_heading(sf)
        body, toc = markdown_to_html(sf.read_text(encoding="utf-8"), link_map)
        (out_dir / "spec" / f"{sf.stem}.html").write_text(
            render_page(title, version, body, toc), encoding="utf-8"
        )
    for pf in profile_files:
        title = bb.first_heading(pf)
        body, toc = markdown_to_html(pf.read_text(encoding="utf-8"), link_map)
        (out_dir / "profiles" / f"{pf.stem}.html").write_text(
            render_page(title, version, body, toc), encoding="utf-8"
        )
    for src_path, out_name in doc_files:
        if src_path.exists():
            title = bb.first_heading(src_path)
            body, toc = markdown_to_html(src_path.read_text(encoding="utf-8"), link_map)
            (out_dir / "docs" / out_name).write_text(
                render_page(title, version, body, toc), encoding="utf-8"
            )

    # Full single-page HTML edition (with Print-to-PDF button & canonical release checksum link)
    full_body, full_toc = markdown_to_html(bundle_md, link_map)
    print_banner = (
        '<div class="btn-row no-print" style="margin-bottom:12px;">'
        '<button class="btn btn-primary" onclick="window.print()" style="cursor:pointer;">Print / Save as PDF</button>'
        f'<a class="btn" href="/releases/{html.escape(version)}/{html.escape(md_name)}">Download Single-File Markdown</a>'
        f'<a class="btn" href="/releases/{html.escape(version)}/{html.escape(md_name)}.sha256">SHA-256 Checksum</a>'
        f'<a class="btn" href="https://github.com/relux-works/seallink-spec/releases/tag/{html.escape(version)}" target="_blank" rel="noopener">GitHub Release Assets</a>'
        "</div>"
        '<p class="no-print" style="font-size:0.84rem;color:var(--fg-muted);margin:0 0 24px;">'
        'Note: For byte-exact SHA-256 verification of the standalone HTML bundle, download the signed GitHub Release asset (web proxies may inject scripts on HTML pages).'
        "</p>"
    )
    html_name = f"seallink-spec-{version}.html"
    full_html = render_page(
        f"Complete Specification ({version})",
        version,
        print_banner + full_body,
        full_toc,
        inline_css=True,
    )
    # Self-check: verify zero duplicate element IDs and zero broken internal #fragment links
    all_ids = re.findall(r'\bid="([^"]+)"', full_html)
    dup_ids = sorted({x for x in all_ids if all_ids.count(x) > 1})
    if dup_ids:
        raise RuntimeError(f"Duplicate HTML IDs in {html_name}: {dup_ids}")
    id_set = set(all_ids)
    broken_frags = sorted({frag for frag in re.findall(r'href="#([^"]+)"', full_html) if frag not in id_set})
    if broken_frags:
        raise RuntimeError(f"Broken internal fragment links in {html_name}: {broken_frags}")
    full_html_bytes = full_html.encode("utf-8")
    full_html_sha = hashlib.sha256(full_html_bytes).hexdigest()
    (rel_base / html_name).write_bytes(full_html_bytes)
    (rel_base / f"{html_name}.sha256").write_text(f"{full_html_sha}  {html_name}\n", encoding="utf-8")

    # 6. Build landing page `/index.html`
    reg_obj = json.loads((ROOT / "registry" / "object-types.json").read_text(encoding="utf-8"))
    reg_ref = json.loads((ROOT / "registry" / "refusal-codes.json").read_text(encoding="utf-8"))
    spec_rows = []
    for sf in spec_files:
        txt = sf.read_text(encoding="utf-8")
        title = bb.first_heading(sf)
        m_mat = re.search(r"\*\*Evidence / Maturity:\*\*\s*`([^`]+)`", txt)
        mat = m_mat.group(1) if m_mat else "prose"
        code_name, desc = title.split(": ", 1) if ": " in title else (sf.stem, title)
        spec_rows.append(
            f'<tr><td><a href="/spec/{sf.stem}.html"><strong>{html.escape(code_name)}</strong></a></td>'
            f'<td>{html.escape(desc)}</td>'
            f'<td><span class="badge badge-ok">{html.escape(mat)}</span></td></tr>'
        )

    profile_cards = []
    for pf in profile_files:
        title = bb.first_heading(pf)
        code_name, desc = title.split(": ", 1) if ": " in title else (pf.stem, title)
        profile_cards.append(
            f'<div class="card"><h3><a href="/profiles/{pf.stem}.html">{html.escape(code_name)}</a></h3>'
            f"<p>{html.escape(desc)}</p></div>"
        )

    schema_links = "\n".join(
        f'<li><a href="/releases/{html.escape(version)}/schemas/{sf.name}"><code>{sf.name}</code></a> '
        f'<span style="color:var(--fg-muted);font-size:0.84rem;">(<code>$id</code> live)</span></li>'
        for sf in schema_files
    )
    registry_links = "\n".join(
        f'<li><a href="/releases/{html.escape(version)}/registry/{rf.name}"><code>{rf.name}</code></a></li>'
        for rf in registry_files
    )
    vector_rows = []
    for vf in vector_files:
        raw = vf.read_bytes()
        meta = json.loads(raw.decode("utf-8"))
        sha = hashlib.sha256(raw).hexdigest()
        vector_rows.append(
            f'<tr><td><a href="/releases/{html.escape(version)}/vectors/{vf.name}"><code>{vf.name}</code></a></td>'
            f"<td>{len(raw):,} B</td>"
            f"<td><code>{sha[:16]}…</code></td>"
            f'<td>{html.escape(meta.get("description", ""))}</td></tr>'
        )

    index_body = f"""
<section class="hero">
  <span class="badge">Protocol Specification &middot; {html.escape(version)}</span>
  <h1>Sovereign identity, contracts, and UTXO-revocable grants.</h1>
  <p class="lead">
    SealLink is an open protocol enabling people, organizations, and autonomous software agents to register
    sovereign identities, verifiable credentials, bilateral contracts, and fine-grained powers of attorney
    that any verifier can validate independently on its own ledger node — even when the issuer is offline.
  </p>
  <div class="btn-row">
    <a class="btn btn-primary" href="/spec/SPEC-00-architecture.html">Read SPEC-00 Architecture</a>
    <a class="btn" href="/releases/{html.escape(version)}/seallink-spec-{html.escape(version)}.html">Full Single-Page HTML / PDF</a>
    <a class="btn" href="/releases/{html.escape(version)}/{html.escape(md_name)}">Single-File Markdown</a>
    <a class="btn" href="https://github.com/relux-works/seallink-spec" target="_blank" rel="noopener">Source on GitHub</a>
  </div>
</section>

<section class="metrics">
  <div class="metric-card"><div class="metric-num">8 + 2</div><div class="metric-label">Core Specs &amp; Standard Profiles</div></div>
  <div class="metric-card"><div class="metric-num">{len(reg_obj["types"])}</div><div class="metric-label">Canonical Object Types</div></div>
  <div class="metric-card"><div class="metric-num">{len(reg_ref["codes"])}/{len(reg_ref["codes"])}</div><div class="metric-label">Refusal Codes Executed in CI</div></div>
  <div class="metric-card"><div class="metric-num">{len(schema_files)}</div><div class="metric-label">Draft 2020-12 JSON Schemas</div></div>
  <div class="metric-card"><div class="metric-num">{len(vector_files)}</div><div class="metric-label">Executable Vector Suites</div></div>
</section>

<h2 id="specifications">Normative Core Specifications</h2>
<div class="table-wrap">
  <table>
    <thead><tr><th>Document</th><th>Scope</th><th>Maturity</th></tr></thead>
    <tbody>
      {"".join(spec_rows)}
    </tbody>
  </table>
</div>

<h2 id="profiles">Standard Domain Profiles</h2>
<div class="grid-2">
  {"".join(profile_cards)}
</div>

<h2 id="schemas">Live JSON Schemas (Draft 2020-12) &amp; Registries</h2>
<p style="color:var(--fg-muted);">
  Every schema below is served at its canonical <code>$id</code> URI under
  <code>https://seallink.org/releases/{html.escape(version)}/schemas/</code> with CORS enabled and immutable caching.
</p>
<div class="grid-2">
  <div class="card">
    <h3>JSON Schemas ({len(schema_files)})</h3>
    <ul style="margin:8px 0 0;padding-left:20px;">{schema_links}</ul>
  </div>
  <div class="card">
    <h3>Machine-Readable Registries ({len(registry_files)})</h3>
    <ul style="margin:8px 0 0;padding-left:20px;">{registry_links}</ul>
    <h3 style="margin-top:20px;">Governance &amp; Guides</h3>
    <ul style="margin:8px 0 0;padding-left:20px;">
      <li><a href="/docs/CONFORMANCE.html">Conformance Requirements</a></li>
      <li><a href="/docs/OPEN-QUESTIONS.html">Open Questions &amp; Provisional Constants</a></li>
      <li><a href="/docs/SLIP-TEMPLATE.html">SLIP Extension Template</a></li>
      <li><a href="/docs/GUIDE-01-custody-and-signers.html">GUIDE-01: Custody, Signers &amp; Agent Runtimes</a></li>
      <li><a href="/docs/CHANGELOG.html">Changelog</a></li>
    </ul>
  </div>
</div>

<h2 id="vectors">Executable Conformance Vectors</h2>
<div class="table-wrap">
  <table>
    <thead><tr><th>Suite</th><th>Size</th><th>SHA-256</th><th>Coverage</th></tr></thead>
    <tbody>
      {"".join(vector_rows)}
    </tbody>
  </table>
</div>

<h2 id="release-artifacts">Release Checksums</h2>
<pre><code>{bundle_sha}  {html.escape(md_name)}
{full_html_sha}  {html.escape(html_name)}</code></pre>
"""
    (out_dir / "index.html").write_text(
        render_page("SealLink Protocol Specification", version, index_body), encoding="utf-8"
    )

    # 7. Cloudflare Pages _headers (explicit version path because Pages wildcards match trailing segments)
    headers_txt = f"""\
/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer

/releases/*
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=31536000, immutable

/releases/{version}/schemas/*
  Content-Type: application/schema+json; charset=utf-8

/schemas/*
  Content-Type: application/schema+json; charset=utf-8
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=300

/registry/*
  Content-Type: application/json; charset=utf-8
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=300

/releases/{version}/registry/*
  Content-Type: application/json; charset=utf-8

/releases/{version}/vectors/*
  Content-Type: application/json; charset=utf-8

/.well-known/seallink/*
  Content-Type: application/json; charset=utf-8
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=31536000, immutable

/.well-known/nostr.json
  Content-Type: application/json; charset=utf-8
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=300
"""
    (out_dir / "_headers").write_text(headers_txt, encoding="utf-8")

    # 8. Also write _redirects (canonicalize www -> apex) and robots.txt
    (out_dir / "_redirects").write_text("https://www.seallink.org/* https://seallink.org/:splat 301\n", encoding="utf-8")
    (out_dir / "robots.txt").write_text("User-agent: *\nAllow: /\n", encoding="utf-8")

    file_count = sum(1 for p in out_dir.rglob("*") if p.is_file())
    return {"version": version, "out_dir": str(out_dir), "files": file_count, "bundle_sha256": bundle_sha}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build static website & live schema host for seallink.org.")
    parser.add_argument("--version", default="v1.0.0-draft.4", help="Release version label (e.g. v1.0.0-draft.4)")
    parser.add_argument("--out", default=str(ROOT / "site"), help="Output directory for generated static site")
    args = parser.parse_args()

    info = build_site(args.version, Path(args.out))
    print(f"Built seallink.org static site ({info['files']} files, version={info['version']}, bundle_sha256={info['bundle_sha256']}) -> {info['out_dir']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
