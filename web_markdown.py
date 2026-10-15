"""Minimal Markdown -> HTML renderer that is safe by construction.

Everything is HTML-escaped first; only a fixed set of tags is ever emitted, links are limited to http(s)/mailto,
and no raw HTML from the source survives. The sell sheet contains text scraped from third-party sites and LLM output,
so rendering it with a permissive library (or a CDN script) next to paid-action buttons would be an XSS risk.

Supported: headings, paragraphs, bold/italic/inline code, links, blockquotes, hr, ordered/unordered (one nesting level)
lists with task boxes, tables, fenced code blocks (rendered with a Copy button container).
"""
from __future__ import annotations

import html
import re

_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_ITAL = re.compile(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])|(?<![\w_])_(?!\s)(.+?)(?<!\s)_(?![\w_])")
_SAFE_URL = re.compile(r"^(https?://|mailto:)", re.I)


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def _inline_plain(text: str) -> str:
    out = _esc(text)

    def link(m: re.Match) -> str:
        label, url = m.group(1), html.unescape(m.group(2))
        if not _SAFE_URL.match(url):
            return label  # drop javascript:, data:, relative etc. - keep the visible text
        return f'<a href="{_esc(url)}" target="_blank" rel="noopener noreferrer">{label}</a>'
    out = _LINK.sub(link, out)
    out = _BOLD.sub(r"<strong>\1</strong>", out)
    out = _ITAL.sub(lambda m: f"<em>{m.group(1) or m.group(2)}</em>", out)
    return out


def inline(text: str) -> str:
    """Code spans are split out first so their content is never interpreted as markdown."""
    parts = re.split(r"(`[^`\n]+`)", text)
    return "".join(f"<code>{_esc(p[1:-1])}</code>" if p.startswith("`") and p.endswith("`") and len(p) > 2
                   else _inline_plain(p) for p in parts)


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def render_markdown(md: str) -> str:
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i = 0
    para: list[str] = []

    def flush_para():
        if para:
            out.append(f"<p>{inline(' '.join(s.strip() for s in para))}</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        fence = re.match(r"^```(\w*)\s*$", stripped)
        if fence:
            flush_para()
            lang, body = fence.group(1), []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                body.append(lines[i])
                i += 1
            i += 1
            label = "Copy message" if lang in {"text", ""} else "Copy"
            out.append(f'<div class="codeblock"><button type="button" class="copy-btn" data-copy="code">{label}</button>'
                       f'<pre><code>{_esc(chr(10).join(body))}</code></pre></div>')
            continue
        if not stripped:
            flush_para()
            i += 1
            continue
        h = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if h:
            flush_para()
            n = len(h.group(1))
            out.append(f"<h{n}>{inline(h.group(2))}</h{n}>")
            i += 1
            continue
        if re.match(r"^(-{3,}|\*{3,}|_{3,})$", stripped):
            flush_para()
            out.append("<hr>")
            i += 1
            continue
        if stripped.startswith(">"):
            flush_para()
            quote = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip().lstrip(">").strip())
                i += 1
            out.append(f"<blockquote>{inline(' '.join(quote))}</blockquote>")
            continue
        if "|" in stripped and i + 1 < len(lines) and re.match(r"^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$", lines[i + 1].strip()):
            flush_para()
            head = _cells(stripped)
            i += 2
            rows = []
            while i < len(lines) and "|" in lines[i] and lines[i].strip():
                rows.append(_cells(lines[i]))
                i += 1
            t = "<div class='tablewrap'><table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in head) + "</tr></thead><tbody>"
            for r in rows:
                r = (r + [""] * len(head))[:len(head)]
                t += "<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>"
            out.append(t + "</tbody></table></div>")
            continue
        li = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", line)
        if li:
            flush_para()
            tag = "ol" if li.group(2)[0].isdigit() else "ul"
            items: list[tuple[int, str]] = []
            while i < len(lines):
                m = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", lines[i])
                if not m:
                    break
                items.append((len(m.group(1)), m.group(3)))
                i += 1
            html_items, depth = [f"<{tag}>"], 0
            base = items[0][0]
            for indent, text in items:
                level = 1 if indent > base else 0
                if level > depth:  # nest inside the previous <li>
                    html_items[-1] = html_items[-1][: -len("</li>")]
                    html_items.append(f"<{tag}>")
                elif level < depth:
                    html_items.append(f"</{tag}></li>")
                depth = level
                text = re.sub(r"^\[ \]\s+", "☐ ", text)
                text = re.sub(r"^\[[xX]\]\s+", "☑ ", text)
                html_items.append(f"<li>{inline(text)}</li>")
            if depth:
                html_items.append(f"</{tag}></li>")
            html_items.append(f"</{tag}>")
            out.append("".join(html_items))
            continue
        para.append(line)
        i += 1
    flush_para()
    return "\n".join(out)
