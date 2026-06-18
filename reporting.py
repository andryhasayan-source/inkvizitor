"""
Инквизитор — построение отчётов (текст и HTML).
ShashevPro · https://www.shashevpro.ru/
"""

from __future__ import annotations

import html
from datetime import datetime

from engine import Finding, FileReport, ScanReport
from i18n import Translator

SITE_URL = "https://www.shashevpro.ru/"

# Значок для текстового отчёта в зависимости от находки
_ICONS: dict[str, str] = {
    "critical": "🚨",
    "high": "⚠️",
    "medium": "⚠️",
    "low": "📌",
    "info": "📝",
}
_STATUS_ICON = {"green": "✅", "yellow": "⚠️", "red": "🚨"}
# Цвета статусов и уровней для HTML
_SEV_COLOR = {
    "critical": "#f85149",
    "high": "#ff7b54",
    "medium": "#d29922",
    "low": "#58a6ff",
    "info": "#8b949e",
}
_STATUS_COLOR = {"green": "#3fb950", "yellow": "#d29922", "red": "#f85149"}


def _finding_icon(finding: Finding) -> str:
    if finding.kind == "author_mark":
        return "👤"
    if finding.kind == "secret":
        return "🔑"
    return _ICONS.get(finding.severity, "•")


def _location(finding: Finding, t: Translator) -> str:
    if finding.line is None:
        return ""
    loc = f"{finding.line}"
    if finding.column:
        loc += f":{finding.column}"
    return loc


# ---------------------------------------------------------------------------
# Текстовый отчёт
# ---------------------------------------------------------------------------


def build_text_report(report: ScanReport, lang: str = "ru") -> str:
    """Строит человекочитаемый текстовый отчёт (в стиле консоли)."""
    t = Translator(lang)
    bar = "=" * 60
    lines: list[str] = [
        bar,
        f"  {t.tr('app.name').upper()} — {t.tr('app.tagline')}",
        f"  ShashevPro · {SITE_URL}",
        bar,
        "",
    ]

    for fr in report.file_reports:
        lines.append(f"{_STATUS_ICON[fr.status]} {fr.path}  "
                     f"({t.tr('ui.encoding')}: {fr.encoding})")
        if not fr.findings:
            lines.append(f"    ✅ {t.tr('ui.no_findings')}")
            lines.append("")
            continue
        for f in fr.findings:
            icon = _finding_icon(f)
            title = t.tr(f.title_key)
            sev = t.tr(f"sev.{f.severity}")
            loc = _location(f, t)
            head = f"    {icon} [{sev}] {title}"
            if loc:
                head += f"  ({loc})"
            lines.append(head)
            if f.detail:
                lines.append(f"        → {f.detail}")
            if f.rec_key:
                lines.append(f"        ⚑ {t.tr(f.rec_key)}")
        lines.append("")

    lines.extend([
        bar,
        f"  {t.tr('ui.files_scanned')}: {report.files_scanned}",
        f"  {t.tr('ui.threats')}: {report.threats}",
        f"  {t.tr('ui.marks')}: {report.author_marks}",
        f"  {t.tr('ui.issues')}: {report.files_with_issues}",
        bar,
    ])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML-отчёт (тёмный, современный, самодостаточный)
# ---------------------------------------------------------------------------


def build_html_report(report: ScanReport, lang: str = "ru") -> str:
    """Строит самодостаточный HTML-отчёт с тёмной темой."""
    t = Translator(lang)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    year = datetime.now().year

    cards = "\n".join(_html_file_card(fr, t) for fr in report.file_reports)

    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(t.tr('app.name'))} — {html.escape(t.tr('app.tagline'))}</title>
<style>
  :root {{
    --bg: #0d1117; --panel: #161b22; --panel2: #1c2330;
    --text: #e6edf3; --muted: #8b949e; --border: #30363d;
    --accent: #f85149; --accent2: #ff7b54;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--text);
    font-family: "JetBrains Mono", "Cascadia Code", Consolas, monospace;
    line-height: 1.5; padding: 32px 16px;
  }}
  .wrap {{ max-width: 980px; margin: 0 auto; }}
  header.top {{
    border: 1px solid var(--border); border-radius: 14px;
    background: linear-gradient(135deg, #161b22, #1c1320);
    padding: 22px 26px; margin-bottom: 22px;
  }}
  header.top h1 {{ margin: 0; font-size: 22px; letter-spacing: .5px; }}
  header.top h1 .ember {{ color: var(--accent); }}
  header.top p {{ margin: 6px 0 0; color: var(--muted); font-size: 13px; }}
  .summary {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 24px; }}
  .stat {{
    flex: 1 1 150px; border: 1px solid var(--border); border-radius: 12px;
    background: var(--panel); padding: 16px 18px;
  }}
  .stat .num {{ font-size: 28px; font-weight: 700; }}
  .stat .lbl {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
  .stat.red .num {{ color: var(--accent); }}
  .stat.mark .num {{ color: #d2a8ff; }}
  details.file {{
    border: 1px solid var(--border); border-left-width: 5px;
    border-radius: 10px; margin-bottom: 12px; background: var(--panel);
    overflow: hidden;
  }}
  details.file.green {{ border-left-color: {_STATUS_COLOR['green']}; }}
  details.file.yellow {{ border-left-color: {_STATUS_COLOR['yellow']}; }}
  details.file.red {{ border-left-color: {_STATUS_COLOR['red']}; }}
  summary {{
    cursor: pointer; padding: 14px 18px; display: flex;
    align-items: center; gap: 10px; user-select: none; list-style: none;
  }}
  summary::-webkit-details-marker {{ display: none; }}
  .dot {{ width: 11px; height: 11px; border-radius: 50%; flex: 0 0 auto; }}
  .path {{ font-size: 14px; word-break: break-all; }}
  .meta {{ color: var(--muted); font-size: 12px; margin-left: auto;
           white-space: nowrap; }}
  .findings {{ padding: 4px 18px 16px; }}
  .row {{
    border-top: 1px solid var(--border); padding: 12px 0;
    display: grid; grid-template-columns: 92px 1fr; gap: 12px;
  }}
  .badge {{
    align-self: start; font-size: 11px; padding: 3px 8px; border-radius: 6px;
    text-align: center; font-weight: 600; text-transform: uppercase;
    border: 1px solid currentColor;
  }}
  .rtitle {{ font-weight: 600; }}
  .rloc {{ color: var(--muted); font-weight: 400; font-size: 12px; }}
  .rdetail {{
    margin-top: 6px; font-size: 13px; color: #c9d1d9;
    background: var(--panel2); border-radius: 8px; padding: 8px 10px;
    word-break: break-word; white-space: pre-wrap;
  }}
  .rrec {{ margin-top: 6px; font-size: 12px; color: var(--muted); }}
  .ok {{ padding: 14px 18px; color: {_STATUS_COLOR['green']}; }}
  footer {{
    margin-top: 30px; padding-top: 18px; border-top: 1px solid var(--border);
    text-align: center; color: var(--muted); font-size: 12px;
  }}
  footer a {{ color: var(--accent2); text-decoration: none; }}
  footer a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1>{html.escape(t.tr('app.name'))} <span class="ember">·</span>
        {html.escape(t.tr('app.tagline'))}</h1>
    <p>{html.escape(t.tr('ui.summary'))} — {generated}</p>
  </header>

  <div class="summary">
    <div class="stat"><div class="num">{report.files_scanned}</div>
      <div class="lbl">{html.escape(t.tr('ui.files_scanned'))}</div></div>
    <div class="stat red"><div class="num">{report.threats}</div>
      <div class="lbl">{html.escape(t.tr('ui.threats'))}</div></div>
    <div class="stat mark"><div class="num">{report.author_marks}</div>
      <div class="lbl">{html.escape(t.tr('ui.marks'))}</div></div>
    <div class="stat"><div class="num">{report.files_with_issues}</div>
      <div class="lbl">{html.escape(t.tr('ui.issues'))}</div></div>
  </div>

  {cards}

  <footer>
    <a href="{SITE_URL}" target="_blank" rel="noopener">
      {html.escape(t.tr('ui.copyright', year=year))}
    </a>
  </footer>
</div>
</body>
</html>"""


def _html_file_card(fr: FileReport, t: Translator) -> str:
    dot = f'<span class="dot" style="background:{_STATUS_COLOR[fr.status]}"></span>'
    meta = f"{t.tr('ui.encoding')}: {html.escape(fr.encoding)}"
    head = (
        f'<summary>{dot}<span class="path">{html.escape(fr.path)}</span>'
        f'<span class="meta">{meta}</span></summary>'
    )
    if not fr.findings:
        body = f'<div class="ok">✅ {html.escape(t.tr("ui.no_findings"))}</div>'
        return f'<details class="file {fr.status}">{head}{body}</details>'

    rows = "\n".join(_html_finding_row(f, t) for f in fr.findings)
    is_open = " open" if fr.status == "red" else ""
    return (
        f'<details class="file {fr.status}"{is_open}>{head}'
        f'<div class="findings">{rows}</div></details>'
    )


def _html_finding_row(f: Finding, t: Translator) -> str:
    color = _SEV_COLOR.get(f.severity, "#8b949e")
    badge = (
        f'<span class="badge" style="color:{color}">'
        f'{html.escape(t.tr(f"sev.{f.severity}"))}</span>'
    )
    loc = _location(f, t)
    loc_html = f' <span class="rloc">· {loc}</span>' if loc else ""
    title = f'<div class="rtitle">{html.escape(t.tr(f.title_key))}{loc_html}</div>'
    detail = (
        f'<div class="rdetail">{html.escape(f.detail)}</div>' if f.detail else ""
    )
    rec = (
        f'<div class="rrec">⚑ {html.escape(t.tr(f.rec_key))}</div>'
        if f.rec_key else ""
    )
    return f'<div class="row">{badge}<div>{title}{detail}{rec}</div></div>'
