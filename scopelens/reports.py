"""Portable, dependency-free reports from normalized evidence.

HTML contains only static application code. Imported data is rendered as escaped
text, never inserted into a script, interpreted as markup, or made into a URL.
"""
from __future__ import annotations

import html
import json
import re
from collections import Counter


_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _text(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _html(value: object) -> str:
    return html.escape(_text(value), quote=True)


def _md(value: object) -> str:
    # One cell/paragraph stays one line. Escape HTML and Markdown independently.
    value = " ".join(_text(value).splitlines())
    value = re.sub(r"([\\`*_{}\[\]()#+.!|~\-])", r"\\\1", value)
    return html.escape(value, quote=False)


def _severity(value: object) -> str:
    value = str(value).lower()
    return value if value in _SEVERITIES else "info"


def _items(report: dict, kind: str) -> list[dict]:
    aliases = {"service": {"service"}, "web": {"web", "http", "web_endpoint"},
               "package": {"package"}}
    return [item for item in report.get("observations", [])
            if item.get("kind") in aliases[kind]]


def _counts(report: dict) -> dict:
    observations = report.get("observations", [])
    findings = report.get("findings", [])
    coverage = report.get("coverage", [])
    values = {
        "assets": len({item.get("asset") for item in observations if item.get("asset")}),
        "services": len(_items(report, "service")),
        "web_endpoints": len(_items(report, "web")),
        "packages": len(_items(report, "package")),
        "findings": len(findings),
        "files_total": len(coverage),
        "files_parsed": sum(item.get("status") == "parsed" for item in coverage),
        "by_severity": dict(Counter(_severity(item.get("severity")) for item in findings)),
    }
    values.update(report.get("summary") or {})
    return values


def render_json(report: dict) -> str:
    """Serialize the full versioned contract, suitable for automation."""
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _evidence_markdown(evidence: list[dict]) -> list[str]:
    if not evidence:
        return ["No source evidence attached.", ""]
    lines = []
    for item in evidence:
        lines.append(f"- Source: {_md(item.get('path', 'unknown'))}, line {_md(item.get('line', '—'))}; "
                     f"locator: {_md(item.get('locator') or '—')}; SHA-256: {_md(item.get('sha256', '—'))}")
        if item.get("excerpt"):
            lines.append(f"  - Excerpt: {_md(item['excerpt'])}")
    return lines + [""]


def render_markdown(report: dict) -> str:
    """Render review-friendly Markdown with escaped imported content."""
    counts = _counts(report)
    source = report.get("source") or {}
    tool = report.get("tool") or {}
    lines = [f"# {_md(report.get('name') or 'ScopeLens analysis')}", "",
             f"Generated: {_md(report.get('generated_at', '—'))} · "
             f"ScopeLens {_md(tool.get('version', '—'))} · Schema {_md(report.get('schema_version', 1))}", "",
             f"Source: {_md(source.get('name', '—'))} ({_md(source.get('kind', '—'))})", "",
             "Evidence-based review of imported files. Severity expresses potential impact; confidence "
             "expresses support in the supplied evidence. Findings require review and do not prove exploitability.", "",
             "## Overview", "", "| Assets | Services | Web endpoints | Packages | Findings | Files parsed |",
             "| --- | --- | --- | --- | --- | --- |",
             f"| {_md(counts['assets'])} | {_md(counts['services'])} | {_md(counts['web_endpoints'])} | "
             f"{_md(counts['packages'])} | {_md(counts['findings'])} | "
             f"{_md(counts['files_parsed'])} / {_md(counts['files_total'])} |", "",
             " · ".join(f"{level.title()}: {_md((counts.get('by_severity') or {}).get(level, 0))}" for level in _SEVERITIES), "",
             "## Scope", ""]
    scope = report.get("scope") or {}
    lines.extend(["Include: " + (", ".join(_md(v) for v in scope.get("include", [])) or "All imported assets"), "",
                  "Exclude: " + (", ".join(_md(v) for v in scope.get("exclude", [])) or "None"), "",
                  "## Findings", ""])
    findings = report.get("findings", [])
    if not findings:
        lines.extend(["No findings were produced. This does not establish that the assets are secure.", ""])
    for item in findings:
        lines.extend([f"### {_md(item.get('title', 'Untitled finding'))}", "",
                      f"Severity: **{_md(_severity(item.get('severity')))}** · "
                      f"Confidence: **{_md(item.get('confidence', 'unknown'))}**", "",
                      f"Asset: {_md(item.get('asset', '—'))} · Subject: {_md(item.get('subject', '—'))}", "",
                      f"Rule: {_md(item.get('rule_id', '—'))} · Finding ID: {_md(item.get('id', '—'))}", "",
                      _md(item.get("detail", "")), "", "**Recommended action**", "",
                      _md(item.get("remediation", "Review the source evidence.")), "", "**Evidence**", ""])
        lines.extend(_evidence_markdown(item.get("evidence", [])))
    for kind, heading in (("service", "Service inventory"), ("web", "Web inventory"), ("package", "Package inventory")):
        lines.extend([f"## {heading}", ""])
        inventory = _items(report, kind)
        if not inventory:
            lines.extend(["No observations in this category.", ""])
        for item in inventory:
            lines.extend([f"### {_md(item.get('asset', '—'))}", "",
                          f"Confidence: {_md(item.get('confidence', 'unknown'))}", ""])
            for key, value in (item.get("data") or {}).items():
                lines.append(f"- {_md(key)}: {_md(value)}")
            lines.append("")
            lines.extend(_evidence_markdown(item.get("evidence", [])))
    lines.extend(["## Baseline comparison", ""])
    diff = report.get("diff")
    if diff is None:
        lines.extend(["No baseline supplied.", ""])
    else:
        lines.extend([_md(diff.get("note") or "Changes compare the supplied evidence snapshots."), ""])
        for key, label in _DIFF_LABELS:
            entries = diff.get(key, [])
            lines.extend([f"### {label} ({len(entries)})", ""])
            for entry in entries:
                lines.append("- " + _md(_diff_label(entry)))
            if not entries:
                lines.append("None.")
            lines.append("")
    lines.extend(["## Import coverage", "", "| File | Status | Parser | Bytes | SHA-256 | Reason |",
                  "| --- | --- | --- | --- | --- | --- |"])
    for item in report.get("coverage", []):
        lines.append("| " + " | ".join(_md(item.get(key, "—")) for key in
                                       ("path", "status", "parser", "bytes", "sha256", "reason")) + " |")
    if not report.get("coverage"):
        lines.append("| No files recorded | — | — | — | — | — |")
    lines.extend(["", "## Warnings", ""])
    for warning in report.get("warnings", []):
        lines.append(f"- {_md(warning.get('code', 'warning'))} · {_md(warning.get('path', '—'))}: "
                     f"{_md(warning.get('message', '—'))}")
    if not report.get("warnings"):
        lines.append("No import warnings.")
    return "\n".join(lines).rstrip() + "\n"


_DIFF_LABELS = (("added_findings", "Added findings"), ("removed_findings", "Removed findings"),
                ("added_services", "Added services"), ("removed_services", "Removed services"),
                ("changed_services", "Changed services"))


def _diff_label(entry: object) -> str:
    if not isinstance(entry, dict):
        return _text(entry)
    title = entry.get("title") or entry.get("subject")
    if title:
        return f"{entry.get('asset', '—')} · {title}"
    data = entry.get("data")
    if isinstance(data, dict):
        return f"{entry.get('asset', '—')} · {_text(data)}"
    return _text(entry)


def _evidence_html(evidence: list[dict]) -> str:
    if not evidence:
        return '<p class="quiet">No source evidence attached.</p>'
    parts = []
    for item in evidence:
        locator = (f'<span class="locator">{_html(item["locator"])}</span>' if item.get("locator") else "")
        excerpt = (f'<pre class="excerpt">{_html(item["excerpt"])}</pre>' if item.get("excerpt") else "")
        parts.append(f'<div class="evidence"><div class="evidence-location"><strong>{_html(item.get("path", "unknown"))}</strong>'
                     f'<span>Line {_html(item.get("line", "—"))}</span>{locator}</div>'
                     f'<div class="hash"><span>SHA-256</span> <code>{_html(item.get("sha256", "—"))}</code></div>{excerpt}</div>')
    return "".join(parts)


def _filter_attrs(item: dict, category: str) -> str:
    search = " ".join(_text(item.get(key, "")) for key in
                      ("asset", "title", "subject", "rule_id", "detail", "remediation", "data", "evidence"))
    level = _severity(item.get("severity")) if category == "finding" else ""
    return (f'data-filterable data-category="{category}" data-asset="{_html(item.get("asset", ""))}" '
            f'data-severity="{level}" data-search="{_html(search.lower())}"')


def _finding_html(item: dict, index: int) -> str:
    level = _severity(item.get("severity"))
    return (f'<article class="finding" {_filter_attrs(item, "finding")} aria-labelledby="finding-{index}">'
            f'<div class="finding-top"><span class="badge {level}">{level}</span>'
            f'<span class="confidence">Confidence <strong>{_html(item.get("confidence", "unknown"))}</strong></span></div>'
            f'<h3 id="finding-{index}">{_html(item.get("title", "Untitled finding"))}</h3>'
            f'<p class="identity"><span>{_html(item.get("asset", "—"))}</span>'
            f'<span>{_html(item.get("subject", "—"))}</span></p>'
            f'<p class="detail">{_html(item.get("detail", ""))}</p>'
            f'<div class="remediation"><span class="eyebrow">Recommended action</span>'
            f'<p>{_html(item.get("remediation", "Review the source evidence."))}</p></div>'
            f'<details><summary>Evidence &amp; provenance <span>{len(item.get("evidence", []))} sources</span></summary>'
            f'<div class="rule-meta">Rule <code>{_html(item.get("rule_id", "—"))}</code>'
            f' · Finding <code>{_html(item.get("id", "—"))}</code></div>'
            f'{_evidence_html(item.get("evidence", []))}</details></article>')


def _inventory_html(report: dict, kind: str, title: str, description: str) -> str:
    inventory = _items(report, kind)
    parts = [f'<section class="section" id="{kind}-inventory"><div class="section-heading"><div>'
             f'<p class="eyebrow">Observed evidence</p><h2>{title}</h2><p>{description}</p></div>'
             f'<span class="section-count">{len(inventory)}</span></div>']
    if not inventory:
        parts.append('<div class="empty">No observations in this category.</div>')
    else:
        parts.append('<div class="inventory-grid">')
        for item in inventory:
            data = item.get("data") or {}
            if kind == "service":
                label = f'{data.get("port", "—")}/{data.get("protocol", "tcp")}'
            elif kind == "web":
                label = data.get("url") or data.get("title") or "Web endpoint"
            else:
                label = data.get("name") or data.get("package") or "Package"
            pairs = "".join(f'<div><dt>{_html(key.replace("_", " "))}</dt><dd>{_html(value)}</dd></div>'
                            for key, value in data.items())
            parts.append(f'<article class="inventory-card" {_filter_attrs(item, kind)}>'
                         f'<p class="eyebrow">{_html(item.get("asset", "—"))}</p><h3>{_html(label)}</h3>'
                         f'<p class="confidence">Confidence <strong>{_html(item.get("confidence", "unknown"))}</strong></p>'
                         f'<dl class="properties">{pairs}</dl><details><summary>Source evidence'
                         f'<span>{len(item.get("evidence", []))}</span></summary>{_evidence_html(item.get("evidence", []))}'
                         '</details></article>')
        parts.append('</div><p class="empty filter-empty" hidden>No observations match the current filters.</p>')
    parts.append('</section>')
    return "".join(parts)


def _baseline_html(report: dict) -> str:
    diff = report.get("diff")
    opening = ('<section class="section" id="baseline"><div class="section-heading"><div>'
               '<p class="eyebrow">Track what changed</p><h2>Baseline comparison</h2></div></div>')
    if diff is None:
        return opening + '<div class="empty">No baseline supplied. Compare with an earlier JSON report to reveal changes in the imported evidence.</div></section>'
    parts = [opening, f'<p class="section-note">{_html(diff.get("note") or "Changes compare the supplied evidence snapshots.")}</p>',
             '<div class="baseline-grid">']
    for key, label in _DIFF_LABELS:
        entries = diff.get(key, [])
        parts.append(f'<details class="delta"><summary><span>{label}</span><strong>{len(entries)}</strong></summary>')
        if entries:
            parts.append('<ul>' + "".join(f'<li>{_html(_diff_label(entry))}</li>' for entry in entries) + '</ul>')
        else:
            parts.append('<p class="quiet">None in this comparison.</p>')
        parts.append('</details>')
    return "".join(parts) + '</div></section>'


def _coverage_html(report: dict) -> str:
    coverage = report.get("coverage", [])
    warnings = report.get("warnings", [])
    parts = ['<section class="section" id="coverage"><div class="section-heading"><div><p class="eyebrow">Know the limits</p>'
             '<h2>Import coverage</h2><p>What was parsed, what was skipped, and where the evidence came from.</p></div></div>']
    if coverage:
        parts.append('<div class="table-wrap" tabindex="0" role="region" aria-label="Import coverage table"><table>'
                     '<caption class="sr-only">Source file coverage and integrity hashes</caption>'
                     '<thead><tr><th scope="col">File / SHA-256</th><th scope="col">Status</th>'
                     '<th scope="col">Parser</th><th scope="col">Bytes</th><th scope="col">Notes</th></tr></thead><tbody>')
        for item in coverage:
            status = item.get("status", "unknown")
            css = "parsed" if status == "parsed" else "unparsed"
            parts.append(f'<tr><th scope="row"><span class="file-name">{_html(item.get("path", "—"))}</span>'
                         f'<code class="coverage-hash">{_html(item.get("sha256", "—"))}</code></th>'
                         f'<td><span class="status {css}">{_html(status)}</span></td>'
                         f'<td>{_html(item.get("parser") or "—")}</td><td>{_html(item.get("bytes", "—"))}</td>'
                         f'<td>{_html(item.get("reason") or "—")}</td></tr>')
        parts.append('</tbody></table></div>')
    else:
        parts.append('<div class="empty">No source files recorded.</div>')
    parts.append(f'<div class="warning-panel"><h3>Import warnings <span class="quiet">({len(warnings)})</span></h3>')
    if warnings:
        parts.append('<ul class="warnings">')
        for item in warnings:
            parts.append(f'<li><strong>{_html(item.get("code", "warning"))}</strong>'
                         f'<span class="warning-path">{_html(item.get("path", "—"))}</span>'
                         f'<p>{_html(item.get("message", "—"))}</p></li>')
        parts.append('</ul>')
    else:
        parts.append('<p class="quiet">No import warnings.</p>')
    return "".join(parts) + '</div></section>'


def render_html(report: dict) -> str:
    """Return a self-contained, accessible offline dashboard."""
    counts = _counts(report)
    source = report.get("source") or {}
    tool = report.get("tool") or {}
    scope = report.get("scope") or {}
    findings = report.get("findings", [])
    assets = sorted({str(item.get("asset", "")) for item in
                     report.get("observations", []) + findings if item.get("asset")})
    options = ''.join(f'<option value="{_html(asset)}">{_html(asset)}</option>' for asset in assets)
    severity_options = ''.join(f'<option value="{level}">{level.title()}</option>' for level in _SEVERITIES)
    metrics = ''.join(f'<div class="metric"><dt>{label}</dt><dd>{_html(counts[key])}</dd></div>'
                      for key, label in (("assets", "Assets"), ("services", "Services"),
                                         ("web_endpoints", "Web endpoints"), ("packages", "Packages")))
    breakdown = ''.join(f'<span class="severity-total"><span class="dot {level}"></span>'
                        f'<strong>{_html((counts.get("by_severity") or {}).get(level, 0))}</strong> {level}</span>'
                        for level in _SEVERITIES)
    include = ', '.join(_html(v) for v in scope.get("include", [])) or "All imported assets"
    exclude = ', '.join(_html(v) for v in scope.get("exclude", [])) or "None"
    finding_cards = ''.join(_finding_html(item, i) for i, item in enumerate(findings))
    if not findings:
        finding_cards = '<div class="empty">No findings were produced. This does not establish that the assets are secure.</div>'
    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; object-src 'none'">
<meta name="referrer" content="no-referrer">
<title>{_html(report.get("name") or "ScopeLens analysis")} · ScopeLens</title>
<style>{_CSS}</style>
</head>
<body>
<a class="skip" href="#main">Skip to analysis</a>
<header class="masthead"><a class="brand" href="#main" aria-label="ScopeLens analysis"><span class="brand-mark" aria-hidden="true">◉</span> Scope<span>Lens</span></a>
<span class="mode"><span aria-hidden="true"></span> Offline evidence report</span>
<button type="button" id="print-report" class="button no-js-hide">Print / PDF</button></header>
<div class="layout">
<aside class="sidebar"><p class="eyebrow">Analysis workspace</p><nav aria-label="Report sections">
<a href="#overview">Overview</a><a href="#findings">Findings <span>{_html(counts['findings'])}</span></a>
<a href="#service-inventory">Services</a><a href="#web-inventory">Web endpoints</a><a href="#package-inventory">Packages</a>
<a href="#baseline">Baseline</a><a href="#coverage">Import coverage</a></nav>
<div class="sidebar-note"><span class="eyebrow">Evidence first</span><p>Every conclusion stays connected to its source.</p>
<p class="small">ScopeLens {_html(tool.get('version', '—'))}<br>Report schema {_html(report.get('schema_version', 1))}</p></div></aside>
<main id="main">
<section id="overview" class="hero"><div class="hero-top"><p class="eyebrow">Observe. Understand. Prioritize.</p><span class="report-label">Analysis report</span></div>
<h1>{_html(report.get('name') or 'ScopeLens analysis')}</h1>
<p class="hero-description">A clear view of your assets, their services, and the evidence that deserves attention.</p>
<div class="report-meta"><span>Generated <strong>{_html(report.get('generated_at', '—'))}</strong></span>
<span>Source <strong>{_html(source.get('name', '—'))}</strong> · {_html(source.get('kind', '—'))}</span></div>
<dl class="metrics">{metrics}</dl>
<div class="risk-strip"><div><strong>{_html(counts['findings'])}</strong><span>review findings</span></div><div class="severity-breakdown">{breakdown}</div></div>
</section>
<div class="context-grid"><div class="context-card"><h2>Analysis scope</h2><dl><dt>Include</dt><dd>{include}</dd><dt>Exclude</dt><dd>{exclude}</dd></dl></div>
<div class="context-card"><h2>Evidence coverage</h2><p class="coverage-stat"><strong>{_html(counts['files_parsed'])}</strong> / {_html(counts['files_total'])} files parsed</p>
<p class="quiet">Results describe the supplied evidence. Missing data and skipped files can leave gaps.</p></div></div>
<section class="filter-bar no-js-hide" aria-label="Filter report"><div class="search-control"><label for="text-filter">Search evidence</label>
<input id="text-filter" type="search" placeholder="Asset, port, rule, or evidence…" autocomplete="off"></div>
<div><label for="asset-filter">Asset</label><select id="asset-filter"><option value="">All assets</option>{options}</select></div>
<div><label for="severity-filter">Finding severity</label><select id="severity-filter"><option value="">All severities</option>{severity_options}</select></div>
<button class="button" type="button" id="clear-filters">Reset</button><p id="filter-status" role="status" aria-live="polite"></p></section>
<noscript><p class="notice">All report content is visible. Enable JavaScript to use the search and filter controls.</p></noscript>
<section class="section" id="findings"><div class="section-heading"><div><p class="eyebrow">Prioritize your review</p><h2>Findings</h2>
<p>Severity describes potential impact. Confidence describes support in the evidence.</p></div><span class="section-count">{len(findings)}</span></div>
<p class="section-note">These observations require review; they do not prove exploitability.</p><div class="finding-grid">{finding_cards}</div>
<p class="empty filter-empty" hidden>No findings match the current filters.</p></section>
{_inventory_html(report, 'service', 'Service inventory', 'Ports, protocols, and service fingerprints captured in the imported files.')}
{_inventory_html(report, 'web', 'Web endpoints', 'Observed responses and configuration evidence. Addresses are displayed as text.')}
{_inventory_html(report, 'package', 'Package inventory', 'Components and versions reported by the supplied inventory.')}
{_baseline_html(report)}
{_coverage_html(report)}
<footer><span class="brand">Scope<span>Lens</span></span><p>Built from evidence. Ready for review.</p><span>Self-contained · Offline · No external resources</span></footer>
</main></div>
<script>{_JS}</script>
</body>
</html>
'''


_CSS = r'''
:root{color-scheme:light;--ink:#142c39;--muted:#566870;--paper:#f4f5ef;--card:#fff;--line:#dce4de;--teal:#08766a;--navy:#102d36;--accent:#d6ef9c;--critical:#92253c;--high:#b24829;--medium:#805e10;--low:#25658e;--info:#5f6b75;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:25px}body{margin:0;color:var(--ink);background:var(--paper);font-size:14px;line-height:1.6}a{color:inherit}button,input,select{font:inherit}button,summary,select{cursor:pointer}button:focus-visible,a:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible,.table-wrap:focus-visible{outline:3px solid #268474;outline-offset:4px}button{color:var(--ink)}[hidden]{display:none!important}.no-js-hide{display:none!important}html.js .no-js-hide{display:flex!important}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.skip{position:absolute;left:18px;top:-80px;z-index:9;padding:12px 20px;background:var(--accent)}.skip:focus{top:12px}.masthead{height:80px;padding:0 42px;border-bottom:1px solid var(--line);display:flex;gap:25px;align-items:center;background:#fff}.brand{display:inline-flex;align-items:center;font-weight:750;font-size:22px;letter-spacing:-.8px;text-decoration:none}.brand>span:last-child{font-weight:400}.brand-mark{font-size:30px!important;color:var(--teal);margin-right:10px}.mode{display:flex;gap:8px;align-items:center;color:var(--muted);font-size:12px;margin-left:auto}.mode>span{width:6px;height:6px;border-radius:50%;background:var(--teal)}.button{display:inline-flex;align-items:center;justify-content:center;border:1px solid #bdcbc3;border-radius:7px;background:#fff;padding:9px 14px;font-weight:600;font-size:12px;white-space:nowrap}.button:hover{background:#eef5ee}.layout{max-width:1760px;margin:auto;display:grid;grid-template-columns:220px minmax(0,1fr)}.sidebar{padding:40px 22px 40px 28px;border-right:1px solid var(--line)}.eyebrow{text-transform:uppercase;font-size:10px;letter-spacing:1.8px;font-weight:700;margin:0 0 12px;color:var(--teal)}.sidebar .eyebrow{font-size:9px;color:var(--muted)}nav{display:flex;flex-direction:column;gap:4px}nav a{display:flex;justify-content:space-between;text-decoration:none;padding:10px 12px;border-radius:6px;font-size:12px;font-weight:600}nav a:first-child{background:#e4eee1;color:#185e4c}nav a:hover{background:#e7ede6}nav a span{background:#d5e6d4;border-radius:4px;min-width:24px;text-align:center}.sidebar-note{margin:50px 10px 0;padding-top:23px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}.small{font-size:10px;line-height:1.8}main{min-width:0;padding:38px 44px 0;max-width:1400px}.hero{background:var(--navy);border-radius:16px;padding:32px 36px 0;color:#f8fbf3;overflow:hidden;box-shadow:0 8px 28px #142c3910}.hero-top{display:flex;align-items:center;justify-content:space-between;gap:20px}.hero .eyebrow{color:var(--accent);margin:0}.report-label{border:1px solid #43615f;border-radius:99px;padding:3px 10px;color:#c1d3cf;font-size:10px;white-space:nowrap}h1{font-size:clamp(27px,3vw,42px);font-weight:600;letter-spacing:-1.6px;line-height:1.2;margin:23px 0 12px;overflow-wrap:anywhere}.hero-description{max-width:660px;color:#c2d2ce;font-size:13px;margin:0}.report-meta{display:flex;flex-wrap:wrap;gap:8px 28px;font-size:10px;color:#a8bfba;margin-top:23px;overflow-wrap:anywhere}.report-meta strong{font-weight:500;color:#dfebe4;margin-left:5px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);margin:28px 0 25px}.metric{border-right:1px solid #34514f;padding:0 25px}.metric:first-child{padding-left:0}.metric:last-child{border:0}.metric dt{font-size:11px;color:#bbcfca;margin-bottom:3px}.metric dd{font-size:36px;line-height:1.35;font-weight:500;letter-spacing:-1px;margin:0}.risk-strip{margin:0 -36px;background:#1d3d43;padding:15px 36px;display:flex;justify-content:space-between;align-items:center;gap:22px}.risk-strip>div:first-child{display:flex;align-items:center;gap:10px;white-space:nowrap}.risk-strip>div:first-child>strong{font-size:24px;color:var(--accent);font-weight:500}.risk-strip>div:first-child>span{font-size:11px;color:#d9e7df}.severity-breakdown{display:flex;flex-wrap:wrap;gap:10px 18px}.severity-total{font-size:10px;display:flex;gap:5px;align-items:center;color:#cedad5;text-transform:capitalize}.severity-total strong{color:#fff;font-weight:600}.dot{width:6px;height:6px;border-radius:50%;display:inline-block}.dot.critical{background:#f091ab}.dot.high{background:#f1a177}.dot.medium{background:#ebd182}.dot.low{background:#84bcd7}.dot.info{background:#bbc5c9}.context-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:20px 0 26px}.context-card{padding:19px 22px;background:var(--card);border:1px solid var(--line);border-radius:10px}.context-card h2{font-size:12px;margin:0 0 12px;font-weight:650}.context-card dl{display:grid;grid-template-columns:55px minmax(0,1fr);gap:5px 12px;margin:0;font-size:11px}.context-card dt{color:var(--muted)}.context-card dd{margin:0;overflow-wrap:anywhere}.coverage-stat{margin:0;font-size:12px;color:var(--muted)}.coverage-stat strong{font-size:23px;font-weight:600;color:var(--ink);margin-right:3px}.context-card .quiet{font-size:10px;margin:5px 0 0}.quiet{color:var(--muted)}.filter-bar{flex-wrap:wrap;align-items:end;gap:13px;padding:18px 20px;border:1px solid var(--line);border-radius:10px;background:#eaf0e6}.filter-bar>div{flex:1;min-width:125px}.filter-bar .search-control{flex:2;min-width:200px}.filter-bar label{display:block;font-size:10px;font-weight:650;margin-bottom:5px}.filter-bar input,.filter-bar select{width:100%;height:36px;background:#fff;border:1px solid #c9d4c8;border-radius:6px;font-size:11px;padding:6px 10px;color:var(--ink)}.filter-bar .button{height:36px}#filter-status{flex-basis:100%;font-size:10px;color:var(--muted);margin:0}.section{margin-top:40px;scroll-margin-top:25px}.section-heading{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:16px}.section-heading .eyebrow{margin:0 0 4px}.section-heading h2{font-size:24px;letter-spacing:-.65px;font-weight:600;margin:0}.section-heading p:not(.eyebrow){font-size:11px;color:var(--muted);margin:5px 0 0}.section-count{background:#e1e9db;display:flex;align-items:center;justify-content:center;min-width:34px;height:34px;border-radius:50%;font-size:12px;font-weight:650}.section-note{font-size:11px;color:var(--muted);margin:-5px 0 17px}.finding-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:17px}.finding,.inventory-card{border:1px solid var(--line);border-radius:10px;background:var(--card);padding:22px;min-width:0;overflow-wrap:anywhere}.finding-top{display:flex;align-items:center;justify-content:space-between;gap:10px}.badge{text-transform:uppercase;letter-spacing:.8px;font-weight:750;font-size:9px;line-height:1;padding:6px 8px;border-radius:4px}.badge.critical{color:var(--critical);background:#fce3e9}.badge.high{color:var(--high);background:#ffeadf}.badge.medium{color:var(--medium);background:#faf0cc}.badge.low{color:var(--low);background:#e2f0f8}.badge.info{color:var(--info);background:#edf0f1}.confidence{font-size:10px;color:var(--muted);margin:0}.confidence strong{font-weight:650;color:var(--ink);text-transform:capitalize;margin-left:4px}.finding h3{font-size:17px;line-height:1.4;letter-spacing:-.2px;margin:14px 0 9px}.identity{display:flex;flex-wrap:wrap;gap:5px 12px;font-size:10px;margin:0 0 15px;color:var(--teal);font-weight:600}.identity span+span{color:var(--muted);font-weight:400}.detail{font-size:12px;color:#4d6169;white-space:pre-wrap}.remediation{background:#f1f5ed;border-left:2px solid #9bbe81;border-radius:0 5px 5px 0;padding:11px 13px;margin:18px 0}.remediation .eyebrow{font-size:8px;letter-spacing:1px}.remediation p{font-size:11px;margin:5px 0 0;color:#395446;white-space:pre-wrap}details{border-top:1px solid var(--line);margin-top:15px;padding-top:12px}summary{font-weight:600;font-size:11px;color:var(--ink)}summary span{font-weight:400;color:var(--muted);margin-left:6px}details[open]>summary{margin-bottom:13px}.rule-meta{font-size:9px;margin-bottom:10px;color:var(--muted)}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.evidence{border:1px solid #e1e8e1;border-radius:5px;padding:10px;background:#f9faf6;margin:8px 0;overflow-wrap:anywhere}.evidence-location{display:flex;flex-wrap:wrap;gap:3px 10px;font-size:9px}.evidence-location strong{font-weight:600}.evidence-location>span{color:var(--muted)}.locator{flex-basis:100%}.hash{font-size:8px;line-height:1.6;margin-top:5px;color:var(--muted)}.hash>span{font-weight:600;margin-right:5px}.excerpt{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:9px;line-height:1.7;white-space:pre-wrap;overflow-wrap:anywhere;background:#eaf0e8;padding:8px;border-radius:4px;margin:9px 0 0}.inventory-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}.inventory-card{padding:18px}.inventory-card>.eyebrow{font-size:8px;letter-spacing:1px;margin-bottom:5px}.inventory-card h3{font-size:15px;line-height:1.5;letter-spacing:-.25px;margin:0 0 7px}.properties{font-size:10px;margin:15px 0 0}.properties>div{display:grid;grid-template-columns:minmax(60px,30%) minmax(0,1fr);gap:10px;padding:7px 0;border-top:1px solid #edf1ea}.properties dt{color:var(--muted);text-transform:capitalize}.properties dd{margin:0;overflow-wrap:anywhere;white-space:pre-wrap}.baseline-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}.delta{margin:0;padding:14px;border:1px solid var(--line);border-radius:8px;background:#fff;overflow-wrap:anywhere}.delta summary{font-size:10px}.delta summary>span{margin:0;color:var(--muted)}.delta summary>strong{display:block;font-size:25px;font-weight:500;line-height:1.4;margin:8px 0 0;color:var(--ink)}.delta ul{font-size:10px;padding-left:13px}.delta li+li{margin-top:9px}.delta .quiet{font-size:10px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:9px;background:#fff}table{width:100%;border-collapse:collapse;font-size:10px;text-align:left}thead{background:#e9efe5}th,td{padding:13px 15px;vertical-align:top;border-bottom:1px solid #e9eee6}thead th{font-weight:650;white-space:nowrap}tbody th{font-weight:500;min-width:210px}tbody tr:last-child>*{border-bottom:0}.file-name{display:block;overflow-wrap:anywhere}.coverage-hash{display:block;font-size:8px;color:var(--muted);margin-top:4px;word-break:break-all;max-width:290px}td{overflow-wrap:anywhere;min-width:80px}.status{font-size:9px;border-radius:4px;padding:3px 7px;white-space:nowrap}.status.parsed{color:#276337;background:#e4f1df}.status.unparsed{color:#7c5c27;background:#faf0d7}.warning-panel{margin-top:18px;padding:18px 22px;border:1px solid var(--line);background:#fff;border-radius:9px}.warning-panel h3{font-size:12px;margin:0}.warning-panel>.quiet{font-size:11px;margin-bottom:0}.warnings{padding:0;list-style:none;margin:12px 0 0}.warnings li{padding:10px 0;border-top:1px solid var(--line);font-size:10px;overflow-wrap:anywhere}.warnings strong{color:#7c5c27}.warning-path{color:var(--muted);margin-left:10px}.warnings p{margin:4px 0 0}.empty,.notice{padding:24px;background:#edf1e8;border:1px dashed #c8d3c0;border-radius:9px;font-size:12px;color:var(--muted)}.finding-grid>.empty{grid-column:1/-1}.filter-empty{margin-top:15px}footer{display:flex;flex-wrap:wrap;align-items:center;gap:10px 22px;padding:38px 0 24px;margin-top:35px;border-top:1px solid var(--line);font-size:10px;color:var(--muted)}footer .brand{font-size:17px;color:var(--ink)}footer p{margin:0}footer>span:last-child{margin-left:auto;font-size:9px}
@media(min-width:1600px){main{padding-right:58px;padding-left:58px}.finding h3{font-size:19px}}
@media(max-width:1150px){.layout{grid-template-columns:170px minmax(0,1fr)}.sidebar{padding:35px 14px}.sidebar .eyebrow{letter-spacing:1px}main{padding:28px 26px 0}.inventory-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.risk-strip{align-items:flex-start;flex-direction:column;gap:10px}.baseline-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.finding{padding:18px}}
@media(max-width:850px){.layout{display:block}.sidebar{display:none}.masthead{height:68px;padding:0 24px}.mode{display:none}.masthead>.button{margin-left:auto}main{padding:24px 20px 0}.hero{padding:25px 25px 0}.risk-strip{margin:0 -25px;padding:14px 25px}.hero-top .report-label{display:none}.finding-grid{grid-template-columns:1fr}.finding h3{font-size:18px}.filter-bar .search-control{flex-basis:100%}.hero-top .eyebrow{font-size:9px}.metrics{margin:25px 0 20px}.metric{padding:0 16px}.metric dd{font-size:30px}.metric dt{font-size:10px}.section{margin-top:32px}.section-heading h2{font-size:22px}.section-heading p:not(.eyebrow){max-width:400px}.finding{padding:23px}.detail{font-size:13px}.remediation p{font-size:12px}}
@media(max-width:540px){main{padding:18px 13px 0}.masthead{padding:0 17px}.brand{font-size:20px}.hero{border-radius:12px;padding:23px 21px 0}h1{letter-spacing:-.9px;margin-top:20px}.hero-description{font-size:12px}.metrics{grid-template-columns:repeat(2,1fr);gap:18px}.metric,.metric:first-child{padding:0}.metric:nth-child(2){border:0}.metric:nth-child(2n){padding-left:20px}.metric dd{font-size:32px}.risk-strip{margin:0 -21px;padding:14px 21px}.severity-breakdown{gap:9px 11px}.severity-total{font-size:9px}.context-grid{grid-template-columns:1fr;gap:11px}.context-card{padding:17px 19px}.filter-bar{padding:15px}.filter-bar>div{min-width:100px}.filter-bar .button{width:100%}.inventory-grid{grid-template-columns:1fr}.baseline-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.finding{padding:18px}.finding-top{align-items:flex-start}.section-heading{gap:10px}.section-heading p:not(.eyebrow){font-size:10px}.section-count{flex-shrink:0}.hero .eyebrow{letter-spacing:1.3px}.warning-path{display:block;margin:3px 0}footer{gap:9px 15px}footer>span:last-child{flex-basis:100%;margin-left:0}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
@media print{:root{--ink:#111;--muted:#444;--line:#ccc}body{background:#fff;font-size:11px}.masthead,.sidebar,.filter-bar,.skip,.no-js-hide{display:none!important}html.js .no-js-hide{display:none!important}.layout{display:block}main{padding:0;max-width:none}.hero{background:#fff;color:#111;border:1px solid #ccc;box-shadow:none;padding:20px}.hero .eyebrow,.hero-description,.report-meta,.report-meta strong,.metric dt{color:#333}.metrics{margin-bottom:0}.risk-strip{background:#eee;color:#111;margin:20px -20px -20px;padding:10px 20px}.risk-strip>div:first-child>strong,.risk-strip>div:first-child>span,.severity-total,.severity-total strong{color:#111}.dot{border:1px solid #777}.hero-top .report-label{color:#333}.finding-grid,.inventory-grid{display:block}.finding,.inventory-card{margin-bottom:12px;break-inside:avoid}.context-grid{gap:12px}.context-card{padding:12px}.section{margin-top:25px}.section-heading{break-after:avoid}.baseline-grid{grid-template-columns:repeat(5,minmax(0,1fr))}.table-wrap{overflow:visible}th,td{padding:7px}details{break-inside:avoid}footer{padding:15px 0;margin-top:20px}.empty{padding:13px}.badge{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
'''


_JS = r'''
"use strict";
document.documentElement.classList.add("js");
const search = document.getElementById("text-filter");
const asset = document.getElementById("asset-filter");
const severity = document.getElementById("severity-filter");
const rows = Array.from(document.querySelectorAll("[data-filterable]"));
function filterReport() {
  const query = search.value.trim().toLowerCase();
  let visibleFindings = 0;
  let visibleObservations = 0;
  rows.forEach(row => {
    const isFinding = row.dataset.category === "finding";
    const matches = (!query || row.dataset.search.includes(query)) &&
      (!asset.value || row.dataset.asset === asset.value) &&
      (!isFinding || !severity.value || row.dataset.severity === severity.value);
    row.hidden = !matches;
    if (matches) {
      if (isFinding) visibleFindings++; else visibleObservations++;
    }
  });
  document.querySelectorAll(".filter-empty").forEach(empty => {
    const section = empty.closest("section");
    const members = Array.from(section.querySelectorAll("[data-filterable]"));
    empty.hidden = members.length === 0 || members.some(row => !row.hidden);
  });
  document.getElementById("filter-status").textContent =
    visibleFindings + " findings · " + visibleObservations +
    " inventory observations shown. Severity applies to findings; asset and search apply to both.";
}
search.addEventListener("input", filterReport);
asset.addEventListener("change", filterReport);
severity.addEventListener("change", filterReport);
document.getElementById("clear-filters").addEventListener("click", () => {
  search.value = "";
  asset.value = "";
  severity.value = "";
  filterReport();
});
document.getElementById("print-report").addEventListener("click", () => window.print());
let closedBeforePrint = [];
window.addEventListener("beforeprint", () => {
  closedBeforePrint = Array.from(document.querySelectorAll("details:not([open])"));
  closedBeforePrint.forEach(details => { details.open = true; });
});
window.addEventListener("afterprint", () => {
  closedBeforePrint.forEach(details => { details.open = false; });
  closedBeforePrint = [];
});
filterReport();
'''
