"""Self-contained HTML rendering; evidence never becomes markup or code."""
from __future__ import annotations

import html

from .common import _counts, _diff_label, _DIFF_LABELS, _items, _severity, _SEVERITIES, _text
from .resources import dashboard_assets


def _html(value: object) -> str:
    return html.escape(_text(value), quote=True)


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
    css, javascript = dashboard_assets()
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
<style>{css}</style>
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
<script>{javascript}</script>
</body>
</html>
'''
