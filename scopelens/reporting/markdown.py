"""Markdown rendering with one-line, context-escaped imported fields."""
from __future__ import annotations

import html
import re

from .common import _counts, _diff_label, _DIFF_LABELS, _items, _severity, _SEVERITIES, _text


def _md(value: object) -> str:
    # One cell/paragraph stays one line. Escape HTML and Markdown independently.
    value = " ".join(_text(value).splitlines())
    value = re.sub(r"([\\`*_{}\[\]()#+.!|~\-])", r"\\\1", value)
    return html.escape(value, quote=False)


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
