"""Application workflow shared by commands and Python callers; no console I/O."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .engine import analyze
from .model import SEVERITIES
from .reports import render_html, render_json, render_markdown
from .storage import MAX_SCOPE_BYTES, new_directory, publish_directory, read_json

FORMATS = ("all", "json", "html", "markdown")


@dataclass(frozen=True)
class AnalysisRequest:
    source: Path
    output: Path
    name: str = ""
    scope: Path | None = None
    baseline: Path | None = None
    fail_on: str | None = None
    format: str = "all"


@dataclass(frozen=True)
class AnalysisResult:
    report: dict
    output: Path
    paths: tuple[Path, ...]
    exit_code: int


def analysis_exit_code(report: dict, fail_on: str | None = None) -> int:
    """Use the same outcome rules for direct analysis and workspace reviews."""
    if fail_on is not None and fail_on not in SEVERITIES:
        raise ValueError(f"Unknown severity threshold: {fail_on}")
    if not report["observations"]:
        return 2
    if fail_on and any(SEVERITIES[item["severity"]] >= SEVERITIES[fail_on]
                       for item in report["findings"]):
        return 1
    return 0


def render_report_files(report: dict, format: str = "all") -> dict[str, str]:
    if format not in FORMATS:
        raise ValueError(f"Unknown report format: {format}")
    renderers = {"json": ("report.json", render_json),
                 "html": ("report.html", render_html),
                 "markdown": ("report.md", render_markdown)}
    return {filename: render(report) for key, (filename, render) in renderers.items()
            if format in ("all", key)}


def run_analysis(request: AnalysisRequest) -> AnalysisResult:
    """Read local evidence and publish reports, returning results without printing.

    Filesystem and validation errors propagate to the caller. Empty evidence
    still produces a coverage report and exit code 2, matching the CLI contract.
    """
    if request.format not in FORMATS:
        raise ValueError(f"Unknown report format: {request.format}")
    if request.fail_on is not None and request.fail_on not in SEVERITIES:
        raise ValueError(f"Unknown severity threshold: {request.fail_on}")
    output = new_directory(request.output)
    scope = read_json(request.scope, MAX_SCOPE_BYTES) if request.scope else None
    baseline = read_json(request.baseline) if request.baseline else None
    report = analyze(request.source.expanduser().absolute(), request.name, scope, baseline, output)
    files = render_report_files(report, request.format)
    publish_directory(output, files)
    return AnalysisResult(report, output, tuple(output / filename for filename in files),
                          analysis_exit_code(report, request.fail_on))


def format_analysis_summary(result: AnalysisResult) -> str:
    """Format the common human summary without writing to stdout."""
    report = result.report
    summary = report["summary"]
    lines = [f"ScopeLens | {summary['assets']} assets | {summary['services']} services | {summary['findings']} review findings",
             f"Coverage: {summary['files_parsed']}/{summary['files_total']} artifacts parsed | {len(report['warnings'])} diagnostics",
             f"Reports: {result.output}"]
    lines.extend(f"  {warning['code']}: {warning.get('path', '')} {warning['message']}"
                 for warning in report["warnings"][:8])
    return "\n".join(lines)
