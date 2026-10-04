"""Additive workspace setup and read-only inspection of offline evidence."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets

from .engine import validate_report, validate_scope
from .inputs import is_link, load_input
from .model import redact
from .parsers import parse_documents

MAX_REPORT_ENTRIES = 1000
MAX_REPORT_BYTES = 64 * 1024 * 1024
HELPERS = {
    "analyze.sh": "review",
    "inspect.sh": "inspect",
}


def _no_links(path: Path) -> None:
    for part in (*reversed(path.parents), path):
        if os.path.lexists(part) and is_link(part):
            raise ValueError(f"Links are not allowed for workspace files: {part}")


def _workspace(path: Path) -> Path:
    path = path.expanduser().absolute()
    _no_links(path)
    if not path.is_dir():
        raise ValueError(f"Expected an existing workspace directory: {path}")
    return path


def _regular(path: Path, *, missing: bool = False) -> bool:
    _no_links(path)
    if not path.exists() and missing:
        return False
    if not path.is_file():
        raise ValueError(f"Expected a regular file: {path}")
    return True


def _target_metadata(workspace: Path) -> tuple[list[dict], list[dict]]:
    path = workspace / ".target.env"
    if not _regular(path, missing=True):
        return [], []
    documents, _, warnings = load_input(path)
    observations, diagnostics = parse_documents(documents)
    warnings.extend(diagnostics)
    return [item["data"] for item in observations if item["kind"] == "target"], warnings


def _helper(command: str) -> str:
    return ('#!/usr/bin/env bash\n'
            '# ScopeLens: inspect existing local evidence; never runs collection scripts.\n'
            'set -euo pipefail\n'
            'SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"\n'
            f'exec "${{HTB_PYTHON:-python3}}" -I -m scopelens {command} "$SCRIPT_DIR" "$@"\n')


def prepare(path: Path, name: str = "", targets: list[str] | None = None) -> dict:
    """Create missing bridge files only. Validate before writing anything."""
    from .cli import read_json

    workspace = _workspace(path)
    managed = ["scope.json", "ANALYSIS.md", *HELPERS]
    present = {filename: _regular(workspace / filename, missing=True) for filename in managed}
    metadata, warnings = _target_metadata(workspace)
    if present["scope.json"]:
        scope = validate_scope(read_json(workspace / "scope.json", 1024 * 1024))
        if targets:
            warnings.append({"code": "scope_preserved", "message": "Existing scope.json takes precedence over --target; edit it explicitly to change scope."})
    else:
        inferred = [value for target in metadata for value in (target["ip"], target["host"]) if value]
        include = list(dict.fromkeys(targets or inferred))
        if not include:
            raise ValueError("No usable targets found. Run prepare with --target HOST (repeat as needed), or create a valid scope.json.")
        scope = validate_scope({"include": include, "exclude": []})
    title = redact(name or next((target["name"] for target in metadata if target.get("name")), workspace.name))
    files = {
        "scope.json": json.dumps(scope, indent=2) + "\n",
        **{filename: _helper(command) for filename, command in HELPERS.items()},
        "ANALYSIS.md": (
            f"# {title}: offline evidence review\n\n"
            "ScopeLens reads collected files without contacting targets or executing scripts.\n"
            "Existing htb-init notes, evidence, and collection helpers are preserved.\n\n"
            "## Quick start\n\n"
            "Install ScopeLens once with `python3 -m pip install git+https://github.com/Zendeni/scopelens.git`.\n"
            "In this workspace, run:\n\n"
            "```sh\n./inspect.sh\n./analyze.sh\n./analyze.sh --baseline latest\n```\n\n"
            "The helpers find their own workspace even when run from another directory. "
            "They use the installed package in Python isolated mode.\n\n"
            "On any supported platform, use `scopelens inspect PATH` and `scopelens review PATH`.\n"
            "Review requires `scope.json` by default; inspect or edit its include/exclude lists first. "
            "An empty include list means all observed hosts except exclusions.\n\n"
            "Each review creates a new directory in `reports/` with HTML, JSON, and Markdown. "
            "The CLI prints the HTML path. `--baseline latest` compares against the latest valid JSON snapshot. "
            "Use `--fail-on medium` for an exit status threshold, or `--format json` for automation.\n\n"
            "Exit codes: 0 = completed; 1 = findings met the requested threshold; "
            "2 = invalid input or no supported in-scope observations. A report may still be written for code 2.\n"
        ),
    }
    created, preserved, different = [], [], []
    for filename, content in files.items():
        destination = workspace / filename
        if present[filename]:
            preserved.append(filename)
            if filename in HELPERS:
                with destination.open("rb") as stream:
                    existing = stream.read(64 * 1024 + 1)
                if existing != content.encode("utf-8"):
                    different.append(filename)
            continue
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        try:
            destination.chmod(0o700 if filename in HELPERS else 0o600)
        except OSError:
            pass
        created.append(filename)
    return {"workspace": str(workspace), "created": created, "preserved": preserved,
            "different_helpers": different, "scope": scope, "diagnostics": warnings}


def report_inventory(workspace: Path) -> tuple[list[dict], list[dict]]:
    """List direct report snapshots with bounded reads and no link traversal."""
    from .cli import read_json

    root = workspace / "reports"
    _no_links(root)
    if not root.exists():
        return [], []
    if not root.is_dir():
        raise ValueError(f"Expected a reports directory: {root}")
    reports, warnings = [], []
    consumed = 0
    with os.scandir(root) as entries:
        candidates = []
        for index, entry in enumerate(entries):
            if index >= MAX_REPORT_ENTRIES:
                warnings.append({"code": "report_limit", "message": f"Report inventory stopped at {MAX_REPORT_ENTRIES} entries; move older snapshots to an archive."})
                break
            candidates.append(Path(entry.path))
    if any(os.path.lexists(root / name) for name in ("report.json", "report.html", "report.md")):
        candidates.append(root)
    for directory in sorted(candidates):
        try:
            _no_links(directory)
            if not directory.is_dir():
                continue
            paths = {key: directory / filename for key, filename in
                     (("json", "report.json"), ("html", "report.html"), ("markdown", "report.md"))}
            available = {key: str(value) for key, value in paths.items() if _regular(value, missing=True)}
            if not available:
                continue
            item = {"directory": str(directory), "paths": available,
                    "status": "without_json", "generated_at": None, "summary": None}
            if "json" in available:
                size = paths["json"].stat().st_size
                if consumed + size > MAX_REPORT_BYTES:
                    warnings.append({"code": "report_byte_limit", "path": str(directory), "message": "Report inventory reached its total byte limit; some snapshots were not inspected."})
                    continue
                consumed += size
                report = validate_report(read_json(paths["json"]))
                if not isinstance(report.get("tool"), dict) or report["tool"].get("name") != "ScopeLens":
                    raise ValueError("JSON is not a ScopeLens-generated report")
                stamp = report.get("generated_at")
                if not isinstance(stamp, str):
                    raise ValueError("Report has no valid generation timestamp")
                generated = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                if generated.tzinfo is None:
                    raise ValueError("Report generation timestamp requires a timezone")
                summary = report.get("summary")
                if not isinstance(summary, dict) or any(type(summary.get(key)) is not int or summary[key] < 0 for key in ("assets", "services", "findings", "files_parsed", "files_total")):
                    raise ValueError("Report has an invalid summary")
                item.update(status="valid", generated_at=generated.astimezone(timezone.utc).isoformat(),
                            summary={key: summary[key] for key in ("assets", "services", "findings", "files_parsed", "files_total")})
            reports.append(item)
        except (OSError, ValueError, RecursionError) as exc:
            warnings.append({"code": "invalid_report", "path": str(directory), "message": redact(exc)})
    reports.sort(key=lambda item: (item["generated_at"] or "", item["directory"]), reverse=True)
    return reports, warnings


def review(path: Path, *, output: Path | None = None, scope: Path | None = None,
           name: str = "", baseline: str | None = None, fail_on: str | None = None,
           format: str = "all") -> int:
    from .cli import main, read_json

    workspace = _workspace(path)
    scope = (scope or workspace / "scope.json").expanduser().absolute()
    if not os.path.lexists(scope):
        raise ValueError(f"Scope file is missing: {scope}. Run scopelens prepare PATH --target HOST first, or pass --scope FILE.")
    _regular(scope)
    validate_scope(read_json(scope, 1024 * 1024))
    if baseline == "latest":
        reports, warnings = report_inventory(workspace)
        if any(item["code"] in {"report_limit", "report_byte_limit"} for item in warnings):
            raise ValueError("Report inventory is incomplete, so the latest baseline cannot be determined. Pass --baseline FILE explicitly, or archive older reports.")
        prior = next((item for item in reports if item["status"] == "valid"), None)
        if prior is None:
            raise ValueError("No valid prior JSON report in reports/. Run review once without --baseline, or pass --baseline FILE.")
        baseline = prior["paths"]["json"]
    if baseline:
        _regular(Path(baseline).expanduser().absolute())
    if output is None:
        root = workspace / "reports"
        _no_links(root)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        output = root / f"{stamp}-{secrets.token_hex(3)}"
    output = output.expanduser().absolute()
    _no_links(output)
    if output.exists():
        raise ValueError(f"Output already exists; choose a new directory: {output}")
    metadata, _ = _target_metadata(workspace)
    title = name or next((item["name"] for item in metadata if item.get("name")), workspace.name)
    argv = ["analyze", str(workspace), "--output", str(output), "--scope", str(scope), "--name", title, "--format", format]
    if baseline:
        argv.extend(["--baseline", str(Path(baseline).expanduser().absolute())])
        print(f"Baseline: {baseline}")
    if fail_on:
        argv.extend(["--fail-on", fail_on])
    result = main(argv)
    for filename in ("report.html", "report.json", "report.md"):
        report_path = output / filename
        if report_path.is_file():
            print(f"Open report: {report_path}")
            break
    return result


def inspect(path: Path) -> dict:
    from .cli import read_json

    workspace = _workspace(path)
    documents, coverage, diagnostics = load_input(workspace)
    target_documents = [doc for doc in documents if doc.path == ".target.env"]
    targets, warnings = parse_documents(target_documents)
    diagnostics.extend(warnings)
    scope_path = workspace / "scope.json"
    scope = {"path": str(scope_path), "status": "missing", "value": None}
    try:
        if _regular(scope_path, missing=True):
            scope.update(status="valid", value=validate_scope(read_json(scope_path, 1024 * 1024)))
        else:
            diagnostics.append({"code": "scope_missing", "message": "Run scopelens prepare PATH --target HOST before review."})
    except (OSError, ValueError, RecursionError) as exc:
        scope["status"] = "invalid"
        diagnostics.append({"code": "scope_invalid", "message": redact(exc)})
    try:
        reports, warnings = report_inventory(workspace)
        diagnostics.extend(warnings)
    except (OSError, ValueError) as exc:
        reports = []
        diagnostics.append({"code": "reports_unavailable", "message": redact(exc)})
    counts = Counter(row["status"] for row in coverage)
    return {"workspace": str(workspace), "targets": [item["data"] for item in targets],
            "scope": scope, "artifact_counts": {key: counts[key] for key in ("loaded", "empty", "skipped", "error")},
            "artifacts": coverage, "reports": reports, "diagnostics": diagnostics}


def print_inspection(result: dict) -> None:
    print(f"Workspace: {result['workspace']}\nScope: {result['scope']['status']} ({result['scope']['path']})")
    for target in result["targets"]:
        print(f"Target: {target['name']} | IP {target['ip'] or '-'} | host {target['host'] or '-'}")
    print("Artifacts: " + " | ".join(f"{count} {status}" for status, count in result["artifact_counts"].items()))
    print("Loaded means readable artifact, not a successful parser or a clean result.")
    print(f"Prior reports: {len(result['reports'])}")
    for report in result["reports"]:
        path = report["paths"].get("html") or report["paths"].get("json") or report["paths"].get("markdown")
        summary = report["summary"]
        detail = f"{summary['assets']} assets, {summary['services']} services, {summary['findings']} findings" if summary else "No JSON summary available"
        print(f"  {report['generated_at'] or 'undated'} | {detail}\n  {path}")
    for diagnostic in result["diagnostics"]:
        print(f"  {diagnostic['code']}: {diagnostic.get('path', '')} {diagnostic['message']}")
