"""Command-line workflow; no shell or network execution."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile

from . import __version__
from .engine import RULES, analyze, compare_reports, normalize_host, validate_scope
from .inputs import is_link
from .model import SEVERITIES, redact
from .reports import render_html, render_json, render_markdown


def read_json(path: Path, limit: int = 32 * 1024 * 1024):
    if not path.is_file() or is_link(path):
        raise ValueError(f"Expected a regular JSON file: {path}")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"JSON file exceeds {limit} bytes")
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON: {path.name}") from exc


def publish_directory(destination: Path, files: dict[str, str]) -> None:
    destination = destination.expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"Output already exists; choose a new directory: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".scopelens-", dir=destination.parent))
    try:
        try:
            stage.chmod(0o700)
        except OSError:
            pass
        for name, content in files.items():
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
            try:
                path.chmod(0o600)
            except OSError:
                pass
        # Claim the destination without ever replacing an existing directory.
        destination.mkdir()
        try:
            for child in stage.iterdir():
                shutil.move(str(child), str(destination / child.name))
            try:
                destination.chmod(0o700)
            except OSError:
                pass
        except Exception:
            # Preserve partial output for inspection; do not delete user data.
            raise
    finally:
        shutil.rmtree(stage)


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(prog="scopelens", description="Turn existing assessment artifacts into evidence-backed reports. Offline; never executes scanners or collected scripts.")
    cli.add_argument("--version", action="version", version=f"ScopeLens {__version__}")
    commands = cli.add_subparsers(dest="command", required=True)
    analysis = commands.add_parser("analyze", help="Analyze a directory, ZIP, or supported artifact")
    analysis.add_argument("input", type=Path)
    analysis.add_argument("-o", "--output", type=Path, default=Path("scopelens-report"), help="New output directory (never overwrites)")
    analysis.add_argument("--name", default="", help="Assessment name")
    analysis.add_argument("--scope", type=Path, help="JSON include/exclude list of exact hosts, IPs, or CIDRs")
    analysis.add_argument("--baseline", type=Path, help="Previous ScopeLens report.json")
    analysis.add_argument("--fail-on", choices=SEVERITIES, help="Return exit 1 if a finding meets this severity")
    analysis.add_argument("--format", choices=("all", "json", "html", "markdown"), default="all")
    initialize = commands.add_parser("init", help="Create an evidence workspace with scope and notes")
    initialize.add_argument("path", type=Path)
    initialize.add_argument("--name", required=True)
    initialize.add_argument("--target", action="append", default=[], help="Exact host, IP, or CIDR; repeat as needed")
    prepare = commands.add_parser("prepare", help="Add ScopeLens helpers to an existing workspace, preserving files")
    prepare.add_argument("path", type=Path)
    prepare.add_argument("--name", default="", help="Assessment name")
    prepare.add_argument("--target", action="append", default=[], help="Exact host, IP, or CIDR; repeat to override inferred targets for a new scope")
    review = commands.add_parser("review", help="Review a prepared workspace into a new offline report snapshot")
    review.add_argument("path", type=Path)
    review.add_argument("-o", "--output", type=Path, help="New report directory; defaults to a unique snapshot in PATH/reports/")
    review.add_argument("--scope", type=Path, help="Scope JSON; defaults to PATH/scope.json (required)")
    review.add_argument("--name", default="", help="Assessment name")
    review.add_argument("--baseline", help="Prior report.json or 'latest' for the newest valid workspace snapshot")
    review.add_argument("--fail-on", choices=SEVERITIES)
    review.add_argument("--format", choices=("all", "json", "html", "markdown"), default="all")
    inspect = commands.add_parser("inspect", help="Read workspace targets, scope, artifact counts, and prior reports")
    inspect.add_argument("path", type=Path)
    inspect.add_argument("--json", action="store_true", help="Machine-readable inventory")
    commands.add_parser("doctor", help="Show runtime and offline capabilities")
    commands.add_parser("rules", help="List the review rules and their assumptions")
    diff = commands.add_parser("diff", help="Compare two ScopeLens JSON reports")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("-o", "--output", type=Path)
    return cli


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command in {"prepare", "review", "inspect"}:
            from . import workspace
            if args.command == "prepare":
                result = workspace.prepare(args.path, args.name, args.target)
                print(f"Workspace prepared: {result['workspace']}")
                print("Created: " + (", ".join(result["created"]) or "none"))
                print("Preserved: " + (", ".join(result["preserved"]) or "none"))
                for filename in result["different_helpers"]:
                    print(f"Preserved customized helper: {filename}. Use scopelens review PATH or scopelens inspect PATH directly if needed.")
                for diagnostic in result["diagnostics"]:
                    print(f"  {diagnostic['code']}: {diagnostic['message']}")
                print("Next: scopelens inspect PATH, then scopelens review PATH")
                return 0
            if args.command == "review":
                return workspace.review(args.path, output=args.output, scope=args.scope,
                                        name=args.name, baseline=args.baseline,
                                        fail_on=args.fail_on, format=args.format)
            result = workspace.inspect(args.path)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                workspace.print_inspection(result)
            return 2 if result["scope"]["status"] == "invalid" else 0
        if args.command == "doctor":
            print(f"ScopeLens {__version__}\nPython {platform.python_version()} | {platform.system()}\nRuntime dependencies: standard library only\nNetwork access: none\nExecution of imported scripts: none\nInputs: directory, ZIP, Nmap XML/text, httpx, ffuf, HTTP headers, package inventories\nOutputs: JSON, Markdown, standalone HTML")
            return 0
        if args.command == "rules":
            print(json.dumps(RULES, indent=2))
            return 0
        if args.command == "init":
            scope = validate_scope({"include": [normalize_host(t) for t in args.target], "exclude": []})
            name = redact(args.name)
            publish_directory(args.path, {
                "scope.json": json.dumps(scope, indent=2) + "\n",
                "assessment.json": json.dumps({"name": name, "purpose": "Offline evidence analysis", "schema_version": 1}, indent=2) + "\n",
                "notes.md": f"# {name}\n\n## Context\n\nRecord ownership, collection dates, and assessment scope.\n\n## Observations\n\n## Decisions and follow-up\n",
                "evidence/.gitkeep": "",
                ".gitignore": "evidence/*\n!evidence/.gitkeep\nreports/\n",
            })
            print(f"Workspace created: {args.path.absolute()}\nPlace collected artifacts in evidence/ and pass --scope scope.json when analyzing.")
            return 0
        if args.command == "diff":
            diff = compare_reports(read_json(args.before), read_json(args.after))
            text = json.dumps(diff, ensure_ascii=False, indent=2) + "\n"
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                with args.output.open("x", encoding="utf-8") as stream:
                    stream.write(text)
                print(f"Comparison written: {args.output.absolute()}")
            else:
                print(text, end="")
            return 0
        if args.output.exists():
            raise ValueError(f"Output already exists; choose a new directory: {args.output}")
        scope = read_json(args.scope, 1024 * 1024) if args.scope else None
        baseline = read_json(args.baseline) if args.baseline else None
        report = analyze(args.input.expanduser().absolute(), args.name, scope, baseline, args.output)
        renderers = {"json": ("report.json", render_json), "html": ("report.html", render_html), "markdown": ("report.md", render_markdown)}
        files = {filename: render(report) for key, (filename, render) in renderers.items() if args.format in ("all", key)}
        publish_directory(args.output, files)
        summary = report["summary"]
        print(f"ScopeLens | {summary['assets']} assets | {summary['services']} services | {summary['findings']} review findings\nCoverage: {summary['files_parsed']}/{summary['files_total']} artifacts parsed | {len(report['warnings'])} diagnostics\nReports: {args.output.absolute()}")
        for warning in report["warnings"][:8]:
            print(f"  {warning['code']}: {warning.get('path', '')} {warning['message']}")
        if not report["observations"]:
            return 2
        if args.fail_on and any(SEVERITIES[f["severity"]] >= SEVERITIES[args.fail_on] for f in report["findings"]):
            return 1
        return 0
    except (OSError, ValueError, RecursionError) as exc:
        print(f"scopelens: {redact(exc)}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("scopelens: interrupted", file=sys.stderr)
        return 130
