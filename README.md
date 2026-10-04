# ScopeLens

**Turn collected assessment artifacts into a clear, traceable review.**

ScopeLens is an offline analysis tool for existing recon workspaces, ZIP archives, and individual supported artifacts. It imports evidence, organizes assets and services, identifies defensive configuration concerns, and produces reports you can inspect or compare over time. It works with the workspace layout created by [htb-init](https://github.com/Zendeni/htb-init) and also accepts supported artifacts in other directory layouts.

ScopeLens 0.3.0 · Python 3.10+ · Linux, macOS, Windows · No runtime dependencies · No network requests

## Try it

From the repository root, with Python 3.10 or newer:

```console
python -m pip install .
scopelens doctor
scopelens analyze examples/demo -o demo-report --scope examples/scope.json
```

Open `demo-report/report.html` in your browser. Filter findings by severity, asset, or text, expand their evidence, or use the browser print view. The output directory also contains `report.json` for integrations and `report.md` for notes or review. The demo uses reserved documentation addresses and synthetic data.

You can run directly from the checkout without installing:

```console
python -m scopelens analyze examples/demo -o another-demo-report
```

Use a **new output directory for every run**. ScopeLens refuses to overwrite an existing report directory.

## What it does

- Imports Nmap XML and text, httpx JSONL and text, saved HTTP headers, ffuf JSON, npm package locks, and pinned Python requirements.
- Preserves host, protocol, and port identity: `53/tcp` and `53/udp` remain separate services.
- Attaches source paths, artifact hashes, and source locations to observations so you can check the evidence.
- Reports import coverage and parsing problems alongside findings. Empty or unsupported evidence is not treated as proof that a host is secure.
- Separates observed facts from defensive review findings, with confidence, rationale, and remediation.
- Applies an optional explicit scope file to filter host observations. Package manifests remain separate inventory because they do not establish a host association.
- Redacts common secret patterns in evidence excerpts and removes URL user information, query values, and fragments from exported URLs.
- Generates a self-contained HTML report, a versioned JSON report, and Markdown.
- Compares report snapshots to identify changes in the supplied evidence.
- Supports a severity threshold for use in automated checks.

ScopeLens analyzes files already collected. It does not run scanners, execute imported scripts, contact targets, authenticate to services, select exploits, or infer CVEs from a port number. A service banner or configuration observation is not a confirmed vulnerability. Its findings are prompts for defensive review, not guarantees about the security of a system.

## Prepare, inspect, and review a workspace

ScopeLens and [htb-init](https://github.com/Zendeni/htb-init) share one reporting workflow. With ScopeLens installed, prepare an existing workspace once:

```console
scopelens prepare /path/to/htb-workspace
scopelens inspect /path/to/htb-workspace
scopelens review /path/to/htb-workspace
```

`prepare` creates missing `scope.json`, `analyze.sh`, `inspect.sh`, and `ANALYSIS.md` files, preserving existing files and user scope. Initial scope entries come from literal `IP` and `HOST` metadata in `.target.env`; that file is read as text and never executed. If neither scope nor usable target metadata exists, supply `--target 192.0.2.10` and repeat `--target` for additional names or addresses. Review the generated scope before relying on it.

`inspect` reads file loading coverage and saved report information without creating a report. A loaded artifact is readable, not necessarily parsed or understood; check the review report for parser coverage. Add `--json` for machine-readable output.

`review` requires a scope file and defaults to the workspace's `scope.json`. It saves a fresh snapshot under `reports/` by default. Run `prepare` first if scope is missing, or supply another file with `--scope`. Open the printed `report.html` path to search findings and inspect their evidence. The default output also includes `report.json` and `report.md`. Choose `--format json`, `--format html`, or `--format markdown` when only one format is needed. Use `-o /path/to/new-review` to choose the output directory explicitly.

The generated helpers work from any current directory and require Bash and the installed package:

```bash
cd /path/to/htb-workspace
./inspect.sh
./analyze.sh
./analyze.sh --baseline latest
```

They use `python3` from your active environment. Set `HTB_PYTHON` to another Python executable when needed.

`--baseline latest` compares against the latest eligible JSON report saved in the workspace. It fails if no earlier report is available; create your first review without that option. An explicit `--baseline /path/to/report.json` is also supported. Runs that save only HTML or Markdown cannot serve as JSON baselines.

### Install alongside htb-init

Use sibling checkouts and one virtual environment on Linux or macOS:

```bash
git clone https://github.com/Zendeni/htb-init.git
git clone https://github.com/Zendeni/scopelens.git
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ./scopelens
bash htb-init/htb-init.sh example 192.0.2.10
```

The updated initializer defaults to `$HOME/htb_labs/example` and prepares analysis helpers automatically when ScopeLens 0.2.0 or newer is installed. Use `HTB_LABS_ROOT` to choose another workspace root. Initialization creates files without running the generated collection scripts. For older workspaces, use `scopelens prepare` to add the same review workflow. Reactivate the shared environment in each new terminal.

Windows users can run ScopeLens commands directly with Python 3.10 or newer; the htb-init initializer and shell helpers require a Bash environment.

## Analyze an archive or choose explicit paths

```console
scopelens analyze /path/to/htb-workspace -o review-001 --name "Internal review"
scopelens analyze /path/to/recon.zip -o review-002 --scope examples/scope.json
```

The `analyze` input may be a directory, ZIP archive, or individual supported file. Both a flat archive and an archive containing a workspace directory are supported. `.target.env` is read as text; it is never sourced as a shell script. Unlike `review`, `analyze` uses a scope file only when supplied explicitly with `--scope` and requires a new output directory.

The original htb-init exports can be used directly. See [format compatibility](docs/compatibility.md) for supported inputs and limits.

### Scope

A scope file contains explicit IP addresses, CIDR networks, or DNS hostnames:

```json
{
  "include": ["192.0.2.0/24", "portal.example.test"],
  "exclude": ["192.0.2.99"]
}
```

Scope matching is local and does not resolve DNS. DNS entries match exact names. Include the names and addresses that appear in your evidence. Exclusions take priority. An empty or omitted include list admits all observed host identifiers except explicit exclusions and produces a `scope_unspecified` warning; the tool does not establish authorization or network reachability from a supplied artifact.

IP addresses and DNS names remain independent asset identifiers, even when they may describe the same machine. The demo reports four identifiers for two nominal hosts. Package observations are retained independently of host scope with an `unattributed_packages` warning, and are excluded from the asset count.

The service total counts unique asset/protocol/port combinations. The inventory may show several observations of one service when fingerprints differ, preserving the separate evidence instead of choosing one banner as authoritative. Likewise, the web endpoint total counts unique sanitized URLs while the inventory retains distinct captured responses.

### Compare snapshots

For a prepared workspace, compare a new review against its last saved JSON report:

```console
scopelens review /path/to/htb-workspace --baseline latest
```

To select the output and baseline paths explicitly, or compare two existing reports:

```console
scopelens analyze /path/to/new-workspace -o review-003 --baseline review-001/report.json
scopelens diff review-001/report.json review-003/report.json -o changes.json
```

A difference describes service and finding changes in the two reports. A removed service or finding can result from different inputs, collection gaps, or parser coverage; it does not prove that a service was removed or a finding remediated. Compare equivalent collections before drawing operational conclusions.

### Select output and a review threshold

```console
scopelens analyze examples/demo -o json-review --format json
scopelens analyze examples/demo -o threshold-review --fail-on medium
scopelens review /path/to/htb-workspace --fail-on medium
```

`--format` accepts `all`, `json`, `html`, or `markdown`. `--fail-on` accepts `info`, `low`, `medium`, `high`, or `critical`; it returns a nonzero status when a finding reaches the selected threshold. Findings use the local rule set rather than a CVSS calculation or online vulnerability database.

| Exit code | Meaning |
| --- | --- |
| `0` | Command completed; no selected finding threshold was reached |
| `1` | Analysis completed and a finding met or exceeded `--fail-on`; reports were saved |
| `2` | Usage, input, or runtime error; also returned when analysis produces no observations. In the no-observation case, the requested reports are saved with coverage and diagnostics |
| `130` | Interrupted by the user |

Import warnings alone do not force a failure when usable observations remain. Inspect coverage even when the exit code is `0`.

### Create a workspace

```console
scopelens init my-review --name "My review" --target 192.0.2.10 --target portal.example.test
```

This creates a new local workspace for artifacts. It does not collect data. Copy supported results into `my-review/evidence/`, then run `scopelens review my-review` to use its scope and create a report snapshot. Use `scopelens prepare my-review` if you also want the Bash helpers and local analysis instructions. `init` requires a new destination; `prepare` adds missing integration files to an existing directory.

### Inspect the installation and rules

```console
scopelens doctor
scopelens rules
scopelens --help
scopelens analyze --help
scopelens prepare --help
scopelens review --help
scopelens inspect --help
```

## From htb-init to ScopeLens

The earlier analyzer provided a useful starting point: import a workspace, extract clues, and produce a readable summary. ScopeLens changes the underlying design to make those summaries easier to trust and maintain:

| Earlier limitation | ScopeLens approach |
| --- | --- |
| Ports keyed only by number could merge TCP and UDP | Asset, protocol, and port stay distinct |
| Technology and header signals pooled across files | Observations retain an asset and their evidence |
| Skipped or malformed inputs were difficult to see | Explicit import coverage and diagnostics |
| Interesting lines could reproduce credentials | Redacted excerpts and sanitized URLs |
| One large script and one Markdown output | Separate import, analysis, and reporting code; HTML, JSON, and Markdown |
| Repeated reviews required manual comparison | Stable observation identities and snapshot comparison |

Redaction is best effort. Paths, hostnames, package names, and other assessment context may still be sensitive. Review reports before sharing them.

Raw htb-init archives preserve the original collected material and may contain secrets. The `reports/` snapshots are separate, excluded from evidence imports, and not automatically included in those archives. For the earlier htb-init workflow, see its [legacy documentation](https://github.com/Zendeni/htb-init/blob/main/docs/legacy-workflow.md).

## Development

The command line and workspace review use the same analysis service. Python integrations can use it directly without constructing command arguments or capturing console output:

```python
from pathlib import Path
from scopelens.service import AnalysisRequest, run_analysis

result = run_analysis(AnalysisRequest(
    source=Path("examples/demo"),
    output=Path("api-review"),  # Must not already exist.
    scope=Path("examples/scope.json"),
    fail_on="medium",
))
print(result.report["summary"])
print(result.paths)
print(result.exit_code)
```

The service saves the requested reports and returns their paths, report data, and the same analysis status as the CLI. Invalid inputs raise exceptions for the caller to handle. See [architecture](docs/architecture.md#code-map) for module responsibilities and [changes](CHANGELOG.md) for release notes.

No external test framework is required:

```console
python -m unittest discover -s tests -v
python -m scopelens doctor
python -m scopelens analyze examples/demo -o development-report --scope examples/scope.json
```

CI runs the test suite and demo analysis on Linux and Windows with Python 3.10 and 3.13. See [architecture](docs/architecture.md) for the data flow and implementation boundaries.
