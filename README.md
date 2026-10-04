# ScopeLens

**Turn collected assessment artifacts into a clear, traceable review.**

ScopeLens is an offline analysis tool for existing recon workspaces, ZIP archives, and individual supported artifacts. It imports evidence, organizes assets and services, identifies defensive configuration concerns, and produces reports you can inspect or compare over time. It works with the workspace layout created by [htb-init](https://github.com/Zendeni/htb-init) and also accepts supported artifacts in other directory layouts.

Python 3.10+ · Linux, macOS, Windows · No runtime dependencies · No network requests

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

## Analyze an existing workspace

```console
scopelens analyze /path/to/htb-workspace -o review-001 --name "Internal review"
scopelens analyze /path/to/recon.zip -o review-002 --scope examples/scope.json
```

The input may be a directory, ZIP archive, or individual supported file. Both a flat archive and an archive containing a workspace directory are supported. `.target.env` is read as text; it is never sourced as a shell script.

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

```console
scopelens analyze /path/to/new-workspace -o review-003 --baseline review-001/report.json
scopelens diff review-001/report.json review-003/report.json -o changes.json
```

A difference describes service and finding changes in the two reports. A removed service or finding can result from different inputs, collection gaps, or parser coverage; it does not prove that a service was removed or a finding remediated. Compare equivalent collections before drawing operational conclusions.

### Select output and a review threshold

```console
scopelens analyze examples/demo -o json-review --format json
scopelens analyze examples/demo -o threshold-review --fail-on medium
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

This prepares a local workspace for artifacts. It does not collect data. Copy supported results into `my-review/evidence/`, then run `scopelens analyze my-review/evidence -o my-review/reports/review-001 --scope my-review/scope.json`. The scope file is used only when supplied with `--scope`.

### Inspect the installation and rules

```console
scopelens doctor
scopelens rules
scopelens --help
scopelens analyze --help
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

## Development

No external test framework is required:

```console
python -m unittest discover -s tests -v
python -m scopelens doctor
python -m scopelens analyze examples/demo -o development-report --scope examples/scope.json
```

CI runs the test suite and demo analysis on Linux and Windows with Python 3.10 and 3.13. See [architecture](docs/architecture.md) for the data flow and implementation boundaries.
