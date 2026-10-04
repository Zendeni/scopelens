# Architecture

ScopeLens converts collected artifacts into a reproducible local review. Runtime code uses the Python standard library and does not launch assessment tools or make network requests.

## Data flow

```text
Directory, ZIP, or supported file
      |
      v
Bounded artifact import ---------> Coverage and diagnostics
      |
      v
Format parsers ------------------> Observations with source evidence
      |
      v
Scope filtering and normalization
      |
      v
Defensive rule evaluation -------> Findings with rationale and remediation
      |
      +---- Optional prior report -> Snapshot differences
      |
      v
Versioned JSON / standalone HTML / Markdown
```

The stages have different responsibilities:

1. **Import** reads data from the provided path and tracks files that could not be used. Archive and input limits protect the analysis process from unbounded resource use. Imported scripts and environment files are never executed.
2. **Parsing** recognizes supported artifact formats and emits observations. Parsers do not decide whether a discovered service is vulnerable.
3. **Normalization** associates observations with an asset and preserves protocol and port identity. Duplicate evidence can support the same observation without becoming an independent finding.
4. **Scope filtering** evaluates supplied IP addresses, CIDRs, and hostnames locally. It performs no DNS resolution and has no knowledge of ownership or authorization. Package observations remain independent of host scope because manifests do not establish a host association; the report records this limitation as a warning.
5. **Rules** evaluate the observations for defensive review. A rule must have relevant evidence and explain the concern and remediation. An open port alone cannot establish a missing authentication control or a specific CVE.
6. **Reporting** renders the resulting data. The JSON format serves as the integration and baseline format; the other outputs are human views of the analysis.

## Code map

| Module | Responsibility |
| --- | --- |
| `cli.py` | Argument parsing, command dispatch, and user-facing status |
| `workspace.py` | Preparation, report history, inspection, and review defaults |
| `service.py` | Shared analysis request/result API, output formats, and threshold status |
| `storage.py` | Bounded JSON reads, path checks, and exclusive report publication |
| `inputs.py`, `parsers.py` | Bounded artifact loading and format recognition |
| `engine.py` | Compose import, normalization, scope, rules, and report data |
| `scope.py` | Normalize and match explicit host identifiers and networks |
| `evidence.py` | Sanitize and deduplicate exported observations |
| `rules.py` | Defensive rule catalog and finding generation |
| `comparison.py` | Validate saved snapshots and compare their evidence |
| `reporting/` | HTML and Markdown renderers, shared escaping, packaged CSS and JavaScript |
| `reports.py` | Stable public renderer imports and JSON serialization |

CLI analysis and workspace review both call `service.run_analysis`; workspace code does not import the CLI or reconstruct command arguments. The service returns an `AnalysisResult` without printing. It raises validation and filesystem errors; the CLI translates those errors into its documented status codes. Scope, rules, evidence, and comparison helpers remain available through their earlier `engine` imports.

Report assets are loaded through `importlib.resources` and embedded into the generated HTML. They ship in the installed package; reports do not depend on the source checkout, a local server, or external styles and scripts. Format-specific rendering is separate from the application workflow.

Publication validates paths and stages complete text before claiming a new destination directory. Existing directories and files are never replaced. A publication failure can leave partial output for inspection; callers must choose another destination when retrying. Temporary staging cleanup does not mask the original error. These checks are safeguards for local files, not a filesystem sandbox against another process actively replacing directories.

## Observation and evidence model

An observation records a kind, asset, structured data, confidence, stable identity, and evidence references. Evidence includes the relative artifact path, a SHA-256 digest of the artifact content, a source line where available, a structured locator where useful, and a sanitized excerpt.

Stable identities are derived from normalized content. They support deduplication and comparison across runs. A hash identifies the input bytes used by a report; it does not authenticate who collected them or whether their contents are accurate.

Service identity for totals and comparison includes the asset, transport protocol, and port. Observation identity also includes recorded attributes. Different fingerprints on the same service therefore remain separate inventory observations while contributing one service to the summary. Equivalent observations merge their evidence references.

Host context and web responses retain their observed identifiers. IP addresses and DNS names are not automatically made equivalent, and the asset count is a count of identifiers rather than physical machines. The synthetic demo has four identifiers for two nominal hosts. Unattributed observations and package inventory do not contribute to the asset count. Web endpoint totals count unique sanitized URLs rather than captured response observations.

## Findings and uncertainty

Rules provide severity and confidence separately. Severity describes the review concern; confidence describes support in the imported evidence. They are not CVSS scores.

Examples of appropriate rules are an observed cleartext service, a management interface that warrants exposure review, or missing cookie attributes in an actual saved HTTP response. Rules must avoid claiming that a management interface is internet-accessible merely because it appears in a scan. Absence of an artifact or an unrecorded HTTP header is also not evidence that the underlying control is absent.

Technology names and package versions are useful inventory. They are not automatically converted into vulnerability claims. ScopeLens ships without online vulnerability enrichment or exploit generation.

## Input and output boundaries

Input content is untrusted. It may include scanner reference links, markup, terminal escape sequences, copied secrets, malformed structured data, or misleading text. Imported content is treated as data throughout the pipeline. Reports escape content for their output context.

Common secret patterns are redacted from excerpts. Exported URLs omit user information, query values, and fragments. This is a practical reduction in exposure, not a guarantee that arbitrary sensitive text will be recognized. Source artifacts remain unchanged.

HTML reports are self-contained and can be opened locally. A new report directory is required so a run cannot silently replace earlier evidence or reports.

Import is bounded to 3,000 directory or ZIP entries, 4 MiB per artifact, and 64 MiB of artifact reads. ZIP files are limited to 128 MiB compressed, with a 200:1 member expansion ratio. Parsing stops at 5,000 observations per document or 10,000 total before deduplication and scope filtering. Diagnostics expose incomplete imports; see [compatibility](compatibility.md#resource-limits) for the distinction between rejection, skipping, and partial import. File coverage is measured before scope filtering.

## Baselines

A baseline is an earlier ScopeLens JSON report. Comparison uses normalized identities to describe added, removed, and changed services, plus added and removed findings. A removed item means it is absent from the later report; it does not prove remediation.

Useful comparisons require similar scope, artifact coverage, and collection methods. Review diagnostics alongside every difference. Results from different parser or rule versions can also differ even when the assessed environment did not change.

## Extension points

When adding a format parser:

- Accept only the supported structure and emit useful diagnostics for malformed input.
- Preserve the source asset, protocol, status, and evidence location.
- Treat source values as untrusted text and sanitize anything exported.
- Keep collection, network access, and subprocess execution outside the analyzer.
- Add representative synthetic fixtures and regression tests for information loss or false attribution.

When adding a rule, document the observed condition, uncertainty, and remediation. Test both supporting evidence and a nearby case that must not produce a finding. Avoid tests that merely repeat the rule implementation.

Run `python -m unittest discover -s tests -v` from the repository root. CI checks Linux and Windows on Python 3.10 and 3.13, along with installation, diagnostics, and a complete demo analysis.
