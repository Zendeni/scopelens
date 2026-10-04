# Input compatibility

ScopeLens reads existing artifacts from a directory, ZIP archive, or individual supported file. It never executes a file found in the input. The same analysis command works for htb-init workspaces and supported files collected by other workflows.

## htb-init workspaces

The original layout is accepted directly:

```text
workspace/
  .target.env
  summary.md
  scans/
    tcp-full.txt
    tcp-services.txt
    tcp-aggressive.txt
    udp-top100.txt
    port-summary.md
  enum/
    web/
    dns/
    smb/
    ldap/
```

The input reader tolerates other workspace files. Being present in the input does not mean a file has a dedicated parser or that every line becomes an observation. Inspect the report's import coverage and diagnostics to understand what contributed to an analysis.

`.target.env` supplies workspace context as plain text. Its contents are not shell-evaluated. ScopeLens does not require Bash, Kali Linux, a hardcoded workspace root, or a modified hosts file.

### Shared workspace commands in 0.2.0

The updated htb-init initializer creates workspaces under `$HOME/htb_labs/<box>` by default, with an optional `HTB_LABS_ROOT` override. If ScopeLens 0.2.0 or newer is installed, it prepares the workspace for offline review automatically. Older workspaces can be prepared directly:

```console
scopelens prepare /path/to/workspace
scopelens inspect /path/to/workspace
scopelens review /path/to/workspace
```

These commands accept an existing workspace directory. `prepare` creates only missing integration files:

| File | Contract |
| --- | --- |
| `scope.json` | Initial include entries from literal `IP` and `HOST` values in `.target.env`; existing scope is preserved |
| `analyze.sh` | Calls the installed ScopeLens package to review its own workspace; accepts review options |
| `inspect.sh` | Calls the installed ScopeLens package to inspect its own workspace; accepts `--json` |
| `ANALYSIS.md` | Local instructions for scope, inspection, review, and comparisons |

Preparation preserves existing helper files and custom content. If neither a scope file nor usable target metadata exists, supply `--target` entries explicitly. It does not run imported scripts or collect evidence. The Bash helpers use isolated Python execution so that a Python module placed in an evidence directory is not used as the analyzer. Install ScopeLens into the active Python environment; merely placing its checkout next to the workspace is not sufficient for those helpers. They use `python3` unless the `HTB_PYTHON` environment variable selects another executable.

`review` requires a scope file and automatically uses the workspace's `scope.json` unless `--scope` supplies another file. Review the scope after preparation, including aliases used in your evidence. Every run chooses a fresh `reports/<timestamp>-<unique-suffix>/` directory and saves all three report formats by default. `--output` selects an explicit new output directory; `--format` selects one format; `--fail-on` sets a finding severity threshold using the same exit codes as `analyze`.

```console
scopelens review /path/to/workspace --baseline latest
scopelens review /path/to/workspace --baseline /path/to/earlier/report.json
scopelens inspect /path/to/workspace --json
```

`--baseline latest` selects the latest valid saved ScopeLens JSON report by its generation time. It errors when no eligible baseline exists. A run containing only HTML or Markdown is not a JSON baseline. Comparison describes changes in the supplied artifacts and does not independently confirm remediation.

`inspect` is read-only: it reports workspace metadata, scope status, file loading coverage, saved report summaries, and diagnostics. A loaded file is readable but may not have a supported parser; use a review report to inspect parsing coverage. JSON inspection output includes `workspace`, `targets`, `scope`, `artifact_counts`, `artifacts`, `reports`, and `diagnostics`. It does not create a new report snapshot.

The original `analyze` command remains available for directories, ZIPs, and individual supported artifacts, with an explicit new output directory. It uses scope only when `--scope` is supplied; it does not automatically adopt the prepared workspace's scope file.

The htb-init ZIP helper writes a flat archive containing `.target.env`, `scans/`, `enum/`, and supporting files. ScopeLens also accepts an archive containing a workspace directory. The original ZIP helper excludes `loot/`, screenshots, packet captures, and nested archives. Their absence in an archive must not be read as evidence that no such material exists. Raw archives preserve original evidence and may include sensitive material; report redaction does not alter them. Review snapshots under `reports/` are stored separately and are not automatically included in those archives.

## Supported formats

| Artifact | What ScopeLens extracts | Important limit |
| --- | --- | --- |
| Nmap XML | Host and service observations, protocol, port, service identity and recorded details | Scanner observations are not proof of reachability at analysis time |
| Nmap text | Reported host context and service rows, including their recorded state | Text output has less structure than XML; ambiguous context cannot be repaired by guessing |
| httpx JSONL | Web endpoints, recorded status, titles, technology and selected saved response details | Missing fields in a JSON record are not equivalent to absent controls |
| httpx text | Recognizable web endpoint observations | Prefer JSONL when structured fields are available |
| Saved HTTP headers | Recorded response headers and cookie attributes with available endpoint context | Only captured response evidence can support header and cookie checks |
| ffuf JSON | Recorded result URLs and response metadata | A discovered URL does not establish a vulnerability |
| `package-lock.json` | Recorded npm components and versions | Inventory only; no automatic vulnerability matching |
| Python requirements | Explicit package/version pins | Constraints, editable sources, and unpinned requirements may not provide an exact version |

Nmap text emitted under the existing htb-init `scans/` filenames is supported. Structured Nmap XML is preferable when already available because it preserves host boundaries and transport protocols.

For a saved HTTP header capture, provide one final response and an explicit `URL: https://portal.example.test/` line when the filename does not establish a unique endpoint. Redirect chains need separate captures. ScopeLens can use selected headers present in httpx JSONL, but does not assume that a httpx header map contains every response header; checks for missing headers require a complete raw capture.

Other htb-init files can contain useful context for a human review but may not have a dedicated parser in this release. In particular, generic tool logs, notes, generated writeups, SMB enumeration text, LDAP output, downloaded JavaScript, and scanner summaries should not be assumed to receive full semantic analysis. ScopeLens reports coverage rather than promising universal parsing.

## Scope

Scope files use JSON with `include` and `exclude` lists. Entries describe IP addresses, CIDRs, or hostnames. Matching is performed locally, without DNS queries. List names and IP addresses separately when your evidence uses both.

```json
{
  "include": ["192.0.2.0/24", "portal.example.test"],
  "exclude": ["192.0.2.99"]
}
```

Exclusions override inclusions. An omitted or empty include list admits all observed host identifiers except explicit exclusions and produces a `scope_unspecified` warning. ScopeLens does not derive authorization from an address, a domain, or the name of an input directory.

Package manifests do not establish which host uses a dependency. Their observations are retained independently of host scope and accompanied by an `unattributed_packages` warning. These package entries are excluded from the asset count.

The asset count measures distinct observed IP/DNS identifiers rather than inferred physical machines. The demo has four identifiers for two nominal hosts. Service totals count unique asset/protocol/port combinations, while inventory cards retain separate fingerprints if recorded attributes differ. Web totals count unique sanitized URLs; multiple response observations can refer to one endpoint.

## Resource limits

The default CLI limits are fixed for this release:

| Resource | Limit | What happens at the limit |
| --- | --- | --- |
| Directory traversal | 3,000 entries, including directories | Traversal stops with an incompleteness warning; unvisited descendants are not individually listed |
| ZIP contents | 3,000 entries, including directories | Larger archives are rejected |
| Individual artifact | 4 MiB | Oversized files are skipped without partial parsing |
| Total artifact bytes read | 64 MiB | Further artifacts that exceed the budget are skipped |
| ZIP file size on disk | 128 MiB compressed | Larger archives are rejected |
| ZIP member expansion ratio | 200:1 | Members above the ratio are skipped |
| Parser observations | 5,000 per document; 10,000 across the analysis, before deduplication and scope filtering | The affected import stops with an incompleteness warning |

Parser diagnostics are also bounded at 100 per document and 1,000 across an analysis, plus a terminal limit warning. Web records are bounded to 256 cookie entries and 256 technology entries. Reaching a parser limit preserves observations already imported, so a file marked parsed can still be incomplete; inspect its warnings.

ZIP files are read in place and never extracted. Unsafe, duplicate, or ambiguous archive member names reject the archive; encrypted entries and archive links are skipped. Directory symlinks, file symlinks, special files, and common generated or sensitive directories such as `.git`, `node_modules`, `loot`, and `reports` are skipped. Import coverage records parsed, unrecognized, empty, skipped, or error states. Coverage describes import before scope filtering, so a parsed artifact may contribute no in-scope observations.

## Diagnostics and limitations

Malformed, unsupported, empty, or bounded inputs can reduce coverage. Check diagnostics before relying on a result, particularly when no findings appear. Findings describe the supplied evidence and cannot establish that an entire environment was assessed.

The analyzer does not ingest packet captures or binary files as semantic evidence, recursively unpack arbitrary nested archives, execute scanner plugins, or contact URLs found in an artifact. It does not preserve secrets as report content intentionally, but automated redaction cannot identify every sensitive value.

The bundled `examples/demo` dataset is synthetic and uses `192.0.2.0/24` and `example.test`. It exercises multiple assets, TCP/UDP separation, structured and textual scanner output, web metadata, and defensive configuration review.
