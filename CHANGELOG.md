# Changes

## 0.3.0

- Added `service.AnalysisRequest`, `AnalysisResult`, and `run_analysis` for Python callers. CLI analysis and workspace review share this silent service and the same threshold handling.
- Removed the workspace-to-CLI dependency and recursive argument parsing.
- Separated scope, evidence normalization, review rules, and snapshot comparison from report assembly. Existing engine imports remain available.
- Split HTML and Markdown rendering into focused modules and moved styles and scripts into readable package resources. Generated HTML remains self-contained.
- Centralized bounded JSON reads and path checks. Report publication rejects unsafe relative filenames, preserves competing files, and keeps the original error if temporary cleanup fails.
- Rejected scope names with repeated trailing dots. Made service comparison stable when conflicting evidence rows change order.
- Expanded regression coverage for library use, publication failures, report resources, and compatibility. CI checks the installed package independently of the source checkout.

Command names, report schema version 1, review defaults, and documented exit codes remain compatible with 0.2.0. The htb-init adapter continues to use the installed ScopeLens package.

## 0.2.0

- Added workspace preparation, inspection, review snapshots, and latest-baseline selection.
- Aligned htb-init with the shared offline review workflow.

## 0.1.0

- Initial offline import, evidence model, explicit scope, defensive rules, HTML/JSON/Markdown reporting, and snapshot comparison.
