# Local effect analysis

This package produces evidence and uncertainty, **not authorization**. It is
integrated into the released v0.1.20 hook path with the paired schema-37 API.
Clients require the API to acknowledge the exact local analysis and revalidate
filesystem evidence and policy expiry after the request.

`Engine.Analyze` parses supported Bash syntax without evaluating it.
`Engine.AnalyzeTool` also handles exact native Read/Write/Edit tool payloads and
Codex's native `apply_patch` envelope. Added/updated/deleted targets contribute
filesystem effects; malformed syntax, repeated targets and patch moves remain
unresolved. Patch text receives the same sensitive-literal inspection.
Installed `CallAnalyzer` implementations may add effect descriptions. Agent
descriptions and MCP names cannot register an analyzer or grant permission.

## Evidence and coverage

- Read, inspect, write, delete, execute, transmit and disclosure effects.
- Literal arguments, conditional branches, compound calls, inspected shell
  scripts, file redirections and selected system utilities.
- Path component identity, missing targets, symlink uncertainty, hard-link
  write risk and content-bound script/read inspection. There is no allow cache.
- Earlier writes in a compound action invalidate assumptions about later reads,
  deletes or script execution. Conditional branches retain possible mutations.
- Sensitive path/variable sources, assignment taint and recognizable credential
  formats in literal payloads and bounded ordinary-file reads. Reports do not
  include matched values. Raw reports/targets still need transport redaction.
- Local limits: 64 KiB per command/script/file, shell nesting depth four and
  4,096 structural steps. Exhaustion is unknown, never ordinary.

Unknown includes unsupported options, glob/variable expansion, most interpreters,
unrecognized tools, arbitrary executable locations, symlinks and oversized reads.
Network calls remain unknown even when a literal upload source was inspected.
The current analysis conservatively treats reads of protected config paths as
sensitive; false-positive behavior must be included in native workflow evaluation.

## Enforcement integration requirements

Analyze original input locally, then redact for retention. Bind reports to the
exact native action and workspace, recheck `Fresh()` at the hook boundary and
preserve current signed policy, session, tenant, expiry and revocation checks.
Model assistance cannot turn unknown into ordinary or override a local denial.

File checks are not atomic with the agent's later execution. This package does
not isolate concurrent processes, prove arbitrary scripts, validate shell startup
files/functions/aliases, or inspect credential formats it does not recognize.
Native agent permissions remain necessary. No laptop-wide protection is claimed.

Run `go test -race ./internal/semantics` for fixtures and
`go test ./internal/semantics -run '^$' -bench . -benchmem` for a local-only
microbenchmark. Neither establishes actual native-hook protection or total cost.
