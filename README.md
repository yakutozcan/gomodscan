# gomodscan

**Understand your Go dependencies before you upgrade them.**

`gomodscan` scans directories for Go modules and produces a single, interactive HTML report. Explore dependency versions, known vulnerabilities, compatibility estimates, and optional upgrade test results across multiple projects.

The report works offline: CSS and JavaScript are embedded, with no CDN, external fonts, or server required. **The report interface is currently in Turkish; CLI help, logs, and error messages are in English.**

## Features

- **Multi-project inventory** — recursively discover `go.mod` files, including nested modules, and record `go.work` files.
- **Module metadata** — Go and toolchain directives; direct/indirect requirements; replace, exclude, retract, and tool directives; `go.sum`, vendor, and optional Git metadata.
- **Version checks** — find the latest preferred version on the same module path, its release date, and Go requirement. Flag deprecated modules and retracted versions.
- **Security checks** — query OSV for current and target versions, with advisory IDs, CVE/GHSA aliases, and published fix versions.
- **Compatibility estimates** — highlight major, v0, prerelease, Go requirement, and excluded-target risks.
- **Optional source analysis** — integrate with `govulncheck` to report call paths to known vulnerable functions.
- **Optional upgrade trials** — build and test a baseline, then try each dependency upgrade in a fresh temporary copy.
- **Cross-project analysis** — compare direct dependency versions and visualize Go version distribution.
- **Interactive reporting** — search packages or CVEs, filter by project/type/risk, sort and paginate dependencies, and expand details on demand. Includes system dark mode and print support.
- **Bounded concurrency** — parallel module parsing and Git queries, plus separate limits for network and verification work.

Inspired by [Renovate](https://github.com/renovatebot/renovate)'s dependency visibility, security prioritization, and release-age concepts. This project is independently implemented and focuses on reporting; it does not create pull requests or automatically merge upgrades.

## Requirements

- **Go 1.27 or later**, as declared in `go.mod`.
- Git is optional; missing Git metadata does not fail a scan.
- Network access is needed for initial dependency installation and online checks.
- `govulncheck` must be installed separately when using `-govulncheck`.

## Install

Build from source:

```sh
git clone https://github.com/yakutozcan/gomodscan.git
cd gomodscan
go build -o gomodscan .
./gomodscan -h
```

Once the source is published to the repository, you can also install it with:

```sh
go install github.com/yakutozcan/gomodscan@latest
```

Ensure your Go binary installation directory is on `PATH`. On Windows, the built executable is `gomodscan.exe`.

## Quick start

Create a local inventory without online version or security checks:

```sh
./gomodscan -o report.html ~/projects/service-a ~/projects/service-b
```

Open `report.html` in a browser. Use the sidebar to switch between the overview, dependencies, modules, version differences, and errors. Click a dependency row for its details.

Check versions and known vulnerabilities:

```sh
./gomodscan -check-updates -o report.html ~/projects
```

Check vulnerabilities only, or disable OSV while checking versions:

```sh
./gomodscan -check-vulns ~/projects
./gomodscan -check-updates -check-vulns=false ~/projects
```

Tune scan depth and parallelism:

```sh
./gomodscan -depth 3 -scan-workers 8 -v ~/projects
```

> **Version checks can modify files.** Outside verification modes, `go list` runs in the source module with `GOFLAGS=-mod=mod`; it may update `go.mod` or `go.sum`. For a read-only inventory, leave online checks disabled. When `-try-upgrades` or `-govulncheck` is combined with version checks, version resolution runs in temporary copies instead.

## CLI reference

```text
gomodscan [flags] <directory> [directory...]
```

Place flags before directory arguments.

| Flag | Default | Description |
| --- | --- | --- |
| `-o <path>` | `gomod-report.html` | Output HTML file. |
| `-check-updates` | `false` | Resolve latest versions and enable OSV checks unless explicitly disabled. |
| `-check-vulns` | `false` | Query OSV independently. Use `-check-vulns=false` to override automatic enablement. |
| `-minimum-release-age <duration>` | `72h` | Warn when an update is younger than this threshold. |
| `-exclude <names>` | `vendor,node_modules,.git,testdata` | Comma-separated directory names to skip. Replaces the default list. |
| `-depth <n>` | `0` | Maximum directory depth; `0` means unlimited. |
| `-timeout <duration>` | `60s` | Per-module update/security budget and Git timeout. |
| `-scan-workers <n>` | CPU count | Concurrent module parsing and Git workers. |
| `-govulncheck` | `false` | Run the installed source vulnerability analyzer in module copies. |
| `-try-upgrades` | `false` | Run builds and project tests in module copies; also enables version checks. |
| `-verify-timeout <duration>` | `5m` | Separate timeout for each source analysis, baseline, or dependency upgrade trial. |
| `-verify-workers <n>` | `2` | Maximum concurrent verification modules. |
| `-v` | `false` | Verbose logs on stderr. |
| `-h` | — | Show help. |

Durations use Go syntax, such as `90s`, `5m`, or `168h`. Worker counts and timeouts must be positive.

### Scan behavior

- The root directory has depth zero; `-depth 1` includes its immediate subdirectories.
- Symbolic links are not followed. Excluded directories are never entered, even if an excluded name is supplied as the root.
- Nested modules are separate records. Overlapping roots are deduplicated; relative paths use the first root that discovers a module.
- Parsing and Git work run concurrently, while report records retain discovery order.
- Invalid modules and inaccessible paths are recorded without stopping the remaining scan.
- A successfully written partial or empty report returns exit code `0`. Invalid arguments, interruption, or output failures return `1`. Security findings alone do not currently fail CI.

## Interpreting results

### Versions and compatibility

“Latest” means the version selected by Go's `@latest` query **on the same module path**. A migration from `example.com/pkg` to `example.com/pkg/v2` is not discovered. Go's stable-release preference can also select a version below an installed prerelease.

Compatibility is a metadata-based estimate:

| Signal | Interpretation |
| --- | --- |
| Major version change | High risk of breaking API changes. |
| v0 or prerelease/pseudo-version transition | Compatibility is not assured; manual review is needed. |
| Higher target Go requirement | The project's declared Go baseline needs review. |
| Target appears in `exclude` | The project's exclusion rule must be reviewed. |
| Stable same-major update with a satisfied Go requirement | Lower estimated risk, not a guarantee. |
| Missing version or Go metadata | Unknown. |

The tool does not perform an API diff. Build/test trial results are separate evidence and do not erase the estimate.

### OSV security checks

OSV receives public module paths and versions, not source files. Effective `GOPRIVATE`, `GONOPROXY`, and `GONOSUMDB` patterns are read through `go env`; matching modules are skipped. Configure these settings for private modules. If privacy settings cannot be read, OSV queries are not sent.

Checks cover `go.mod` **require entries**. When resolution succeeds, the resolved version is queried; otherwise the declared version is used. Local or versioned replacements are marked as skipped. Standard-library vulnerabilities and transitive modules absent from `require` are outside this OSV check's scope.

The target version is queried separately. Advisory fix versions may refer to different release branches and are not automatically a recommended minimum safe upgrade. Different advisory sources may report the same underlying vulnerability under separate IDs. Successful queries are cached for the current run; pagination is completed before reporting results.

A version match does not prove exploitability. “No known record” is not a security guarantee. Network, HTTP, and decoding errors are reported as unavailable information, never as clean results.

### Priority and release age

The action list prioritizes security findings, retracted/deprecated dependencies, high compatibility risk, recent releases, and routine updates. The release-age threshold is an advisory warning: it neither blocks upgrades nor hides security findings, and an older release is not necessarily safe.

Summary dependency counts use unique module paths. The dependency list and security coverage counts refer to project-dependency records. Partial checks can make totals incomplete.

## Source vulnerability analysis

Install a `govulncheck` version compatible with your Go toolchain:

```sh
go install golang.org/x/vuln/cmd/govulncheck@latest
./gomodscan -govulncheck -verify-timeout 5m ~/projects/service
```

The tool runs `govulncheck -json -scan=symbol ./...` in a temporary copy. Only findings containing function call traces are displayed as reachable; module/package-only matches are not treated as calls. The Modules section shows advisory IDs, fixed versions, and traces from the vulnerable function toward the entry point.

This analysis can include standard-library and transitive dependency findings. Results depend on the current platform and build configuration; test files are not included in this invocation. A call path is not proof of exploitation.

Missing tools, incompatible source-analysis libraries, package-loading errors, malformed output, and timeouts are reported as unavailable. New Go releases may require an updated `govulncheck` even when its executable was built with a recent Go compiler. See the [official Go vulnerability documentation](https://go.dev/doc/security/vuln/).

## Upgrade trials

```sh
./gomodscan -try-upgrades -verify-workers 2 -verify-timeout 5m ~/projects/service

# Combine both verification features without separate OSV queries:
./gomodscan -govulncheck -try-upgrades -check-vulns=false ~/projects/service
```

For each module with upgrade candidates:

1. Copy the current project and run `go build ./...` and `go test -json -count=1 ./...`.
2. If the baseline fails, mark trials as blocked rather than blaming an upgrade.
3. For each candidate, create a fresh copy, run `go get module@target`, then build and test again.
4. Record command results in the HTML report and remove the temporary copy.

Candidates are tested individually, not as a combined upgrade. `go get` may also change transitive dependencies and the Go directive. Passing tests only cover the tests executed; zero successful test events do not establish behavior coverage. Logs are size-limited, with truncation identified in the report.

**A temporary copy is not a security sandbox.** Tests and build subprocesses run with your user permissions, environment, network access, and access to external services. Enable trials only for trusted projects whose tests are appropriate to run in your environment. Go caches and downloads are shared with the local environment.

The current implementation supports standalone modules. Workspaces, external/absolute local replacements, symbolic links, and special files are rejected rather than silently testing an incomplete copy. `.git` is excluded; ordinary files, including `testdata`, are copied. Commands use `GOWORK=off`, `GOFLAGS=-mod=mod`, and `GOTOOLCHAIN=auto`.

On Unix, verification timeouts terminate the command's process group, including test subprocesses. On other platforms, parent-command cancellation does not guarantee termination of every child process.

## Development

Production Go dependencies are limited to [`golang.org/x/mod`](https://pkg.go.dev/golang.org/x/mod) and [`golang.org/x/sync`](https://pkg.go.dev/golang.org/x/sync). `govulncheck` is an optional external executable.

```sh
go test -race ./...
go vet ./...
go build ./...
```

Tests use local fixtures and fake commands/HTTP servers; after Go dependencies are installed, unit tests do not require network access.

Generate a sample inventory containing a deliberately invalid module:

```sh
go run . -o sample-report.html testdata/tree
```

Optional DOM interaction tests use development-only `jsdom`, installed outside the repository:

```sh
npm install --prefix /tmp/gomodscan-ui-test --no-save --no-audit --no-fund jsdom@20.0.3
NODE_PATH=/tmp/gomodscan-ui-test/node_modules node scripts/test-report.cjs sample-report.html
```

These exercise filtering, sorting, pagination, navigation, detail expansion, and print-state restoration. They do not replace visual browser testing. The generated report itself has no JavaScript dependencies.

### Project layout

| File | Responsibility |
| --- | --- |
| `main.go` | CLI flags and orchestration. |
| `scanner.go` | Discovery, parsing, and concurrent Git metadata collection. |
| `updates.go` | Go version queries. |
| `security.go` | OSV querying, privacy rules, and per-run cache. |
| `insights.go` | Compatibility estimates and action priorities. |
| `reachability.go` | `govulncheck` integration. |
| `verification.go`, `checkprocess_*.go` | Temporary copies, build/test trials, and cancellation. |
| `report.go`, `template.html` | Exported data models and embedded HTML report. |
| `*_test.go`, `testdata/`, `scripts/` | Unit fixtures and optional interaction checks. |

Models have JSON tags for future integrations; a JSON output flag is not currently implemented.

## Contributing

Issues and pull requests are welcome. For bugs, include your Go version, OS/architecture, command flags, expected behavior, and a minimal reproducible example. Remove private module names, absolute paths, credentials, and sensitive test output before sharing reports or logs.

Keep changes focused, add regression coverage for behavior changes, and run the Go checks above. Preserve standalone HTML output, automatic template escaping, bounded concurrency, and explicit unavailable states. Do not report incomplete checks as successful security or compatibility verification.

## License

[MIT](LICENSE) © 2026 Yakut Özcan.
