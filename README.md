# PRS v1.5.0
  <p>
    <a href="https://github.com/MOYARU/prs/releases">
      <img src="https://img.shields.io/github/v/release/MOYARU/prs?color=5865F2" alt="Release">
    </a>
    <a href="https://github.com/MOYARU/prs/stargazers">
      <img src="https://img.shields.io/github/stars/MOYARU/prs?style=social" alt="Stars">
    </a>
    <img src="https://img.shields.io/github/go-mod/go-version/MOYARU/prs?color=00ADD8" alt="Go">
    <img src="https://img.shields.io/github/license/MOYARU/prs?color=green" alt="MIT">
  </p>
</p>

## Overview

PRS is a CLI-based scanner focused on safe assessment of web targets.
It combines crawling, passive checks, optional active checks, and report export (JSON/HTML).

Core goals:
- Useful findings with clear evidence
- Conservative defaults for safer operation
- Fast workflow for security testing in real environments

## Features

- Crawler with scope discovery and form extraction
- Passive and active scan modes
- Security checks across:
  - TLS and transport security
  - Security headers
  - Auth/session and cookie hardening
  - Input handling and injection patterns
  - API-related checks
  - Information leakage and web content exposure
- Interactive mode with built-in tools:
  - `scan`
  - `port` (simple port scanner with service names)
  - `repeater`
  - `fuzz`
- Report outputs:
  - Console summary
  - JSON report
  - HTML report

## Installation

### Requirements
- Go 1.21+ (or version compatible with `go.mod`)
- Windows/macOS/Linux terminal

### Install with `go install`
```bash
go install github.com/MOYARU/prs@latest
```

If the `prs` command is not found, add your Go bin path to `PATH`.

- Windows (PowerShell): `"$env:USER\go\bin"`
- macOS/Linux: `"$HOME/go/bin"`

Then restart your terminal and run:

```bash
prs
```

### Build in Arch Linux
```
yay -S prs-scan

prs-scan
```


### Build from source (optional)
```bash
git clone https://github.com/MOYARU/prs.git
cd prs
go build -o prs
```

### Makefile (optional)
```bash
make deps
make
make run
```

## Quick Start

### Basic scan
```bash
prs https://example.com
```

### Active scan
```bash
prs https://example.com --active
```

### Crawl depth and delay

```bash
prs https://example.com --depth 3 --delay 300
```

### JSON report
```bash
prs https://example.com --json
```

## CLI Flags

- `--active` Enable active checks
- `--respect-robots` Respect `robots.txt` disallow rules during crawl
- `--depth` Crawl depth (default: `2`)
- `--json` Save JSON report
- `--delay` Delay between requests in milliseconds

## `.prs.yaml` Policy

PRS supports runtime policy tuning through `.prs.yaml`:

- `max_concurrency` Worker concurrency cap
- `request_budget` Global outbound request budget (`0` = auto)
- `active_cross_domain` Allow active checks outside root domain boundary
- `passive_profile` Passive mode sensitivity profile:
  - `strict` Lower-noise passive checks only
  - `balanced` Default profile
  - `aggressive` Enables all passive indicators/signals

## Interactive Mode

Run without target:
```bash
prs
```

Available commands:
- `scan <target_url> [--active] [--respect-robots] [--depth N] [--json] [--delay MS]`
- `port <host> [start-end]`
- `repeater <METHOD> <url> [body]`
- `fuzz <url_with_FUZZ> <wordlist_path>`
- `help`
- `clear` / `cls`
- `exit` / `quit`

Examples:
```bash
port 127.0.0.1
port 127.0.0.1 1-10000
```

## Output and Severity

- Findings include severity, confidence, evidence quality score, message, fix guidance, and evidence.
- Final scan output includes elapsed time, for example:
  - `Scan completed in 4.87s`
- Some severities are centrally adjusted via:
  - `internal/report/severity_policy.go`

## Project Structure

- `cmd/` CLI entrypoint
- `internal/app/` scan runtime, interactive mode, output
- `internal/crawler/` URL discovery and parsing
- `internal/checks/` security checks by category
- `internal/report/` finding model and severity policy
- `internal/messages/` UI message catalog

## Ethical Use

Use PRS only on systems you own or have explicit permission to test.
Do not scan unauthorized targets.

## License

MIT License

