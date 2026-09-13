# ChainWatch

npm supply-chain runtime watchdog. Behavioral anomaly detection for installed
packages — watches what packages **do**, not what they look like. Built to catch
the 2026 worm wave (Shai-Hulud, ChainDrop) that ran with zero CVEs assigned
during active exploitation.

## Why

Signature scanners look at what a package **is**. ChainWatch looks at what a
package **does**. A package reading `~/.npmrc` isn't necessarily bad. A package
making a network call isn't necessarily bad. But **read credentials → enumerate
tokens → POST to an unknown host**, in that order, is unambiguously a worm.
That sequence is exactly what Shai-Hulud and ChainDrop do, and it's exactly what
signature scanners miss because none of the individual steps trips a signature.

## Install

```bash
npm install -g chainwatch
```

Or use without installing:

```bash
npx chainwatch scan
npx chainwatch watch -- node server.js
```

## Commands

### `chainwatch scan [dir]`

Statically scan `node_modules` for supply-chain risks. Six detection rules:

| Rule | What it catches | Severity |
|------|----------------|----------|
| `postinstall_network` | Install scripts that make network calls | HIGH |
| `postinstall_shell` | Install scripts that spawn shells or run `npm publish` | CRITICAL |
| `credential_file_access` | Source code that reads `~/.npmrc`, `.env`, SSH keys, AWS creds | HIGH |
| `obfuscation_score` | Hex-encoded eval, `Function()` constructor, nested `atob()` | MEDIUM–HIGH |
| `suspicious_publish` | Version published < 48hr ago by a new maintainer; typosquat names | MEDIUM–CRITICAL |
| `dependency_confusion` | Scoped package resolved from public registry instead of private | CRITICAL |

```bash
# Scan current project
chainwatch scan

# JSON output for CI/tooling
chainwatch scan --output json

# SARIF output for GitHub Security tab
chainwatch scan --output sarif

# Fail CI on HIGH+ findings
chainwatch scan --fail-on high
```

**Options:**
- `-o, --output <fmt>` — `pretty` (default) | `json` | `sarif`
- `-s, --severity <lvl>` — minimum severity to show (default: `medium`)
- `--fail-on <lvl>` — exit code 1 if any finding >= this severity (default: `high`)
- `--no-color` — disable color output (for CI)
- `-q, --quiet` — only print findings, no progress

### `chainwatch watch -- <command>`

Run any command under live runtime monitoring. Reuses the Phase 1 interceptor —
wraps Node's core modules (`fs`, `net`, `http`, `https`, `dns`, `child_process`)
and attributes every suspicious call to the package that made it via call-stack
resolution.

```bash
# Watch a server
chainwatch watch -- node server.js

# Watch tests
chainwatch watch -- npm test

# Block on HIGH+ (default: warn only, block on CRITICAL)
chainwatch watch --block -- node server.js

# Log events to a file
chainwatch watch --log events.jsonl -- node server.js
```

**Options:**
- `--block` — block on HIGH+ (default: warn only)
- `--block-on <lvl>` — block threshold (default: `critical`)
- `-o, --output <fmt>` — `pretty` (default) | `json`
- `--log <file>` — append events to a JSONL log file
- `--drift` — enable drift detection (requires baseline, see below)
- `--baseline <file>` — baseline file to compare against (default: `.chainwatch/baseline.jsonl`)
- `--drift-threshold <n>` — drift score to trigger alert (0–100, default: 40)
- `--block-on-drift` — kill the process if drift score exceeds threshold
- `--trust <pkgs>` — comma-separated packages that are logged but never blocked
- `--allow <hosts>` — comma-separated extra allowlist hosts
- `--sync` — push events to ChainWatch Cloud after the run

### Configuration file

`chainwatch.config.json` (or `.chainwatchrc.json`) in the project root — all
keys optional, CLI flags take precedence:

```json
{
  "trustedPackages": ["esbuild", "my-internal-tool"],
  "networkAllowlist": ["npm.corp.example.com"],
  "credentialPatterns": ["\\.pem$", "id_ed25519"],
  "blockOn": "high",
  "flagThreshold": 50,
  "blockThreshold": 80,
  "chainBlockThreshold": 75
}
```

### `chainwatch baseline record`

Record what packages do during a known-good run. This creates a behavioral
baseline that `watch --drift` compares against to detect deviations.

```bash
# Record a baseline from your test suite
chainwatch baseline record -- npm test

# Record multiple runs for a richer baseline
chainwatch baseline record --runs 3 -- npm run dev

# Merge into an existing baseline
chainwatch baseline record --merge -- node scripts/build.js
```

### `chainwatch baseline show`

Inspect what's in the recorded baseline.

```bash
chainwatch baseline show
chainwatch baseline show --pkg vite
chainwatch baseline show --signal network_out
chainwatch baseline show --json
```

### Drift detection workflow

```bash
# 1. Record a baseline from a known-good run
chainwatch baseline record -- npm test

# 2. Later, run with drift detection to catch deviations
chainwatch watch --drift -- npm test

# 3. Block if drift exceeds threshold
chainwatch watch --drift --block-on-drift -- npm test
```

Drift detection catches slow-burn attacks that evade the chain scorer: a
compromised package that does one suspicious thing per run, across many runs.
No single run trips the chain scorer, but the differ sees that the behavior is
new relative to the baseline.

**Drift scoring:**

| New behavior | Points |
|-------------|--------|
| `network_out` to a raw IP (not a hostname) | +50 |
| `network_out` to a new hostname | +30 |
| `fs_read` of a credential file | +40 |
| `child_process` spawn not in baseline | +35 |
| `dns_lookup` of a new domain | +25 |
| `fs_write` outside CWD | +30 |
| Any signal right after credential read | +20 (chain bonus) |

Score >= 40 = warn, >= 70 = high, >= 85 = critical. Paths are normalized
(`{HOME}`, `{CWD}`, `{TMP}`) so baselines are portable across machines.

## GitHub Action

ChainWatch ships as a GitHub Action that runs automatically on every push and
pull request. Findings appear as PR annotations and in the repo's Security tab
via SARIF upload.

### Quick start

Add this workflow to `.github/workflows/chainwatch.yml`:

```yaml
name: Supply Chain Scan

on:
  push:
    branches: [main]
    paths: ['package.json', 'package-lock.json']
  pull_request:
    paths: ['package.json', 'package-lock.json']

permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  chainwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
      - run: npm ci
      - name: ChainWatch supply chain scan
        uses: quantum-fabric-industries/chainwatch@v1
        with:
          severity: medium
          fail-on: high
          upload-sarif: true
      - name: Upload SARIF to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: chainwatch-results.sarif
```

### With baseline drift detection

The baseline is cached by lockfile hash — when `package-lock.json` changes
(new package added), the cache misses and a fresh baseline is recorded.
No manual baseline management required.

```yaml
      - name: Restore baseline
        uses: actions/cache@v4
        with:
          path: .chainwatch/baseline.jsonl
          key: chainwatch-baseline-${{ runner.os }}-${{ hashFiles('package-lock.json') }}
          restore-keys: chainwatch-baseline-${{ runner.os }}-

      - name: ChainWatch scan + drift detection
        uses: quantum-fabric-industries/chainwatch@v1
        with:
          severity: medium
          fail-on: high
          baseline-file: .chainwatch/baseline.jsonl
          drift-threshold: 40
          upload-sarif: true

      - name: Update baseline cache
        uses: actions/cache/save@v4
        if: github.ref == 'refs/heads/main'
        with:
          path: .chainwatch/baseline.jsonl
          key: chainwatch-baseline-${{ runner.os }}-${{ hashFiles('package-lock.json') }}
```

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-dir` | `./node_modules` | Directory to scan |
| `severity` | `medium` | Minimum severity to report |
| `fail-on` | `high` | Exit code 1 if any finding at this severity or higher |
| `baseline-file` | `''` | Path to baseline JSONL for drift detection (optional) |
| `drift-threshold` | `40` | Drift score to trigger a finding (0–100) |
| `sarif-output` | `chainwatch-results.sarif` | Write SARIF output to this file |
| `upload-sarif` | `true` | Upload SARIF to GitHub Security tab |
| `install-command` | `npm ci` | Command to run before scanning |

### Action outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high findings |
| `sarif-file` | Path to the SARIF output file |

### SARIF rule IDs

| ID | Rule | Default level |
|----|------|---------------|
| CW001 | PostinstallNetwork | error |
| CW002 | PostinstallShell | error |
| CW003 | CredentialFileAccess | error |
| CW004 | ObfuscationScore | warning |
| CW005 | SuspiciousPublish | warning |
| CW006 | DependencyConfusion | error |
| CW007 | BehavioralDrift | warning |

## Cloud Sync + Team Dashboard

ChainWatch Cloud adds team-wide visibility: all repos' scan results in one
dashboard, real-time event feed, Slack alerts, and shared baselines across
machines. The free tier (CLI + GitHub Action) is fully functional without an
account — cloud features require a Team plan.

### Setup

```bash
# 1. Get an API key (creates a workspace)
curl -X POST https://api.chainwatch.dev/api/v1/workspaces \
  -H 'Content-Type: application/json' \
  -d '{"name":"My Team","slug":"my-team","tier":"team"}'

# 2. Set the API key
export CHAINWATCH_API_KEY=cw_<workspace>_<key>

# 3. Scan with cloud sync
chainwatch scan --sync

# 4. Open the dashboard
open https://dashboard.chainwatch.dev
```

### CLI sync commands

```bash
# Push findings to cloud after a scan
chainwatch scan --sync

# Push events after a watch session
chainwatch watch --sync -- npm test

# Record baseline and upload to team
chainwatch baseline record --sync -- npm test

# Pull team baseline for current repo
chainwatch baseline pull

# Manually sync previously saved findings
chainwatch sync --repo org/repo-name
```

The `--sync` flag silently skips if `CHAINWATCH_API_KEY` is not set, so teams
without cloud sync aren't affected by the flag being present.

### Dashboard

The dashboard (React + Tailwind) provides:

- **Overview** — summary cards, findings trend chart (30 days), recent findings
- **Repo Detail** — full finding history, per-signal breakdown, baseline status
- **Live Event Feed** — real-time WebSocket stream of findings as scans complete
- **Settings** — API key management, Slack webhook config, alert rules

### Slack alerts

Configure Slack alerts from the dashboard Settings page or via the API:

```bash
# Create a Slack alert config
curl -X POST https://api.chainwatch.dev/api/v1/alerts \
  -H "Authorization: Bearer $CHAINWATCH_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"type":"slack","config":{"url":"https://hooks.slack.com/services/..."},"min_severity":"high"}'

# Test the alert
curl -X POST https://api.chainwatch.dev/api/v1/alerts/test \
  -H "Authorization: Bearer $CHAINWATCH_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"type":"slack","config":{"url":"https://hooks.slack.com/services/..."}}'
```

### Self-hosting

The server runs with Docker Compose (PostgreSQL + Redis):

```bash
docker compose up -d          # start postgres + redis
cd server && npm install
npm run db:migrate            # create tables
npm run db:seed               # create dev workspace + API key
npm run dev                   # start API server on :3000
```

The dashboard dev server proxies API requests to localhost:3000:

```bash
cd dashboard && npm install
npm run dev                   # start dashboard on :5173
```

### Freemium tier

| Feature | Free | Team ($29/mo) | Enterprise |
|---------|------|---------------|------------|
| CLI scan + watch | unlimited | unlimited | unlimited |
| GitHub Action | unlimited | unlimited | unlimited |
| SARIF + GitHub Security tab | yes | yes | yes |
| Baseline (local) | yes | yes | yes |
| Cloud event sync | no | yes | yes |
| Team dashboard | no | yes (10 repos) | unlimited |
| Team baseline sharing | no | yes | yes |
| Slack / webhook alerts | no | yes | yes |
| Live event feed | no | yes | yes |

## How it works

### Runtime interceptor (watch mode)

ChainWatch wraps `fs` (+ `fs.promises`, `readdir`, `stat`), `net`, `tls`,
`http`, `https`, `http2`, `dns` (+ `dns.promises`), `dgram`, `child_process`,
the `fetch`/`WebSocket` globals, and `worker_threads` (workers get the preload
injected — a fresh module registry can't bypass monitoring).

ChainWatch wraps Node's module loader and core modules at startup. When a
package calls `fs.readFileSync('~/.npmrc')`, ChainWatch:

1. Walks the call stack to find which package made the call (attribution)
2. Resolves symlinks so `file:` deps, pnpm, and workspace links attribute correctly
3. Emits a `credential_access` signal with the package name
4. Feeds the signal to the chain scorer

The chain scorer keeps a per-package sliding window of recent signals. When it
sees the sequence `credential_access → self_propagation → network_exfil`, it
adds chain bonuses that push the score to 100 and triggers a block — **before**
the exfiltration completes.

### Static scanner (scan mode)

The scanner discovers all packages in `node_modules` (including nested
`node_modules` and pnpm's `.pnpm` layout), then runs each detection rule
against each package. Rules are independent functions — each can be tested in
isolation. The scanner produces findings sorted by severity.

### Threat model

ChainWatch runs **in the same process** as the code it watches — that's what
makes behavioral attribution cheap and precise, but it means a sufficiently
hostile package can patch over the wrappers or run code in a `vm` context the
interceptors can't see. Treat `watch` as a strong tripwire, not a sandbox. For
high-assurance isolation, run under `--experimental-permission` or a container.

## Development

```bash
git clone <repo>
cd chainwatch
npm install

# Run the live worm-catch demo
npm run demo

# Run tests
npm test

# Build
npm run build

# Type check
npm run typecheck
```

## Project structure

```
src/
  events.ts          — event schema
  attribution.ts     — call-stack package attribution
  resolver.ts        — symlink-aware path-to-package resolver
  policy.ts          — default detection policy
  scorer.ts          — chain scorer (the heart)
  engine.ts          — wires interceptors → scorer → event log
  intercept/         — core module wrappers (fs, net, child_process)
  scan/              — static scanner + detection rules
    scanner.ts
    rules/
  baseline/          — Phase 3: baseline recording + drift detection
    recorder.ts
    store.ts
    differ.ts
    summarizer.ts
  sync/              — Phase 5: cloud sync client
    client.ts
  reporter/          — pretty, json, sarif output
  cli/               — commander-based CLI
    commands/        — scan, watch, baseline, sync
  preload.ts         — --import preload for watch mode
  recorder-preload.ts — --import preload for baseline recording
action/
  action.yml         — GitHub Action definition (shield/red branding)
  src/               — Action entry point (scan + SARIF + summary)
  dist/index.js      — esbuild bundle (committed, GitHub runs this directly)
server/              — Phase 5: ChainWatch Cloud API
  src/
    api/             — events, baselines, dashboard, alerts, auth
    db/              — schema.sql, queries.ts, migrate.ts, seed.ts
    realtime/        — WebSocket server + Redis pub/sub
  test/              — server unit tests
dashboard/           — Phase 5: React + Tailwind dashboard
  src/
    pages/           — Overview, RepoDetail, EventFeed, Settings
    components/      — FindingCard, TrendChart
    api.ts           — API client + WebSocket
.github/workflows/   — dogfood + example workflows
test/
  fixtures/          — fake packages for testing (including fake-worm)
```

## License

MIT
