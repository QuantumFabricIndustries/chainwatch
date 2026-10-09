# Changelog

All notable changes to ChainWatch are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — tensorlake hostage-token worm

- `hostage_token` scan rule (SARIF CW008, critical): known-compromised
  `tensorlake@0.5.144`, `gh-token-monitor` / C2 / exfil-repo indicators, any
  file pairing a GitHub token check with a home-directory wipe, and install
  scripts that fetch the Bun runtime (high). Findings say to remove the
  monitor before revoking; the pretty report opens with a stop banner.
- `chainwatch hostage-check`: finds the wipe-on-revoke monitor on Linux,
  macOS and Windows plus worm-committed `.claude/` and `.vscode/` files, and
  prints the safe cleanup order.
- `~/.config/gh/hosts.yml` is now a credential path in both watch mode and
  `credential_file_access`.

### Fixed — CI

- Scanner fixtures under `test/fixtures/node_modules` are committed (they were
  swallowed by the `node_modules/` ignore rule).
- Action bundle is `action/dist/index.cjs` so Node loads it under
  `"type": "module"`; root `action.yml` YAML repaired; new `allow-packages`
  input; `install-command: ''` skips the install.

### Added — detection coverage

- `credential_file_access` now flags stealer-shopping-list paths, not just
  dotfile creds: Discord token stores (`Local Storage/leveldb`), Chromium
  credential databases (`Login Data`, `Web Data`, `Local State`,
  `Network/Cookies`), Firefox stores (`logins.json`, `key4.db`, `cert9.db`),
  crypto wallets (`wallet.dat`, Electrum, Exodus, MetaMask extension vault),
  FileZilla/WinSCP saved credentials, and Telegram `tdata` sessions. Targets
  RAT/stealer campaigns like MALFEX that harvest these stores on install.
- MALFEX regression fixtures (`fake-malfex-stealer`, `fake-malfex-rat`)
  replaying the campaign's documented shapes: modular credential harvesters,
  HTTPS exfil to a C2, scheduled-task persistence, and a beacon-and-eval RAT
  loop.

### Fixed — runtime interception

- `watch --block` / `--block-on` now actually reach the watched process — the
  preload builds its policy from `chainwatch.config.json` and env vars
  (`CHAINWATCH_BLOCK_ON`, `CHAINWATCH_TRUSTED`, `CHAINWATCH_ALLOW_HOSTS`).
- `spawn('npm', ['publish'])` and `execFile` no longer evade self-propagation
  detection; nested `npm/pnpm/yarn install` now fires `install_script`.
- Interception now covers `fetch`, `WebSocket`, `tls.connect`, `dgram.send`,
  `http2.connect`, `dns.promises.*`, `fs.promises`, `readdir`, `stat`/`access`.
- `worker_threads` no longer bypasses monitoring — the preload is injected
  into worker `execArgv`.
- Attribution uses the LAST `node_modules` segment (pnpm `.pnpm/` layout and
  nested deps), strips Windows `\\?\` realpath prefixes, compares
  case-insensitively on win32, and raises `stackTraceLimit` for deep chains.
- Credential patterns catch bare `.env`, `.env.*` variants, and are
  case-insensitive; `github.com` removed from the network allowlist
  (Shai-Hulud exfiltrated *to* GitHub).
- Signal-killed children report real exit codes (`128+signo`), the event tail
  no longer corrupts on multi-byte characters, engine listeners can't throw
  into watched code, and repeated identical events dedupe with an
  `occurrences` counter.

### Fixed — scanner + CLI

- `suspicious_publish` reads the real npm `time` field — the <48h recency
  check works against production registry data; typosquat messages report the
  actual Levenshtein distance.
- `dependency_confusion` reads `.npmrc` from the scanned project root.
- `postinstall_network` keeps HIGH for files referenced by install scripts
  and downgrades unrelated network code to MEDIUM.
- Nested `node_modules` are scanned; rules run in an 8-wide pool; registry
  fetches have a 10s timeout.
- `sync --since` validates its argument; `--sync` payloads serialize
  descriptions as strings (server no longer 400s); chain score comes from
  `detail.chainScore`; `--runs` rejects non-numeric input.
- SARIF handles Windows drive-letter paths; reporters share `src/version.ts`
  and the pretty header shows the actual scanned directory.

### Fixed — server + dashboard

- Dashboard trend query no longer 500s (parameterized interval).
- API key auth uses an indexed `key_sha256` lookup (bcrypt still verifies) —
  no more per-request table scan. `DELETE /api/v1/api-keys/:id` revokes keys;
  the Settings page can create/list/revoke them.
- WebSocket fan-out no longer drops every workspace client when one socket
  closes; dashboard auto-reconnects with backoff.
- Workspace creation can't self-mint `tier: 'enterprise'` (opt-in env var for
  dev). Alert webhook URLs are SSRF-checked; outbound fetches have timeouts.
- GitHub Action: `baseline-file`/`drift-threshold`/`upload-sarif` inputs are
  wired — the install command runs under a bundled recorder preload and drift
  becomes CW007 findings; SARIF uploads to code scanning via `github-token`.
- `file:` test fixtures moved to `devDependencies` (published tarball was
  uninstallable); stray `{}}` file removed.

## [1.0.0] — 2026-08-13

### Added — Phase 1: Runtime Interceptor
- Core interceptor wrapping `fs`, `net`, `http`, `https`, `dns`, `child_process`
- Call-stack package attribution with symlink-aware path resolution
- Chain scorer detecting credential_access → self_propagation → network_exfil sequences
- Live worm-catch demo with simulated Shai-Hulud attack chain
- Policy engine with configurable signal scores and block thresholds

### Added — Phase 2: Static Scanner + CLI
- `chainwatch scan` — static analysis of node_modules with 6 detection rules
- `chainwatch watch -- <cmd>` — live runtime monitoring via `--import` preload
- Detection rules: postinstall_network, postinstall_shell, credential_file_access,
  obfuscation_score, suspicious_publish, dependency_confusion
- Output formats: pretty (terminal), JSON, SARIF
- `--sarif-output <file>` flag for CI integration

### Added — Phase 3: Baseline + Drift Detection
- `chainwatch baseline record -- <cmd>` — records behavioral baseline
- `chainwatch baseline show` — inspect recorded baseline
- `chainwatch baseline clear` — delete baseline file
- `chainwatch baseline pull` — download team baseline from cloud
- `chainwatch watch --drift -- <cmd>` — compare current run to baseline
- `--block-on-drift` — kill process if drift exceeds threshold
- Path normalization with `{HOME}`, `{CWD}`, `{TMP}` tokens for portable baselines
- Drift scorer: raw IP network call (+50), credential read (+40), chain bonus (+20)

### Added — Phase 4: GitHub Action + CI/CD
- GitHub Action (`action/action.yml`) with node20 runtime
- SARIF 2.1.0 output with 7 rule IDs (CW001–CW007)
- `action/dist/index.js` — esbuild-bundled single file (committed)
- Dogfood workflow (`.github/workflows/chainwatch-ci.yml`)
- Example workflow with baseline drift detection in CI
- GitHub step summary with findings table

### Added — Phase 5: Cloud Sync + Dashboard + Publish
- `chainwatch sync` — push findings to ChainWatch Cloud API
- `--sync` flag on scan, watch, and baseline commands
- `chainwatch baseline pull` — download team baseline from cloud
- `CHAINWATCH_API_KEY` env var support throughout
- Fastify API server with PostgreSQL + Redis
- API endpoints: events, baselines, dashboard, alerts, api-keys
- WebSocket server for real-time live event feed
- Slack + webhook alert dispatch with HMAC signing
- React + Tailwind dashboard with Overview, RepoDetail, EventFeed, Settings pages
- Recharts trend chart for findings over time
- Freemium tier gate (free: full scanner + CI; team: dashboard + cloud sync)
- npm publish config with `files`, `publishConfig`, keywords
- GitHub Action branding (shield icon, red color)

### Security
- API keys stored as bcrypt hashes (never raw)
- HMAC-SHA256 webhook signing
- Freemium gate blocks cloud features without a team plan

## [0.1.0] — 2026-08-01

Initial prototype with basic interceptor and chain scorer.
