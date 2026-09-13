# ChainWatch audit & fix plan

## Plan

- [x] Baseline: `npm run typecheck` + `npm test` — all 98 tests passed on arrival
- [x] Audit core runtime (engine, scorer, attribution, resolver, interceptors)
- [x] Audit static scanner + 6 rules
- [x] Audit baseline recorder + drift differ
- [x] Audit CLI commands, reporters, sync client
- [x] Audit GitHub Action, server API, dashboard, packaging
- [x] Fix critical bugs
- [x] Fix detection-evasion gaps
- [x] Fix medium/minor bugs
- [x] Wire GitHub Action drift + SARIF upload
- [x] Dashboard key management + WS reconnect
- [x] Packaging fixes (file: deps → devDeps, junk file)
- [x] Regression tests for fixed bugs
- [x] Docs: README config/threat model, CHANGELOG
- [x] Final verification: typecheck + tests + builds

## Bugs fixed

### Critical (features that silently didn't work)

- `watch --block` / `--block-on` never reached the child — policy is now built
  in the preload from `chainwatch.config.json` + `CHAINWATCH_BLOCK_ON` etc.
- `suspicious_publish` read `regMeta.times` but real npm returns `time` —
  recency check was dead in production. `makeDefaultFetcher` now maps it.
- `spawn('npm', ['publish'])` evaded self_propagation — args[1] is now joined
  into the checked command; `execFile`/`execFileSync` wrapped too.
- `watch --sync` sent an object `description` to a zod `z.string()` field →
  server 400 every time. Now serializes a human-readable string.
- `getFindingTrend` used `INTERVAL '${days} days'` inside a template literal —
  parameterized to `${days} * INTERVAL '1 day'` (dashboard Overview 500'd).
- `github.com` was in the network allowlist — the flagship threat (Shai-Hulud
  exfil to attacker repos) sailed through. Removed.

### Detection-evasion gaps

- Intercepted `fetch`, `WebSocket`, `tls.connect`, `dgram.send`, `http2.connect`,
  `dns.promises.*` — none were covered.
- `fs.promises`, `readdir`, `stat`/`access` probes — not wrapped before.
- `worker_threads` — fresh module registry was a full bypass; preload is now
  injected into worker `execArgv` (shared `intercept/worker.ts` used by both
  engine and recorder).
- pnpm/nested attribution — now matches LAST `node_modules` segment.
- Windows `\\?\` realpath prefix + case-insensitive compare — `file:` deps
  now attribute on Windows.
- `Error.stackTraceLimit` raised (50) — deep call chains no longer lose
  attribution.
- Credential patterns: bare `.env`, `.env.*` variants, case-insensitive.
- `install_script` signal (defined but never emitted) now fires on nested
  `npm/pnpm/yarn install`.

### Medium/minor

- Signal-killed children reported exit 0 — now conventional `128+signo`.
- Event tail mixed byte offset with char index — rewrote as byte-accurate
  `JsonlTail` with partial-line buffering.
- `baseline record --runs abc` → NaN → silently recorded 0 events. Validated.
- `dependency_confusion` read `.npmrc` from process.cwd — now from scanned
  project root (`context.projectDir`).
- Engine listener exceptions propagated into watched code — isolated.
- Repeated identical events flooded the log — dedupe + `occurrences` counter.
- WS server: one client disconnect unsubscribed the shared Redis channel for
  ALL workspace clients — now one subscription per channel with a socket set.
- `POST /workspaces` let anyone self-mint `tier: 'enterprise'` — tier now
  forced to `free` unless `CHAINWATCH_ALLOW_SELF_TIER=1`.
- `package.json` shipped `file:` fixture deps in `dependencies` — moved to
  devDependencies (npm publish tarball would have been uninstallable).
- `BaselineRecorder.install()` didn't set the module-global recorder →
  silently recorded nothing when called directly.
- `sync --since` was all-or-nothing on the scan timestamp — now validated +
  documented semantics.
- `pretty` reporter hardcoded `./node_modules` in the header; JSON reporter
  hardcoded version `0.2.0` — shared `src/version.ts`.
- SARIF `file.split(':')` corrupted `C:\...` paths — last-colon parsing.
- API key auth did a per-request table scan + N bcrypt compares — added
  indexed `key_sha256` lookup column (bcrypt still verifies), plus legacy
  fallback that backfills the digest.
- Added `DELETE /api/v1/api-keys/:id` (revocation) + dashboard key UI.
- Webhook/Slack alert URLs validated against private/internal hosts (SSRF) at
  creation and dispatch; all outbound fetches now have `AbortSignal.timeout`.
- Scanner: nested `node_modules` discovery, 8-wide rule pool, registry fetch
  timeout + `time` mapping, postinstall-network FP reduction (install-referenced
  files stay HIGH, unrelated network code → MEDIUM), wider obfuscation patterns.
- GitHub Action: `baseline-file`/`drift-threshold`/`upload-sarif` were parsed
  but never used — install command now runs under bundled
  `recorder-preload.mjs`, drift diffs → CW007 findings, SARIF uploads via
  code-scanning API (new `github-token` input).
- Dashboard: WS reconnect with exponential backoff; Settings → API key
  management (create/list/revoke).
- Housekeeping: deleted stray `{}}` file, dead `getApiKeyByHash`, duplicate
  `extractHost`, duplicate `uninstall()`.
- Windows exit crash (0xC0000409 libuv `UV_HANDLE_CLOSING` assert): registry
  fetcher moved off `fetch` to `https.request` (agent: false);
  `closeNetworkConnections()` destroys the undici dispatcher before
  post-fetch `process.exit` in scan/sync/watch/baseline commands.
- CI: test job added to the dogfood workflow (root + server tests).

## Regression tests added

- `test/regression/engine.test.ts` — listener isolation, dedupe
- `test/regression/interceptors.test.ts` — spawn/execFile arg joining,
  install_script, fetch interception
- `test/regression/resolver.test.ts` — pnpm/nested/scoped/Windows paths
- `test/regression/recorder-install.test.ts` — install() footgun + uninstall
- `test/action/sarif.test.ts` — Windows drive-letter paths (2 new cases)

## Review / results

- Root: `tsc --noEmit` clean; 98 → 119 tests pass (21 new regression tests);
  `npm run build` clean; `npm run demo` catches the worm end-to-end.
- Server: `tsc --noEmit` clean; 18 tests pass; `npm run build` clean.
- Dashboard: `tsc --noEmit` clean.
- Action: `tsc -p action/tsconfig.json` clean; `build:action` emits both
  `dist/index.js` and `dist/recorder-preload.mjs`; bundled preload verified
  end-to-end (records `{HOME}/.npmrc` read attributed to the package).

## Tracked risks (accepted, not blocking)

1. **In-process threat model** — hostile packages can still patch over
   wrappers or escape via `vm` contexts. README documents it;
   `--experimental-permission` is the real answer once Node stabilizes it.
   Never present ChainWatch as a full sandbox.
2. **Sync is snapshot-based** — `last-scan.json` only. Real event history
   (replay, audit trails) needs a JSONL/SQLite event store. Low priority
   unless a customer asks.
3. **No Postgres integration tests** — server tests are unit-only. Revisit
   if subtle query/migration bugs start slipping through mocks.
