# Lessons

Patterns worth remembering for this codebase — things that bit me or that the
audit proved easy to get wrong.

## Testing interceptors

- **ESM builtin namespaces are snapshots.** `await import('node:child_process')`
  captures exports the first time the module is imported — if vitest (or any
  earlier module) imported it before `engine.install()`, you get unpatched
  functions and the test silently tests nothing. Use `createRequire` in tests
  that verify wrapper behavior; require returns the live patched object.
- Test blocking paths with a `blockThreshold: 0` policy so wrappers throw
  `ChainWatchBlockError` *before* the real syscall — no real `npm publish`
  or network call ever executes.

## Runtime interception (this codebase)

- Anything that gets a fresh module registry bypasses in-process patching:
  `worker_threads`, and (still open) `vm` contexts. Workers are handled by
  injecting the preload into `execArgv`.
- Node internals capture references at module load — patching `net.connect`
  does NOT catch `tls.connect`'s internal use. Wrap each public entry point.
- `spawn`/`execFile` take `args` as `args[1]` — regexing only `args[0]` misses
  every array-form spawn, which is the common form.

## Windows specifics

- `fs.realpathSync` returns `\\?\` extended paths; stack frames don't. Strip
  the prefix before prefix-matching.
- Drive-letter colons break `path.split(':')` — always split on the LAST colon
  for `file:line` parsing.
- Paths compare case-insensitively on Windows (`/i` on patterns, lowercase
  compare on prefix matching).

## npm registry

- Publish timestamps live in `time`, not `times`. Maintainers are
  `{name, email}` objects. Normalize in the fetcher, keep the internal type
  honest.

## Windows + undici

- **`process.exit()` after `fetch()` can abort with `0xC0000409`** — a libuv
  `UV_HANDLE_CLOSING` assert in `src\win\async.c`. The undici global dispatcher
  keeps a keep-alive socket that is mid-close at exit. Fix: prefer
  `https.request` (with `agent: false`) for one-shot CLI requests, and call
  `closeNetworkConnections()` (destroys the dispatcher via the documented
  `Symbol.for('undici.globalDispatcher.1')` key) before any post-fetch
  `process.exit`.
- CLI tests spawn `node dist/cli/index.js` — the BUILT bundle. A green test
  run against a stale dist proves nothing; rebuild before trusting results.

## Process / housekeeping

- Zero-byte junk files (`{}}`) can be committed on Windows where quoting is
  weird — `rm` may not match the name; remove via Node `fs.rmSync` with the
  exact `readdirSync` name.
- `file:` dev fixtures must live in `devDependencies` — in `dependencies` they
  produce an uninstallable published tarball.
- postgres.js tagged templates: `${x} * INTERVAL '1 day'` parameterizes;
  `INTERVAL '${x} days'` embeds the bind inside a literal and Postgres rejects.
