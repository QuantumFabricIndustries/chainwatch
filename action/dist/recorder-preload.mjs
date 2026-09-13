// src/recorder-preload.ts
import * as fs2 from "node:fs";
import * as path3 from "node:path";

// src/baseline/recorder.ts
import { createRequire as createRequire2 } from "node:module";

// src/attribution.ts
import { fileURLToPath } from "node:url";
import * as path2 from "node:path";

// src/resolver.ts
import * as fs from "node:fs";
import * as path from "node:path";
function stripUncPrefix(p) {
  return p.startsWith("\\\\?\\") ? p.slice(4) : p;
}
function packageNameFromPath(filePath) {
  const parts = filePath.split(/[\\/]node_modules[\\/]/i);
  if (parts.length < 2) return null;
  const last = parts[parts.length - 1];
  const m = /^(?:@([^\\/]+)[\\/])?([^\\/]+)/.exec(last);
  if (!m) return null;
  const scope = m[1];
  const name = m[2] ?? "";
  if (name.startsWith(".")) return null;
  return scope ? `@${scope}/${name}` : name;
}
var PackageResolver = class {
  /** Sorted by path length descending so longest prefix wins. */
  entries = [];
  nodeModulesPath;
  /** filePath → package name memo; hot path during recording. */
  cache = /* @__PURE__ */ new Map();
  /** Windows paths are case-insensitive — compare accordingly. */
  caseInsensitive = process.platform === "win32";
  constructor(cwd = process.cwd()) {
    this.nodeModulesPath = path.join(cwd, "node_modules");
  }
  /** Scan node_modules (incl. nested) and build the path map. Once at startup. */
  scan() {
    this.entries = [];
    this.cache.clear();
    if (!fs.existsSync(this.nodeModulesPath)) return;
    const visited = /* @__PURE__ */ new Set();
    const scanDir = (dir, depth, scope) => {
      if (depth > 6) return;
      let entries;
      try {
        entries = fs.readdirSync(dir);
      } catch {
        return;
      }
      for (const entry of entries) {
        if (entry.startsWith(".")) continue;
        const pkgDir = path.join(dir, entry);
        let stat;
        try {
          stat = fs.lstatSync(pkgDir);
        } catch {
          continue;
        }
        if (!stat.isDirectory() && !stat.isSymbolicLink()) continue;
        if (entry.startsWith("@") && !scope) {
          scanDir(pkgDir, depth, entry);
          continue;
        }
        const pkgJsonPath = path.join(pkgDir, "package.json");
        let name = scope ? `${scope}/${entry}` : entry;
        try {
          const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
          if (pkg.name) name = pkg.name;
        } catch {
        }
        let realPath;
        try {
          realPath = stripUncPrefix(fs.realpathSync(pkgDir));
        } catch {
          realPath = pkgDir;
        }
        this.entries.push({ realPath: realPath + path.sep, name });
        if (visited.has(realPath)) continue;
        visited.add(realPath);
        const nested = path.join(pkgDir, "node_modules");
        try {
          if (fs.statSync(nested).isDirectory()) scanDir(nested, depth + 1);
        } catch {
        }
      }
    };
    scanDir(this.nodeModulesPath, 0);
    this.entries.sort((a, b) => b.realPath.length - a.realPath.length);
  }
  /**
   * Resolve a file path to its package name.
   * Returns null if the file is not inside any known package.
   */
  resolve(filePath) {
    if (!filePath) return null;
    const cached = this.cache.get(filePath);
    if (cached !== void 0) return cached;
    const result = this.resolveUncached(stripUncPrefix(filePath));
    if (this.cache.size > 1e4) this.cache.clear();
    this.cache.set(filePath, result);
    return result;
  }
  resolveUncached(filePath) {
    const fast = packageNameFromPath(filePath);
    if (fast) return fast;
    const normalized = filePath.replace(/\//g, path.sep);
    const cmp = this.caseInsensitive ? normalized.toLowerCase() : normalized;
    for (const entry of this.entries) {
      const target = this.caseInsensitive ? entry.realPath.toLowerCase() : entry.realPath;
      if (cmp.startsWith(target)) {
        return entry.name;
      }
    }
    return null;
  }
};

// src/attribution.ts
var SELF_DIR = path2.dirname(fileURLToPath(import.meta.url));
var SELF_RE = /[\\/]node_modules[\\/]chainwatch[\\/]/;
if (Error.stackTraceLimit < 50) Error.stackTraceLimit = 50;
function captureCallSites() {
  const oldPrepare = Error.prepareStackTrace;
  Error.prepareStackTrace = (_err, sites2) => sites2;
  const err = new Error();
  const sites = err.stack;
  Error.prepareStackTrace = oldPrepare;
  return sites ?? [];
}
function isSelfFile(file) {
  const f = file.replace(/\//g, path2.sep);
  return f.startsWith(SELF_DIR + path2.sep) || SELF_RE.test(file);
}
function attributeCall(resolver) {
  const sites = captureCallSites();
  let entryFile = "";
  for (const site of sites) {
    const file = site.getFileName?.() ?? "";
    if (!file) continue;
    if (file.startsWith("node:") || file.includes("internal/")) continue;
    if (isSelfFile(file)) continue;
    if (!entryFile) entryFile = file;
    if (resolver) {
      const pkg2 = resolver.resolve(file);
      if (pkg2) {
        return { package: pkg2, file, stack: serialize(sites) };
      }
    }
    const pkg = packageNameFromPath(file);
    if (pkg) {
      return { package: pkg, file, stack: serialize(sites) };
    }
  }
  return {
    package: entryFile ? "<entry>" : "<unknown>",
    file: entryFile,
    stack: serialize(sites)
  };
}
function serialize(sites) {
  return sites.slice(0, 40).map((s) => `    at ${s.toString()}`).join("\n");
}

// src/baseline/store.ts
import * as os from "node:os";
var HOME = os.homedir();
var CWD = process.cwd();
var TMP = os.tmpdir();
function normalizePath(rawPath) {
  let p = rawPath;
  p = p.replace(/\\/g, "/");
  const homeNorm = HOME.replace(/\\/g, "/");
  const cwdNorm = CWD.replace(/\\/g, "/");
  const tmpNorm = TMP.replace(/\\/g, "/");
  if (p.toLowerCase().startsWith(cwdNorm.toLowerCase())) {
    p = "{CWD}" + p.slice(cwdNorm.length);
  } else if (p.toLowerCase().startsWith(tmpNorm.toLowerCase())) {
    p = "{TMP}" + p.slice(tmpNorm.length);
    p = p.replace(/\/[a-zA-Z0-9._-]+-[a-zA-Z0-9]{6,}/g, "/*");
  } else if (p.toLowerCase().startsWith(homeNorm.toLowerCase())) {
    p = "{HOME}" + p.slice(homeNorm.length);
  }
  return p;
}
function normalizeHost(host) {
  return host;
}
function normalizeCommand(cmd) {
  let normalized = cmd;
  const cwdNorm = CWD.replace(/\\/g, "/");
  const homeNorm = HOME.replace(/\\/g, "/");
  normalized = normalized.replace(
    new RegExp(escapeRegex(cwdNorm).replace(/\//g, "[\\\\/]"), "gi"),
    "{CWD}"
  );
  normalized = normalized.replace(
    new RegExp(escapeRegex(homeNorm).replace(/\//g, "[\\\\/]"), "gi"),
    "{HOME}"
  );
  return normalized;
}
function normalizeDetail(signal, detail) {
  switch (signal) {
    case "fs_read":
    case "fs_write":
      return normalizePath(detail);
    case "network_out":
    case "dns_lookup":
      return normalizeHost(detail);
    case "child_process":
      return normalizeCommand(detail);
    default:
      return detail;
  }
}
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// src/intercept/worker.ts
import { createRequire } from "node:module";
var require2 = createRequire(import.meta.url);
var wt = require2("node:worker_threads");
var PRELOAD_ENV = "CHAINWATCH_PRELOAD_URL";
var originalWorker = null;
var patched = false;
function injectWorkerPreload() {
  if (patched) return;
  const preloadUrl = process.env[PRELOAD_ENV];
  if (!preloadUrl) return;
  const Original = wt.Worker;
  if (typeof Original !== "function") return;
  originalWorker = Original;
  patched = true;
  wt.Worker = class PatchedWorker extends Original {
    constructor(filename, options = {}) {
      const execArgv = Array.isArray(options.execArgv) ? [...options.execArgv] : [...process.execArgv];
      if (!execArgv.includes(preloadUrl)) {
        execArgv.push("--import", preloadUrl);
      }
      super(filename, { ...options, execArgv });
    }
  };
}
function unpatchWorker() {
  if (originalWorker) {
    wt.Worker = originalWorker;
    originalWorker = null;
  }
  patched = false;
}

// src/intercept/host.ts
function extractHost(args) {
  const a = args[0];
  if (!a) return "";
  if (typeof a === "string") {
    if (a.startsWith("/") || a.startsWith("\\\\") || a.startsWith(".")) return "";
    try {
      return new URL(a).hostname.toLowerCase();
    } catch {
      return stripPort(a.toLowerCase());
    }
  }
  if (a instanceof URL) return a.hostname.toLowerCase();
  if (typeof a === "object") {
    if (a.socketPath || a.path?.startsWith?.("\\\\")) return "";
    const h = a.hostname || a.host || "";
    return stripPort(String(h).toLowerCase());
  }
  if (typeof a === "number" && typeof args[1] === "string") {
    return stripPort(args[1].toLowerCase());
  }
  return "";
}
function stripPort(host) {
  const m = /^(\[[0-9a-f:]+\])(?::\d+)?$/i.exec(host);
  if (m) return m[1].slice(1, -1);
  const i = host.lastIndexOf(":");
  return i > 0 && host.indexOf(":") === i ? host.slice(0, i) : host;
}

// src/baseline/recorder.ts
var require3 = createRequire2(import.meta.url);
var BaselineRecorder = class {
  resolver;
  entries = /* @__PURE__ */ new Map();
  originals = {};
  installed = false;
  runTimestamp;
  constructor() {
    this.resolver = new PackageResolver();
    this.runTimestamp = (/* @__PURE__ */ new Date()).toISOString();
  }
  /** Install wrappers on core modules. Call before running the watched command. */
  install() {
    if (this.installed) return;
    this.installed = true;
    recorder = this;
    this.resolver.scan();
    this.wrapFs();
    this.wrapNet();
    this.wrapChildProcess();
    injectWorkerPreload();
  }
  /** Remove wrappers, restore originals. */
  uninstall() {
    if (!this.installed) return;
    this.installed = false;
    if (recorder === this) recorder = null;
    unpatchWorker();
    for (const [key, fn] of Object.entries(this.originals)) {
      const [modName, fnName] = key.split(".");
      if (!fnName) continue;
      this.getModule(modName ?? "")[fnName] = fn;
      delete this.originals[key];
    }
  }
  /** Get all recorded events as BaselineEvent[]. */
  getEvents(tag) {
    return [...this.entries.values()].map((e) => ({
      pkg: e.pkg,
      signal: e.signal,
      detail: e.detail,
      count: e.count,
      run: this.runTimestamp,
      ...tag ? { tag } : {}
    }));
  }
  /** Number of unique (pkg, signal, detail) entries recorded. */
  get eventCount() {
    return this.entries.size;
  }
  /** Number of unique packages observed. */
  get packageCount() {
    return new Set([...this.entries.values()].map((e) => e.pkg)).size;
  }
  // ─── Wrappers ─────────────────────────────────────────────────────────────
  record(signal, detail) {
    const attr = attributeCall(this.resolver);
    if (attr.package === "<entry>" || attr.package === "<unknown>") return;
    if (attr.package === "chainwatch") return;
    const normalized = normalizeDetail(signal, detail);
    const key = `${attr.package}\0${signal}\0${normalized}`;
    const existing = this.entries.get(key);
    if (existing) {
      existing.count++;
    } else {
      this.entries.set(key, {
        pkg: attr.package,
        signal,
        detail: normalized,
        count: 1
      });
    }
  }
  wrapFs() {
    const fs3 = require3("node:fs");
    const wrap = (name, signal, extractPath) => {
      const original = fs3[name];
      this.originals[`fs.${name}`] = original;
      fs3[name] = function patched2(...args) {
        const p = extractPath(args);
        if (p) recorder?.record(signal, p);
        return original.apply(this, args);
      };
    };
    wrap("readFileSync", "fs_read", (a) => String(a[0] ?? ""));
    wrap("readFile", "fs_read", (a) => String(a[0] ?? ""));
    wrap("createReadStream", "fs_read", (a) => String(a[0] ?? ""));
    wrap("writeFileSync", "fs_write", (a) => String(a[0] ?? ""));
    wrap("writeFile", "fs_write", (a) => String(a[0] ?? ""));
  }
  wrapNet() {
    const http = require3("node:http");
    const https = require3("node:https");
    const dns = require3("node:dns");
    const net = require3("node:net");
    const wrapRequest = (mod, modName, name) => {
      const original = mod[name];
      this.originals[`${modName}.${name}`] = original;
      mod[name] = function patched2(...args) {
        const host = extractHost(args);
        if (host) recorder?.record("network_out", host);
        return original.apply(this, args);
      };
    };
    wrapRequest(http, "http", "request");
    wrapRequest(http, "http", "get");
    wrapRequest(https, "https", "request");
    wrapRequest(https, "https", "get");
    const netConnect = net.connect;
    this.originals["net.connect"] = netConnect;
    net.connect = function patched2(...args) {
      const host = extractHost(args);
      if (host) recorder?.record("network_out", host);
      return netConnect.apply(this, args);
    };
    const wrapDns = (name) => {
      const original = dns[name];
      this.originals[`dns.${name}`] = original;
      dns[name] = function patched2(...args) {
        const host = String(args[0] ?? "");
        if (host) recorder?.record("dns_lookup", host);
        return original.apply(this, args);
      };
    };
    wrapDns("lookup");
    wrapDns("resolve");
    wrapDns("resolve4");
    wrapDns("resolve6");
  }
  wrapChildProcess() {
    const cp = require3("node:child_process");
    const wrap = (name) => {
      const original = cp[name];
      this.originals[`cp.${name}`] = original;
      cp[name] = function patched2(...args) {
        const cmd = String(args[0] ?? "");
        if (cmd) recorder?.record("child_process", cmd);
        return original.apply(this, args);
      };
    };
    wrap("exec");
    wrap("execSync");
    wrap("spawn");
    wrap("spawnSync");
    wrap("fork");
  }
  getModule(name) {
    switch (name) {
      case "fs":
        return require3("node:fs");
      case "http":
        return require3("node:http");
      case "https":
        return require3("node:https");
      case "dns":
        return require3("node:dns");
      case "net":
        return require3("node:net");
      case "cp":
        return require3("node:child_process");
      default:
        return {};
    }
  }
};
var recorder = null;
function startRecording() {
  const rec = new BaselineRecorder();
  recorder = rec;
  rec.install();
  return rec;
}

// src/recorder-preload.ts
var recorderLog = process.env["CHAINWATCH_RECORDER_LOG"];
var baselineFile = process.env["CHAINWATCH_BASELINE_FILE"];
var baselineTag = process.env["CHAINWATCH_BASELINE_TAG"];
if (process.env["CHAINWATCH_DEBUG"]) {
  process.stderr.write(`[chainwatch recorder] preload loaded, baseline=${baselineFile}, log=${recorderLog}
`);
}
var recorder2 = startRecording();
if (process.env["CHAINWATCH_DEBUG"]) {
  process.stderr.write(`[chainwatch recorder] recording started
`);
}
if (recorderLog) {
  let lastFlushedCount = 0;
  const flushInterval = setInterval(() => {
    const events = recorder2.getEvents(baselineTag);
    if (events.length > lastFlushedCount) {
      const newEvents = events.slice(lastFlushedCount);
      lastFlushedCount = events.length;
      try {
        fs2.appendFileSync(recorderLog, newEvents.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
      } catch {
      }
    }
  }, 200);
  flushInterval.unref();
  process.on("exit", () => {
    clearInterval(flushInterval);
    const events = recorder2.getEvents(baselineTag);
    if (events.length > lastFlushedCount) {
      const newEvents = events.slice(lastFlushedCount);
      try {
        fs2.appendFileSync(recorderLog, newEvents.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
      } catch {
      }
    }
  });
} else if (baselineFile) {
  process.on("exit", () => {
    const events = recorder2.getEvents(baselineTag);
    if (process.env["CHAINWATCH_DEBUG"]) {
      process.stderr.write(`[chainwatch recorder] exit: ${events.length} events, writing to ${baselineFile}
`);
    }
    if (events.length > 0) {
      try {
        const dir = path3.dirname(baselineFile);
        if (!fs2.existsSync(dir)) {
          fs2.mkdirSync(dir, { recursive: true });
        }
        fs2.appendFileSync(baselineFile, events.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
      } catch (e) {
        if (process.env["CHAINWATCH_DEBUG"]) {
          process.stderr.write(`[chainwatch recorder] write error: ${e.message}
`);
        }
      }
    }
  });
}
export {
  recorder2 as recorder
};
