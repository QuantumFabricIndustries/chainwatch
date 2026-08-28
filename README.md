# ChainWatch

**Runtime supply-chain watchdog for npm packages.**

ChainWatch monitors your installed npm dependencies at runtime — detecting behavioral anomalies, unauthorized network calls, file system tampering, and supply-chain compromise the moment they happen, not after the fact.

Most supply-chain attacks are caught too late: after `npm install`, after the CI run, after the build ships. ChainWatch sits in your runtime and watches what packages actually do, not just what their code says they'll do.

---

## What It Detects

- **Unauthorized network egress** — packages phoning home to unknown endpoints
- **File system anomalies** — reads/writes outside expected package scope
- **Process spawning** — unexpected child processes launched by dependencies
- **Behavioral drift** — packages behaving differently between environments
- **Integrity violations** — installed files that don't match published checksums

---

## How It Works

ChainWatch hooks into Node.js at the module level, wrapping native APIs to intercept and analyze behavior in real time. Each package gets a behavioral profile. Deviations from that profile trigger alerts — configurable from warn to block.

```
npm install → ChainWatch baseline → runtime monitoring → anomaly alerts
```

---

## Quick Start

```bash
npm install chainwatch
```

```typescript
import { ChainWatch } from 'chainwatch';

const watcher = new ChainWatch({
  policy: 'strict',       // warn | strict | block
  allowlist: ['axios'],   // packages with known network needs
  output: 'console'       // console | file | webhook
});

watcher.start();
```

---

## Configuration

```typescript
{
  policy: 'strict',
  allowlist: ['axios', 'node-fetch'],
  rules: {
    network: true,        // monitor outbound connections
    filesystem: true,     // monitor file access
    processes: true,      // monitor child process spawning
    integrity: true       // verify checksums at load time
  },
  output: {
    type: 'webhook',
    url: 'https://your-siem-endpoint.com/events'
  }
}
```

---

## Why Runtime vs. Static Analysis

Static scanners (Snyk, Dependabot, Socket) analyze code before it runs. That's necessary but not sufficient — obfuscated payloads, conditional logic, and time-delayed attacks all bypass static analysis. ChainWatch catches what static tools miss by watching actual behavior.

---

## Built By

[Quantum Fabric Industries](https://github.com/QuantumFabricIndustries) — AI infrastructure, cybersecurity tooling, and audio DSP research.

---

## License

MIT
