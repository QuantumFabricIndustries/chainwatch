/**
 * ChainWatch runtime engine.
 *
 * Wires interceptors → scorer → event log. Each interceptor calls `evaluate()`
 * with a proposed signal; the engine asks the scorer for the final action
 * (log / flag / block) based on chain context, records the event, and tells the
 * interceptor whether to proceed or throw.
 */

import { attributeCall } from './attribution.js';
import { makeEvent, type Action, type ChainWatchEvent, type Severity, type SignalType } from './events.js';
import { DEFAULT_POLICY, type Policy } from './policy.js';
import { ChainScorer } from './scorer.js';
import { PackageResolver } from './resolver.js';

export class ChainWatchBlockError extends Error {
  readonly event: ChainWatchEvent;
  constructor(event: ChainWatchEvent) {
    super(`ChainWatch BLOCKED ${event.signal} from "${event.package}" (chain score ${event.detail.chainScore})`);
    this.name = 'ChainWatchBlockError';
    this.event = event;
  }
}

export type EventListener = (e: ChainWatchEvent) => void;

export class Engine {
  readonly policy: Policy;
  readonly events: ChainWatchEvent[] = [];
  private readonly scorer: ChainScorer;
  private readonly resolver: PackageResolver;
  private listeners: EventListener[] = [];
  private installed = false;

  constructor(policy: Policy = DEFAULT_POLICY) {
    this.policy = policy;
    this.scorer = new ChainScorer(policy);
    this.resolver = new PackageResolver();
  }

  onEvent(cb: EventListener): void {
    this.listeners.push(cb);
  }

  /**
   * Called by an interceptor when it observes a suspicious action.
   * Returns the action the interceptor should take AND the recorded event
   * (so the interceptor can throw a ChainWatchBlockError with full context).
   */
  evaluate(
    signal: SignalType,
    severity: Severity,
    baseScore: number,
    detail: Record<string, unknown>,
  ): { action: Action; event: ChainWatchEvent } {
    const attr = attributeCall(this.resolver);

    // Trusted packages are logged but never blocked.
    if (this.policy.trustedPackages.includes(attr.package)) {
      return { action: 'log', event: this.record(signal, severity, baseScore, detail, attr, 'log') };
    }

    // Ask the scorer for chain context.
    const { action, chainScore } = this.scorer.observe(
      attr.package,
      signal,
      severity,
      baseScore,
      detail,
    );

    const enrichedDetail = { ...detail, chainScore };
    const event = this.record(signal, severity, baseScore, enrichedDetail, attr, action);
    return { action, event };
  }

  /**
   * Dedupe: identical (package, signal, detail) events within this window are
   * merged into the original event with an `occurrences` counter instead of
   * flooding the log. Worms retrying the same call produce ONE event.
   */
  private static readonly DEDUPE_MS = 60_000;
  private readonly recentEvents = new Map<string, ChainWatchEvent>();

  private record(
    signal: SignalType,
    severity: Severity,
    score: number,
    detail: Record<string, unknown>,
    attr: { package: string; file: string; stack: string },
    action: Action,
  ): ChainWatchEvent {
    const key = `${attr.package}\x00${signal}\x00${stableKey(detail)}`;
    const existing = this.recentEvents.get(key);
    if (existing && Date.now() - existing.ts < Engine.DEDUPE_MS) {
      const n = ((existing.detail['occurrences'] as number) ?? 1) + 1;
      existing.detail['occurrences'] = n;
      existing.ts = Date.now();
      this.notify(existing);
      return existing;
    }

    const event = makeEvent(attr.package, signal, severity, score, detail, attr.stack, action);
    this.recentEvents.set(key, event);
    this.events.push(event);
    this.notify(event);
    return event;
  }

  /** Notify listeners, isolating failures so a bad callback can't break the watched process. */
  private notify(event: ChainWatchEvent): void {
    for (const cb of this.listeners) {
      try {
        cb(event);
      } catch (err) {
        // A throwing listener must never propagate into the watched process —
        // it would surface inside e.g. fs.readFileSync and corrupt app state.
        process.stderr.write(`chainwatch: event listener error: ${(err as Error).message}\n`);
      }
    }
  }

  install(): void {
    if (this.installed) return;
    this.installed = true;
    // Build the package path map so attribution can resolve symlinks.
    this.resolver.scan();
    // Imported here to avoid circular deps at module load.
    installInterceptors(this);
  }

  uninstall(): void {
    if (!this.installed) return;
    this.installed = false;
    uninstallInterceptors(this);
  }
}

/** Stable dedupe key for event detail — excludes volatile scorer fields. */
function stableKey(detail: Record<string, unknown>): string {
  const keys = Object.keys(detail).filter((k) => k !== 'chainScore' && k !== 'occurrences').sort();
  return keys.map((k) => `${k}=${JSON.stringify(detail[k])}`).join('|');
}

// Late-bound installer refs (set by intercept/index.ts on import).
let installInterceptors: (e: Engine) => void = () => {};
let uninstallInterceptors: (e: Engine) => void = () => {};

export function registerInstallers(
  install: (e: Engine) => void,
  uninstall: (e: Engine) => void,
): void {
  installInterceptors = install;
  uninstallInterceptors = uninstall;
}
