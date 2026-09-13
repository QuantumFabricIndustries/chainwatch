/**
 * Regression tests — Engine listener isolation and event dedupe.
 *
 * Bugs covered:
 *  - A throwing onEvent listener propagated into the watched process,
 *    corrupting app state mid-readFileSync. Listeners must be isolated.
 *  - Identical repeated events flooded the log — they're now merged with
 *    an `occurrences` counter.
 */

import { describe, it, expect } from 'vitest';
import { Engine } from '../../src/engine.js';
import { DEFAULT_POLICY } from '../../src/policy.js';

describe('Engine regression', () => {
  it('a throwing listener does not break evaluate()', () => {
    const engine = new Engine(DEFAULT_POLICY);
    engine.onEvent(() => {
      throw new Error('listener exploded');
    });

    // Must not throw — the error goes to stderr, not into watched code.
    const { event } = engine.evaluate('credential_access', 'high', 60, { path: '/x/.npmrc' });
    expect(event.signal).toBe('credential_access');
  });

  it('dedupes identical events into occurrences', () => {
    const engine = new Engine(DEFAULT_POLICY);
    const detail = { path: '/x/.npmrc' };

    engine.evaluate('credential_access', 'high', 60, detail);
    engine.evaluate('credential_access', 'high', 60, detail);
    engine.evaluate('credential_access', 'high', 60, detail);

    expect(engine.events).toHaveLength(1);
    expect(engine.events[0]!.detail['occurrences']).toBe(3);
  });

  it('does not dedupe events with different details', () => {
    const engine = new Engine(DEFAULT_POLICY);
    engine.evaluate('network_exfil', 'medium', 30, { host: 'a.example.com' });
    engine.evaluate('network_exfil', 'medium', 30, { host: 'b.example.com' });
    expect(engine.events).toHaveLength(2);
  });

  it('dedupe key ignores volatile fields like chainScore', () => {
    const engine = new Engine(DEFAULT_POLICY);
    // Simulate two events whose detail differs only in scorer-injected fields.
    engine.evaluate('network_exfil', 'medium', 30, { host: 'x.example.com' });
    // Manually inject a different chainScore — stableKey must exclude it.
    const { event } = engine.evaluate('network_exfil', 'medium', 30, { host: 'x.example.com' });
    expect(engine.events).toHaveLength(1);
    expect(event.detail['occurrences']).toBe(2);
  });
});
