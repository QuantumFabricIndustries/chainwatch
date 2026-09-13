/**
 * Regression test — BaselineRecorder.install() must wire the module-level
 * recorder reference.
 *
 * Bug: install() only set `installed = true`; the module-level `recorder`
 * was set exclusively by startRecording(). Calling `install()` directly
 * meant every wrapper's `recorder?.record(...)` no-oped — recording silently
 * produced zero events.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { createRequire } from 'node:module';
import { BaselineRecorder } from '../../src/baseline/recorder.js';

const require = createRequire(import.meta.url);

describe('BaselineRecorder.install() regression', () => {
  let rec: BaselineRecorder | null = null;
  afterEach(() => rec?.uninstall());

  it('records events when install() is called directly (no startRecording)', () => {
    rec = new BaselineRecorder();
    rec.install();

    // fake-drift-pkg is a file: devDependency — its real path resolves through
    // the node_modules symlink so attribution maps it to "fake-drift-pkg".
    const drift = require('fake-drift-pkg') as { runClean: () => unknown };
    drift.runClean();

    const events = rec.getEvents();
    expect(events.length).toBeGreaterThan(0);
    expect(events.some((e) => e.pkg === 'fake-drift-pkg')).toBe(true);
  });

  it('uninstall() clears the module-level recorder so wrappers stop recording', () => {
    rec = new BaselineRecorder();
    rec.install();
    rec.uninstall();
    const eventsAfter = rec.getEvents().length;

    const drift = require('fake-drift-pkg') as { runClean: () => unknown };
    drift.runClean();

    expect(rec.getEvents().length).toBe(eventsAfter);
    rec = null;
  });
});
