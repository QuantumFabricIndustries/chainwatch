/**
 * Regression tests — package name extraction from file paths.
 *
 * Bugs covered:
 *  - The old regex matched the FIRST node_modules segment, so pnpm paths
 *    (…/node_modules/.pnpm/foo@1.0/node_modules/foo/…) attributed to ".pnpm"
 *    and nested deps (foo/node_modules/bar) attributed to "foo".
 *  - Now: LAST node_modules segment wins.
 */

import { describe, it, expect } from 'vitest';
import { packageNameFromPath } from '../../src/resolver.js';

describe('packageNameFromPath regression', () => {
  it('extracts the real package from a pnpm .pnpm path', () => {
    expect(
      packageNameFromPath('D:/proj/node_modules/.pnpm/foo@1.0.0/node_modules/foo/index.js'),
    ).toBe('foo');
  });

  it('extracts the nested package, not the parent', () => {
    expect(
      packageNameFromPath('/proj/node_modules/foo/node_modules/bar/lib/x.js'),
    ).toBe('bar');
  });

  it('handles scoped packages', () => {
    expect(
      packageNameFromPath('/proj/node_modules/@scope/pkg/dist/index.js'),
    ).toBe('@scope/pkg');
  });

  it('handles scoped packages under pnpm', () => {
    expect(
      packageNameFromPath('/proj/node_modules/.pnpm/@scope+pkg@1.0.0/node_modules/@scope/pkg/index.js'),
    ).toBe('@scope/pkg');
  });

  it('handles Windows backslash paths', () => {
    expect(
      packageNameFromPath('D:\\proj\\node_modules\\evil\\index.js'),
    ).toBe('evil');
  });

  it('returns null for non-node_modules paths', () => {
    expect(packageNameFromPath('/proj/src/index.js')).toBeNull();
  });

  it('skips dot-dirs like .pnpm and .bin', () => {
    expect(
      packageNameFromPath('/proj/node_modules/.bin/foo.js'),
    ).toBeNull();
  });
});
