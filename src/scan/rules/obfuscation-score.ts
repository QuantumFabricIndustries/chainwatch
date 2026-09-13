/**
 * Rule 4: obfuscation_score
 *
 * Scores each package 0–100 for obfuscation patterns strongly associated with
 * malicious code:
 *  - Hex/unicode escape runs > 20 chars
 *  - eval() called with computed/concatenated strings
 *  - Function('...') constructor with string arg
 *  - Multiple layers of atob/btoa
 *  - High ratio of non-printable chars to printable
 *
 * Flag at > 60. Severity: MEDIUM (60–79), HIGH (80+).
 */

import * as path from 'node:path';
import type { Finding } from '../finding.js';
import type { Rule, PackageMeta } from '../types.js';
import { collectSourceFiles, readFileSafe, evidenceAround, lineOf } from '../util.js';

const HEX_RUN_RE = /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){9,}/; // 10+ consecutive \xNN
const UNICODE_RUN_RE = /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){9,}/;
const EVAL_COMPUTED_RE = /eval\s*\(\s*[^'")]+\s*\+/; // eval( with concatenation, not literal
const EVAL_VAR_RE = /eval\s*\(\s*[A-Za-z_$][\w$]*(?:\.[\w$]+|\[[^\]]*\])*\s*\)/; // eval(someVar) — the common obfuscator shape
const FUNCTION_CTOR_RE = /new\s+Function\s*\(\s*['"`]/;
const ATOB_LAYERS_RE = /atob\s*\(\s*atob\s*\(/;
const FROMCHARCODE_RUN_RE = /String\.fromCharCode\s*\((?:\s*\d+\s*,){4,}/; // 5+ char codes — string built from char codes
const ESCAPE_RE = /\\x[0-9a-fA-F]{2}/g;

export const obfuscationScore: Rule = {
  id: 'obfuscation_score',
  check(meta: PackageMeta): Finding[] {
    const findings: Finding[] = [];
    const pkgRef = `${meta.name}@${meta.version}`;

    for (const file of collectSourceFiles(meta.path)) {
      const content = readFileSafe(file);
      if (!content || content.length < 20) continue;
      const relFile = path.relative(meta.path, file);

      let score = 0;
      const hits: string[] = [];

      if (HEX_RUN_RE.test(content)) {
        score += 40;
        hits.push('hex escape run');
      }
      if (UNICODE_RUN_RE.test(content)) {
        score += 30;
        hits.push('unicode escape run');
      }
      if (EVAL_COMPUTED_RE.test(content)) {
        score += 25;
        hits.push('eval() with computed string');
      }
      if (EVAL_VAR_RE.test(content)) {
        score += 20;
        hits.push('eval() of variable');
      }
      if (FROMCHARCODE_RUN_RE.test(content)) {
        score += 20;
        hits.push('String.fromCharCode run');
      }
      if (FUNCTION_CTOR_RE.test(content)) {
        score += 30;
        hits.push('Function() constructor');
      }
      if (ATOB_LAYERS_RE.test(content)) {
        score += 25;
        hits.push('nested atob()');
      }

      // Non-printable ratio — high proportion of escaped bytes.
      const escapes = content.match(ESCAPE_RE) ?? [];
      const escapeChars = escapes.length * 4; // each \xNN is 4 chars
      if (content.length > 0 && escapeChars / content.length > 0.15) {
        score += 20;
        hits.push('high escape ratio');
      }

      score = Math.min(score, 100);

      if (score >= 60) {
        const severity = score >= 80 ? 'high' : 'medium';
        // Find the first hit's location for evidence.
        const firstHit = hits[0] ?? 'obfuscation';
        const matchStr = content.match(HEX_RUN_RE)?.[0] ?? content.match(UNICODE_RUN_RE)?.[0] ?? firstHit;
        findings.push({
          rule: 'obfuscation_score',
          severity,
          package: pkgRef,
          description: `Obfuscation score ${score}: ${hits.join(', ')}`,
          file: `${relFile}:${lineOf(content, matchStr.slice(0, 10))}`,
          evidence: evidenceAround(content, matchStr.slice(0, 20)),
          chainScore: score,
        });
      }
    }

    return findings;
  },
};
