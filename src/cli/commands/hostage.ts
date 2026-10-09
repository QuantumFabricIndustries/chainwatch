/**
 * `chainwatch hostage-check` — look for the tensorlake-style wipe-on-revoke
 * monitor before anyone revokes a token.
 */

import type { Command } from 'commander';
import { checkHost, remediationSteps } from '../../hostage.js';

export function registerHostage(program: Command): void {
  program
    .command('hostage-check')
    .description('Check this machine and project for a wipe-on-revoke token monitor (tensorlake worm)')
    .option('--project <dir>', 'Project to check for worm-committed files', process.cwd())
    .action((opts: { project: string }) => {
      const found = checkHost({ projectDir: opts.project });
      const monitors = found.filter((a) => a.kind === 'monitor');

      if (found.length === 0) {
        console.log('No hostage-token monitor or worm repo files found.');
        process.exit(0);
      }

      for (const a of found) console.log(`  [${a.kind}] ${a.path} — ${a.detail}`);
      if (monitors.length > 0) {
        console.log('\nA token monitor is installed. Follow these steps in order:');
        remediationSteps().forEach((s, i) => console.log(`  ${i + 1}. ${s}`));
      } else {
        console.log('\nNo monitor running, but these project files can re-run the worm. Review and remove them.');
      }
      // 2 = monitor present (do not revoke), 1 = repo files only.
      process.exit(monitors.length > 0 ? 2 : 1);
    });
}
