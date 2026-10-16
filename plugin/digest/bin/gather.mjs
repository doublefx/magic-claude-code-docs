#!/usr/bin/env node
// CLI wrapper around src/gather.mjs.
//
//   --home <dir>            defaults to os.homedir()
//   --plugin-root <dir>     required (the checked-out `plugin/` directory)
//   --claude-version <v>    override, mainly for manual testing
//   --previous-version <v>  override the range start (default: digests/latest), e.g. to re-gather a version
//                            whose earlier digest was built from a stale changelog
//   --dry-run               print the gathered object to stdout instead of
//                            writing anything under <home>/.claude-code-docs/

import path from 'node:path';
import os from 'node:os';
import { mkdir, writeFile } from 'node:fs/promises';
import { gather, compareVersions } from '../src/gather.mjs';

function parseArgs(argv) {
  const args = { home: os.homedir(), dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--home') args.home = argv[++i];
    else if (a === '--plugin-root') args.pluginRoot = argv[++i];
    else if (a === '--claude-version') args.claudeVersion = argv[++i];
    else if (a === '--previous-version') args.previousVersion = argv[++i];
    else if (a === '--dry-run') args.dryRun = true;
  }
  return args;
}

function emptyRange(previousVersion, version) {
  if (!previousVersion || compareVersions(previousVersion, version) < 0) return false;
  console.error(`gather: --previous-version ${previousVersion} is not older than ${version}: the range would be empty`);
  process.exitCode = 1;
  return true;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.pluginRoot) {
    console.error('gather: --plugin-root <dir> is required');
    process.exitCode = 1;
    return;
  }
  // Both ends given: an empty range is refused before any work. Otherwise checked once the installed version is known.
  if (args.claudeVersion && emptyRange(args.previousVersion, args.claudeVersion)) return;

  const result = await gather({
    // MAGIC_CLAUDE_DOCS_OFFLINE=1 seals the run (tests, air-gapped hosts): the
    // SDK-version fetch then fails fast and reports `unavailable`.
    ...(process.env.MAGIC_CLAUDE_DOCS_OFFLINE ? { fetch: async () => { throw new Error('offline'); } } : {}),
    home: args.home,
    pluginRoot: args.pluginRoot,
    claudeVersion: args.claudeVersion,
    ...(args.previousVersion ? { previousVersion: args.previousVersion } : {}),
  });

  const version = result.claudeVersion.status === 'ok' ? result.claudeVersion.value : 'unknown';
  if (version !== 'unknown' && emptyRange(args.previousVersion, version)) return;

  if (args.dryRun) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const digestsDir = path.join(args.home, '.claude-code-docs', 'digests');
  await mkdir(digestsDir, { recursive: true });

  const outPath = path.join(digestsDir, `${version}.gather.json`);
  await writeFile(outPath, JSON.stringify(result, null, 2) + '\n', 'utf8');

  // Only the gather file is written here. `<version>.snapshot.json` and
  // `latest` belong to bin/analyze.mjs, written after a SUCCESSFUL analysis
  // (ADR on the digest card): a `latest` written by gather would silence the
  // session-start signal for a version that was never digested.

  console.log(outPath);
}

main().catch((e) => {
  console.error((e && e.stack) || e);
  process.exitCode = 1;
});
