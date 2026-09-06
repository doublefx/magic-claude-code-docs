#!/usr/bin/env node
// CLI wrapper around src/gather.mjs.
//
//   --home <dir>            defaults to os.homedir()
//   --plugin-root <dir>     required (the checked-out `plugin/` directory)
//   --claude-version <v>    override, mainly for manual testing
//   --dry-run               print the gathered object to stdout instead of
//                            writing anything under <home>/.claude-code-docs/

import path from 'node:path';
import os from 'node:os';
import { mkdir, writeFile } from 'node:fs/promises';
import { gather } from '../src/gather.mjs';

function parseArgs(argv) {
  const args = { home: os.homedir(), dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--home') args.home = argv[++i];
    else if (a === '--plugin-root') args.pluginRoot = argv[++i];
    else if (a === '--claude-version') args.claudeVersion = argv[++i];
    else if (a === '--dry-run') args.dryRun = true;
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.pluginRoot) {
    console.error('gather: --plugin-root <dir> is required');
    process.exitCode = 1;
    return;
  }

  const result = await gather({
    home: args.home,
    pluginRoot: args.pluginRoot,
    claudeVersion: args.claudeVersion,
  });

  if (args.dryRun) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const version = result.claudeVersion.status === 'ok' ? result.claudeVersion.value : 'unknown';
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
