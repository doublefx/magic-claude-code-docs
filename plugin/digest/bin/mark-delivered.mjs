#!/usr/bin/env node
// CLI wrapper around src/mark-delivered.mjs.
//
//   --home <dir>       defaults to os.homedir()
//   --version <v>      required
//   --note <text>      required — where the digest was posted (Atrium room,
//                       card ids, "no board configured", etc.)
//
// Exit codes: 0 success (including the idempotent no-op when already
// delivered); 1 bad arguments; 2 the digest's <version>.json is missing.

import os from 'node:os';
import { markDelivered } from '../src/mark-delivered.mjs';

function parseArgs(argv) {
  const args = { home: os.homedir() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--home') args.home = argv[++i];
    else if (a === '--version') args.version = argv[++i];
    else if (a === '--note') args.note = argv[++i];
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.version || !args.note) {
    console.error('mark-delivered: --version <v> and --note <text> are required');
    process.exitCode = 1;
    return;
  }

  let outcome;
  try {
    outcome = await markDelivered(args);
  } catch (e) {
    if (e.code === 'MISSING') {
      console.error(e.message);
      process.exitCode = 2;
      return;
    }
    throw e;
  }

  if (outcome.alreadyDelivered) {
    console.log(`mark-delivered: ${outcome.jsonPath} was already delivered at ${outcome.record.deliveredAt} — no-op`);
    return;
  }

  console.log(outcome.jsonPath);
}

main().catch((e) => {
  console.error((e && e.stack) || e);
  process.exitCode = 1;
});
