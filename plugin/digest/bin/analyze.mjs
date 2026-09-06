#!/usr/bin/env node
// CLI wrapper around src/analyze.mjs — the "analyze" phase of the digest.
//
//   --home <dir>        defaults to os.homedir()
//   --gather <path>     override the gather-result path (default:
//                        <home>/.claude-code-docs/digests/<version>.gather.json,
//                        version read from <home>/.claude-code-docs/digests/latest)
//   --version <v>       claude version to analyze (default: read from `latest`)
//   --model <name>      default claude-sonnet-5
//   --dry-run           print prompt size + would-be output paths, call nothing
//   --fake <file>        inject the file's content as the model's raw answer text
//                        instead of calling the real Agent SDK — for end-to-end
//                        testing without a real model call.
//
// The real model call is made only by this script, without --fake, one call
// per Claude Code version.

import path from 'node:path';
import os from 'node:os';
import { mkdir, writeFile, readFile, rename, unlink, stat } from 'node:fs/promises';
import { analyze, buildPrompt, renderMarkdown, AnalyzeError } from '../src/analyze.mjs';

const LOCK_STALE_MS = 30 * 60 * 1000;

function parseArgs(argv) {
  const args = { home: os.homedir(), dryRun: false, model: 'claude-sonnet-5' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--home') args.home = argv[++i];
    else if (a === '--gather') args.gatherPath = argv[++i];
    else if (a === '--version') args.version = argv[++i];
    else if (a === '--model') args.model = argv[++i];
    else if (a === '--dry-run') args.dryRun = true;
    else if (a === '--fake') args.fakePath = argv[++i];
  }
  return args;
}

async function atomicWrite(filePath, content) {
  const tmp = `${filePath}.tmp-${process.pid}`;
  await writeFile(tmp, content, 'utf8');
  await rename(tmp, filePath);
}

function makeFakeQuery(rawText) {
  return function fakeQuery() {
    async function* gen() {
      yield { type: 'result', subtype: 'success', result: rawText };
    }
    return gen();
  };
}

async function fileAge(p) {
  try {
    const st = await stat(p);
    return Date.now() - st.mtimeMs;
  } catch {
    return null;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const digestsDir = path.join(args.home, '.claude-code-docs', 'digests');

  let version = args.version;
  if (!version && !args.gatherPath) {
    try {
      version = (await readFile(path.join(digestsDir, 'latest'), 'utf8')).trim();
    } catch {
      console.error('analyze: no --version given and no digests/latest pointer found');
      process.exitCode = 1;
      return;
    }
  }

  const gatherPath = args.gatherPath ?? path.join(digestsDir, `${version}.gather.json`);
  let gathered;
  try {
    gathered = JSON.parse(await readFile(gatherPath, 'utf8'));
  } catch (e) {
    console.error(`analyze: could not read gather result at ${gatherPath}: ${String(e.message || e)}`);
    process.exitCode = 1;
    return;
  }
  version = version ?? gathered?.claudeVersion?.value ?? 'unknown';

  const jsonPath = path.join(digestsDir, `${version}.json`);
  const mdPath = path.join(digestsDir, `${version}.md`);
  const snapshotPath = path.join(digestsDir, `${version}.snapshot.json`);
  const latestPath = path.join(digestsDir, 'latest');
  const lockPath = path.join(digestsDir, `${version}.lock`);

  if (args.dryRun) {
    const prompt = buildPrompt(gathered);
    console.log(`prompt size: ${prompt.length} characters`);
    console.log(`would write: ${jsonPath}`);
    console.log(`would write: ${mdPath}`);
    console.log(`would write: ${snapshotPath}`);
    console.log(`would write: ${latestPath}`);
    return;
  }

  await mkdir(digestsDir, { recursive: true });

  const age = await fileAge(lockPath);
  if (age !== null && age < LOCK_STALE_MS) {
    console.error(
      `analyze: lock ${lockPath} is ${Math.round(age / 1000)}s old (< 30min) — another run may be in progress`,
    );
    process.exitCode = 3;
    return;
  }
  await writeFile(lockPath, String(process.pid), 'utf8');

  try {
    let queryFn;
    if (args.fakePath) {
      const rawText = await readFile(args.fakePath, 'utf8');
      queryFn = makeFakeQuery(rawText);
    }

    let outcome;
    try {
      outcome = await analyze(gathered, { query: queryFn, model: args.model });
    } catch (e) {
      if (e instanceof AnalyzeError) {
        console.error(`analyze: model answer failed validation: ${e.message}`);
        if (e.rawText) console.error(`--- raw model text ---\n${e.rawText}`);
        process.exitCode = 2;
        return;
      }
      throw e;
    }

    const { result, analyzedAt, usage } = outcome;
    const record = {
      result,
      sources: gathered,
      gatheredAt: gathered.gatheredAt ?? null,
      analyzedAt,
      usage: usage ?? null,
      deliveredAt: null,
    };

    await atomicWrite(jsonPath, JSON.stringify(record, null, 2) + '\n');
    await atomicWrite(mdPath, renderMarkdown(result, gathered) + '\n');

    const snapshot = gathered?.docsChanged?.snapshot ?? {};
    await atomicWrite(snapshotPath, JSON.stringify(snapshot, null, 2) + '\n');

    // `latest` is written LAST — everything else must be durably on disk
    // before any reader can discover this version through the pointer.
    await atomicWrite(latestPath, version + '\n');

    console.log(jsonPath);
  } finally {
    await unlink(lockPath).catch(() => {});
  }
}

main().catch((e) => {
  console.error((e && e.stack) || e);
  process.exitCode = 1;
});
