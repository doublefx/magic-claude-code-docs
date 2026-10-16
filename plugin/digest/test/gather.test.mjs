import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, cp, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readdir } from 'node:fs/promises';
import { gather, parseChangelog, computeLineDiff, formatDiff } from '../src/gather.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(__dirname, 'fixtures');
const pluginRoot = path.join(FIXTURES, 'pluginRoot');

async function freshHome() {
  const dir = await mkdtemp(path.join(tmpdir(), 'digest-home-'));
  await cp(path.join(FIXTURES, 'home'), dir, { recursive: true });
  return dir;
}

// Fake `exec` matching the contract src/gather.mjs relies on:
//   exec(command, args, { env, timeoutMs }) -> { code, stdout, stderr }
function makeExec({ versionOk = true, versionStdout = '3.0.0 (Claude Code)', typesExit = 0, typesContent = 'export type Foo = 1;\nexport type Baz = 3;\n' } = {}) {
  return async function exec(_command, args = []) {
    if (args[0] === '--version') {
      if (!versionOk) return { code: 1, stdout: '', stderr: 'command not found' };
      return { code: 0, stdout: versionStdout, stderr: '' };
    }
    if (args[0] === '-p') {
      const m = String(args[1]).match(/^\/plugin-types (.+)$/);
      const dir = m ? m[1] : null;
      if (typesExit === 0 && dir) {
        await mkdir(dir, { recursive: true });
        await writeFile(path.join(dir, 'claude-code.d.ts'), typesContent, 'utf8');
      }
      return {
        code: typesExit,
        stdout: 'ran plugin-types',
        stderr: typesExit === 0 ? '' : 'boom: types generation failed',
      };
    }
    throw new Error(`unexpected exec call: ${_command} ${args.join(' ')}`);
  };
}

function okFetch(version = '0.3.261') {
  return async () => ({ version });
}
function throwingFetch() {
  return async () => {
    throw new Error('network down');
  };
}

test('(a) happy path — every field comes back ok', async () => {
  const home = await freshHome();
  const result = await gather({
    home,
    pluginRoot,
    exec: makeExec(),
    fetch: okFetch(),
    now: () => new Date('2026-09-05T00:00:00Z'),
  });

  assert.equal(result.claudeVersion.status, 'ok');
  assert.equal(result.claudeVersion.value, '3.0.0');
  assert.equal(result.previousVersion.status, 'ok');
  assert.equal(result.previousVersion.value, '2.0.0');

  // (f) version-range selection: 3 blocks in the fixture, previous=2.0.0 -> only 3.0.0
  assert.equal(result.changelog.status, 'ok');
  assert.deepEqual(result.changelog.blocks.map((b) => b.version), ['3.0.0']);
  assert.match(result.changelog.blocks[0].body, /newest change/);

  assert.equal(result.docsChanged.status, 'ok');
  assert.deepEqual(result.docsChanged.added.sort(), ['c.md']);
  assert.deepEqual(result.docsChanged.changed.sort(), ['a.md']);
  assert.deepEqual(result.docsChanged.removed.sort(), ['d.md']);

  assert.equal(result.sdk.status, 'ok');
  assert.equal(result.sdk.latest, '0.3.261');

  assert.equal(result.types.status, 'ok');
  assert.equal(result.types.ranCommand, true);
  assert.equal(typeof result.types.diff, 'string');
  assert.ok(result.types.addedLines >= 1);

  // (g) highest-version-dir selection is semver, not lexical: 9.53.0 beats 9.9.0
  assert.equal(result.manifests.status, 'ok');
  const names = result.manifests.entries.map((e) => `${e.marketplace}/${e.plugin}@${e.version}`).sort();
  assert.deepEqual(names, [
    'marketA/pluginA@2.0.0',
    'marketB/pluginB@9.53.0',
    'marketC/pluginC@1.0.0',
    'marketD/pluginD@1.0.0',
  ]);

  // (e) invalid manifest is listed with an error; the rest are unaffected
  const invalid = result.manifests.entries.find((e) => e.plugin === 'pluginC');
  assert.equal(invalid.manifest, null);
  assert.ok(invalid.error);
  const valid = result.manifests.entries.find((e) => e.plugin === 'pluginA');
  assert.equal(valid.manifest.plugin, 'pluginA');

  assert.equal(result.gatheredAt, '2026-09-05T00:00:00.000Z');
});

test('(b) no latest pointer -> previousVersion null, changelog only current block, docsChanged all added', async () => {
  const home = await freshHome();
  await rm(path.join(home, '.claude-code-docs', 'digests', 'latest'));

  const result = await gather({ home, pluginRoot, exec: makeExec(), fetch: okFetch(), now: () => new Date() });

  assert.equal(result.previousVersion.status, 'ok');
  assert.equal(result.previousVersion.value, null);

  assert.deepEqual(result.changelog.blocks.map((b) => b.version), ['3.0.0']);

  assert.equal(result.docsChanged.status, 'ok');
  assert.equal(result.docsChanged.note, 'no previous snapshot');
  assert.deepEqual(result.docsChanged.added.sort(), ['a.md', 'b.md', 'c.md']);
  assert.deepEqual(result.docsChanged.changed, []);
  assert.deepEqual(result.docsChanged.removed, []);
});

test('(c) fetch throws -> sdk unavailable, every other field stays ok', async () => {
  const home = await freshHome();
  const result = await gather({ home, pluginRoot, exec: makeExec(), fetch: throwingFetch(), now: () => new Date() });

  assert.equal(result.sdk.status, 'unavailable');
  assert.match(result.sdk.reason, /network down/);

  assert.equal(result.claudeVersion.status, 'ok');
  assert.equal(result.changelog.status, 'ok');
  assert.equal(result.docsChanged.status, 'ok');
  assert.equal(result.types.status, 'ok');
  assert.equal(result.manifests.status, 'ok');
});

test('(d) plugin-types exits non-zero -> types unavailable, reason names the exit', async () => {
  const home = await freshHome();
  const result = await gather({
    home,
    pluginRoot,
    exec: makeExec({ typesExit: 1 }),
    fetch: okFetch(),
    now: () => new Date(),
  });

  assert.equal(result.types.status, 'unavailable');
  assert.match(result.types.reason, /exited 1/);
  assert.match(result.types.reason, /boom/);

  // never lets one source's failure hide the others
  assert.equal(result.claudeVersion.status, 'ok');
  assert.equal(result.sdk.status, 'ok');
});

test('claudeVersion falls back to the versions directory, sorted by semver', async () => {
  const home = await freshHome();
  const result = await gather({
    home,
    pluginRoot,
    exec: makeExec({ versionOk: false }),
    fetch: okFetch(),
    now: () => new Date(),
  });

  assert.equal(result.claudeVersion.status, 'ok');
  assert.equal(result.claudeVersion.value, '9.53.0');
  assert.equal(result.claudeVersion.source, 'versions-dir');
});

test('types step is skipped when claude-code.d.ts already exists for that version', async () => {
  const home = await freshHome();
  const dir = path.join(home, '.claude-code-docs', 'types', '3.0.0');
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, 'claude-code.d.ts'), 'export type Existing = true;\n', 'utf8');

  let execCalledForTypes = false;
  const exec = async (command, args = []) => {
    if (args[0] === '-p') execCalledForTypes = true;
    return makeExec()(command, args);
  };

  const result = await gather({ home, pluginRoot, exec, fetch: okFetch(), now: () => new Date() });

  assert.equal(result.types.status, 'ok');
  assert.equal(result.types.ranCommand, false);
  assert.equal(execCalledForTypes, false);
});

test('every read is independently wrapped: pluginRoot missing changelog/manifest still returns an object, never throws', async () => {
  const home = await freshHome();
  const emptyPluginRoot = await mkdtemp(path.join(tmpdir(), 'digest-empty-root-'));

  const result = await gather({
    home,
    pluginRoot: emptyPluginRoot,
    exec: makeExec(),
    fetch: okFetch(),
    now: () => new Date(),
  });

  assert.equal(result.changelog.status, 'unavailable');
  assert.ok(result.changelog.reason);
  assert.equal(result.docsChanged.status, 'unavailable');
  assert.ok(result.docsChanged.reason);
  // unrelated fields still resolve fine
  assert.equal(result.claudeVersion.status, 'ok');
  assert.equal(result.sdk.status, 'ok');
});

test('bin/gather.mjs writes only <version>.gather.json — never latest nor snapshot', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'gather-bin-'));
  const bin = path.join(__dirname, '..', 'bin', 'gather.mjs');
  const pluginRoot = path.join(FIXTURES, 'pluginRoot');
  const run = promisify(execFile);
  // A fake `claude` on PATH keeps the run offline and deterministic.
  const fakeBin = path.join(home, 'bin');
  await mkdir(fakeBin, { recursive: true });
  await writeFile(path.join(fakeBin, 'claude'), '#!/bin/sh\necho "9.9.9 (Claude Code)"\n', { mode: 0o755 });
  await run(process.execPath, [bin, '--home', home, '--plugin-root', pluginRoot], {
    env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, CLAUDE_CODE_ENABLE_FUNCTION_HOOKS: '', MAGIC_CLAUDE_DOCS_OFFLINE: '1' },
    timeout: 60000,
  });
  const files = await readdir(path.join(home, '.claude-code-docs', 'digests'));
  assert.deepEqual(files.sort(), ['9.9.9.gather.json']);
  await rm(home, { recursive: true, force: true });
});

test('manifests: digest-targets.json manifestPath entries are included, unreadable ones listed with error', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'gather-extra-'));
  await mkdir(path.join(home, '.claude-code-docs'), { recursive: true });
  const good = path.join(home, 'toolbox-manifest.json');
  await writeFile(good, JSON.stringify({ plugin: 'workflow-toolbox', version: '0.171.0', hooks: {} }));
  await writeFile(path.join(home, '.claude-code-docs', 'digest-targets.json'), JSON.stringify({
    'workflow-toolbox': { manifestPath: good, marketplace: 'wt' },
    'ghost': { manifestPath: path.join(home, 'missing.json') },
    'no-path': { boardId: 'x' },
  }));
  const result = await gather({ home, pluginRoot: path.join(FIXTURES, 'pluginRoot'), exec: makeExec(), fetch: okFetch(), now: () => new Date() });
  const names = result.manifests.entries.map((e) => e.plugin);
  assert.ok(names.includes('workflow-toolbox'));
  const ghost = result.manifests.entries.find((e) => e.plugin === 'ghost');
  assert.ok(ghost && ghost.error && ghost.manifest === null);
  assert.ok(!names.includes('no-path'));
  const wt = result.manifests.entries.find((e) => e.plugin === 'workflow-toolbox');
  assert.equal(wt.version, '0.171.0');
  await rm(home, { recursive: true, force: true });
});

test('parseChangelog reads the raw GitHub CHANGELOG format (## X.Y.Z headings) as well as <Update> blocks', () => {
  const raw = '# Claude Code Changelog\n\n> source\n\n---\n\n# Changelog\n\n## 2.1.263\n\n- Bug fixes\n\n## 2.1.261\n\n- Added X\n- Fixed Y\n\n## 2.1.260\n\n- Old\n';
  const blocks = parseChangelog(raw);
  assert.deepEqual(blocks.map((b) => b.version), ['2.1.263', '2.1.261', '2.1.260']);
  assert.equal(blocks[1].body, '- Added X\n- Fixed Y');
  assert.equal(blocks[0].date, null);
  const upd = parseChangelog('<Update label="9.9.9" description="d">body</Update>\n## 1.0.0\nignored');
  assert.deepEqual(upd.map((b) => b.version), ['9.9.9']);
});

test('computeLineDiff on a large file with one changed line reports one del and one add', () => {
  const oldLines = Array.from({ length: 6000 }, (_, i) => `line ${i}`);
  const newLines = oldLines.slice();
  newLines[0] = '// Written by Claude Code 2.1.263.';
  oldLines[0] = '// Written by Claude Code 2.1.261.';
  const { addedLines, removedLines } = formatDiff(computeLineDiff(oldLines, newLines));
  assert.equal(addedLines, 1);
  assert.equal(removedLines, 1);
});

// A range that lacks the digested version's OWN section read as "no changelog entries" for 2.1.290-2.1.301,
// because the mirror lagged the release. Fixture changelog sections: 1.0.0, 2.0.0, 3.0.0; latest pointer 2.0.0.
test('changelog: the version newer than every section is STALE, never ok with zero blocks (not yet published / mirror lag)', async () => {
  const home = await freshHome();
  const result = await gather({ home, pluginRoot, claudeVersion: '3.0.1', previousVersion: '3.0.0', exec: makeExec(), fetch: okFetch() });
  assert.equal(result.changelog.status, 'stale');
  assert.deepEqual(result.changelog.blocks, []);
  assert.equal(result.changelog.newest, '3.0.0');
  assert.match(result.changelog.reason, /newest section is 3\.0\.0, not 3\.0\.1/);
});

test('changelog: a range that holds older sections but not the version own one is still STALE', async () => {
  const home = await freshHome();
  const result = await gather({ home, pluginRoot, claudeVersion: '4.0.0', exec: makeExec(), fetch: okFetch() });
  assert.equal(result.previousVersion.value, '2.0.0');
  assert.equal(result.changelog.status, 'stale');
  assert.deepEqual(result.changelog.blocks.map((b) => b.version), ['3.0.0'], 'the sections it has are still returned');
});

test('changelog: a release the source moved past without a section is ok with a note (published without notes)', async () => {
  const home = await freshHome();
  const result = await gather({ home, pluginRoot, claudeVersion: '2.5.0', exec: makeExec(), fetch: okFetch() });
  assert.equal(result.changelog.status, 'ok');
  assert.deepEqual(result.changelog.blocks, []);
  assert.match(result.changelog.note, /no changelog section was published for 2\.5\.0; the changelog moved on to 3\.0\.0/);
});

test('bin/gather.mjs --previous-version sets the range start instead of digests/latest', async () => {
  const home = await freshHome();
  const bin = path.join(__dirname, '..', 'bin', 'gather.mjs');
  const fakeBin = path.join(home, 'bin');
  await mkdir(fakeBin, { recursive: true });
  await writeFile(path.join(fakeBin, 'claude'), '#!/bin/sh\necho "3.0.0 (Claude Code)"\n', { mode: 0o755 });
  await promisify(execFile)(process.execPath, [bin, '--home', home, '--plugin-root', pluginRoot, '--claude-version', '3.0.0', '--previous-version', '1.0.0'], {
    env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, CLAUDE_CODE_ENABLE_FUNCTION_HOOKS: '', MAGIC_CLAUDE_DOCS_OFFLINE: '1' },
    timeout: 60000,
  });
  const { readFile } = await import('node:fs/promises');
  const written = JSON.parse(await readFile(path.join(home, '.claude-code-docs', 'digests', '3.0.0.gather.json'), 'utf8'));
  assert.equal(written.previousVersion.value, '1.0.0');
  assert.deepEqual(written.changelog.blocks.map((b) => b.version).sort(), ['2.0.0', '3.0.0']);
  await rm(home, { recursive: true, force: true });
});

test('bin/gather.mjs refuses a --previous-version that is not older than the target, writing nothing', async () => {
  const home = await freshHome();
  const bin = path.join(__dirname, '..', 'bin', 'gather.mjs');
  const fakeBin = path.join(home, 'bin');
  await mkdir(fakeBin, { recursive: true });
  await writeFile(path.join(fakeBin, 'claude'), '#!/bin/sh\necho "3.0.0 (Claude Code)"\n', { mode: 0o755 });
  const run = promisify(execFile)(process.execPath, [bin, '--home', home, '--plugin-root', pluginRoot, '--claude-version', '3.0.0', '--previous-version', '3.0.0'], {
    env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, CLAUDE_CODE_ENABLE_FUNCTION_HOOKS: '', MAGIC_CLAUDE_DOCS_OFFLINE: '1' },
    timeout: 60000,
  });
  await assert.rejects(run, (e) => e.code === 1 && /--previous-version 3\.0\.0 is not older than 3\.0\.0/.test(e.stderr));
  const { readFile } = await import('node:fs/promises');
  await assert.rejects(() => readFile(path.join(home, '.claude-code-docs', 'digests', '3.0.0.gather.json'), 'utf8'));
  await rm(home, { recursive: true, force: true });
});
