import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  buildPrompt,
  renderMarkdown,
  analyze,
  AnalyzeError,
  keyManifestEntries,
} from '../src/analyze.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(__dirname, '..', 'bin', 'analyze.mjs');

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

function sampleGathered({ typesDiffLines } = {}) {
  const diffLines = typesDiffLines
    ? Array.from({ length: typesDiffLines }, (_, i) => `+added line ${i}`)
    : ['+export type Foo = 1;', '-export type Bar = 2;'];
  return {
    claudeVersion: { status: 'ok', value: '3.0.0' },
    previousVersion: { status: 'ok', value: '2.0.0' },
    changelog: {
      status: 'ok',
      blocks: [{ version: '3.0.0', date: 'March 1, 2026', body: 'newest change' }],
    },
    docsChanged: {
      status: 'ok',
      added: ['c.md'],
      changed: ['a.md'],
      removed: ['d.md'],
      snapshot: { 'a.md': 'hash-a', 'c.md': 'hash-c' },
    },
    sdk: { status: 'ok', latest: '0.3.261' },
    types: {
      status: 'ok',
      diff: diffLines.join('\n'),
      addedLines: diffLines.length,
      removedLines: 0,
    },
    manifests: {
      status: 'ok',
      entries: [
        {
          plugin: 'pluginA',
          marketplace: 'marketA',
          version: '1.0.0',
          path: '/x/pluginA/usage-manifest.json',
          configDir: '/home/.claude',
          manifest: { plugin: 'pluginA', sdk: { version: '0.3.200' } },
        },
        {
          plugin: 'pluginB',
          marketplace: 'marketB',
          version: '2.0.0',
          path: '/x/pluginB/usage-manifest.json',
          configDir: '/home/.claude',
          manifest: { plugin: 'pluginB', sdk: { version: '0.3.100' } },
        },
        {
          plugin: 'pluginC',
          marketplace: 'marketC',
          version: '1.0.0',
          path: '/x/pluginC/usage-manifest.json',
          configDir: '/home/.claude',
          manifest: null,
          error: 'Unexpected token , in JSON at position 2',
        },
      ],
    },
    gatheredAt: '2026-09-05T00:00:00.000Z',
  };
}

function validAnswerObject() {
  return {
    version: '3.0.0',
    from: '2.0.0',
    plugins: {
      pluginA: { breaks: [], couldServe: [], noise: 2 },
      pluginB: {
        breaks: [{ item: 'X removed', evidence: 'changelog says X', manifestRef: 'usage.foo' }],
        couldServe: [{ item: 'new hook', evidence: 'changelog mentions Y' }],
        noise: 0,
      },
    },
    summary: 'One plugin breaks, one could adopt a new hook.',
  };
}

function fakeQueryFromText(rawText) {
  return function fakeQuery() {
    async function* gen() {
      yield { type: 'result', subtype: 'success', result: rawText };
    }
    return gen();
  };
}

function runBin(args) {
  return new Promise((resolve) => {
    execFile('node', [BIN, ...args], (error, stdout, stderr) => {
      resolve({
        code: error ? (typeof error.code === 'number' ? error.code : 1) : 0,
        stdout,
        stderr,
      });
    });
  });
}

// ---------------------------------------------------------------------------

test('(a) buildPrompt names every manifest and every changelog version', () => {
  const prompt = buildPrompt(sampleGathered());
  assert.match(prompt, /pluginA/);
  assert.match(prompt, /pluginB/);
  assert.match(prompt, /pluginC/);
  assert.match(prompt, /3\.0\.0/);
});

test('(b) valid fake answer -> validated result, every plugin present, invalid manifest flagged by our code', async () => {
  const gathered = sampleGathered();
  const { result, analyzedAt } = await analyze(gathered, {
    query: fakeQueryFromText(JSON.stringify(validAnswerObject())),
    now: () => new Date('2026-09-05T01:00:00Z'),
  });

  assert.equal(result.version, '3.0.0');
  assert.equal(analyzedAt, '2026-09-05T01:00:00.000Z');
  assert.ok(result.plugins.pluginA);
  assert.ok(result.plugins.pluginB);
  assert.deepEqual(result.plugins.pluginC, {
    breaks: [],
    couldServe: [],
    noise: 0,
    manifestInvalid: true,
  });
});

test('(c) fake answer wrapped in prose -> JSON still extracted', async () => {
  const gathered = sampleGathered();
  const rawText = `Sure, here you go:\n${JSON.stringify(validAnswerObject())}\nHope that helps!`;
  const { result } = await analyze(gathered, { query: fakeQueryFromText(rawText) });
  assert.equal(result.version, '3.0.0');
  assert.equal(result.plugins.pluginA.noise, 2);
});

test('(d) fake answer missing a plugin -> AnalyzeError', async () => {
  const gathered = sampleGathered();
  const answer = validAnswerObject();
  delete answer.plugins.pluginB;
  await assert.rejects(
    () => analyze(gathered, { query: fakeQueryFromText(JSON.stringify(answer)) }),
    AnalyzeError,
  );
});

test('(e) fake answer with wrong field type -> AnalyzeError', async () => {
  const gathered = sampleGathered();
  const answer = validAnswerObject();
  answer.plugins.pluginA.noise = '3';
  await assert.rejects(
    () => analyze(gathered, { query: fakeQueryFromText(JSON.stringify(answer)) }),
    AnalyzeError,
  );
});

test('(f) renderMarkdown has one table row per plugin', async () => {
  const gathered = sampleGathered();
  const { result } = await analyze(gathered, {
    query: fakeQueryFromText(JSON.stringify(validAnswerObject())),
  });
  const md = renderMarkdown(result, gathered);
  const rows = md
    .split('\n')
    .filter((l) => l.startsWith('|') && !l.startsWith('|---') && !l.startsWith('| plugin '));
  assert.equal(rows.length, 3);
});

test('(i) types diff truncation marker appears past 400 lines', () => {
  const prompt = buildPrompt(sampleGathered({ typesDiffLines: 500 }));
  assert.match(prompt, /truncated \(100 more lines\)/);
});

test('(g) bin --fake writes the four files, latest holds the version, deliveredAt is null', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'digest-analyze-home-'));
  const digestsDir = path.join(home, '.claude-code-docs', 'digests');
  await mkdir(digestsDir, { recursive: true });
  await writeFile(
    path.join(digestsDir, '3.0.0.gather.json'),
    JSON.stringify(sampleGathered()),
    'utf8',
  );
  const fakePath = path.join(home, 'fake-answer.json');
  await writeFile(fakePath, JSON.stringify(validAnswerObject()), 'utf8');

  const { code, stderr } = await runBin([
    '--home',
    home,
    '--version',
    '3.0.0',
    '--fake',
    fakePath,
  ]);
  assert.equal(code, 0, stderr);

  const jsonRaw = await readFile(path.join(digestsDir, '3.0.0.json'), 'utf8');
  const record = JSON.parse(jsonRaw);
  assert.equal(record.deliveredAt, null);
  assert.equal(record.result.version, '3.0.0');
  assert.equal(record.gatheredAt, '2026-09-05T00:00:00.000Z');

  const md = await readFile(path.join(digestsDir, '3.0.0.md'), 'utf8');
  assert.match(md, /pluginA/);

  const snapshot = JSON.parse(await readFile(path.join(digestsDir, '3.0.0.snapshot.json'), 'utf8'));
  assert.deepEqual(snapshot, { 'a.md': 'hash-a', 'c.md': 'hash-c' });

  const latest = (await readFile(path.join(digestsDir, 'latest'), 'utf8')).trim();
  assert.equal(latest, '3.0.0');
});

test('(h) lock younger than 30 min -> exit 3, nothing written', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'digest-analyze-home-'));
  const digestsDir = path.join(home, '.claude-code-docs', 'digests');
  await mkdir(digestsDir, { recursive: true });
  await writeFile(
    path.join(digestsDir, '3.0.0.gather.json'),
    JSON.stringify(sampleGathered()),
    'utf8',
  );
  const fakePath = path.join(home, 'fake-answer.json');
  await writeFile(fakePath, JSON.stringify(validAnswerObject()), 'utf8');
  // fresh lock, mtime = now
  await writeFile(path.join(digestsDir, '3.0.0.lock'), 'other-pid', 'utf8');

  const { code } = await runBin(['--home', home, '--version', '3.0.0', '--fake', fakePath]);
  assert.equal(code, 3);

  await assert.rejects(() => readFile(path.join(digestsDir, '3.0.0.json'), 'utf8'));
  await assert.rejects(() => readFile(path.join(digestsDir, 'latest'), 'utf8'));
});

test('(j) the same plugin in two config dirs is ONE key, highest version kept, installs recorded', () => {
  const keyed = keyManifestEntries([
    { configDir: '/h/.claude', marketplace: 'm', plugin: 'atrium', version: '0.4.199', manifest: { plugin: 'atrium' } },
    { configDir: '/h/.claude-work', marketplace: 'm', plugin: 'atrium', version: '0.4.198', manifest: { plugin: 'atrium' } },
    { configDir: '/h/.claude', marketplace: 'other', plugin: 'atrium', version: '1.0.0', manifest: { plugin: 'atrium' } },
  ]);
  assert.deepEqual([...keyed.keys()].sort(), ['m/atrium', 'other/atrium']);
  assert.equal(keyed.get('m/atrium').version, '0.4.199');
  assert.equal(keyed.get('m/atrium').installs.length, 2);
  const single = keyManifestEntries([
    { configDir: '/h/.claude', marketplace: 'm', plugin: 'docs', version: '2', manifest: {} },
    { configDir: '/h/.claude-work', marketplace: 'm', plugin: 'docs', version: '3', manifest: {} },
  ]);
  assert.deepEqual([...single.keys()], ['docs']);
  assert.equal(single.get('docs').version, '3');
});

test('(k) the prompt names the exact plugin keys the answer must use', () => {
  const gathered = {
    manifests: { status: 'ok', entries: [
      { configDir: '/h/.claude', marketplace: 'm', plugin: 'atrium', version: '1', manifest: { plugin: 'atrium' } },
      { configDir: '/h/.claude', marketplace: 'm', plugin: 'docs', version: '1', manifest: { plugin: 'docs' } },
    ] },
    changelog: { status: 'ok', blocks: [] }, docsChanged: { status: 'ok', added: [], changed: [], removed: [] },
    sdk: { status: 'ok', latest: '0.3.261' }, types: { status: 'unavailable', reason: 'x' },
    claudeVersion: { status: 'ok', value: '9.9.9' }, previousVersion: { status: 'ok', value: null },
  };
  const prompt = buildPrompt(gathered);
  assert.match(prompt, /EXACTLY these keys[^\n]*"atrium"[^\n]*"docs"/);
});

test('(l) analyze passes the section-matching rule in the system prompt', async () => {
  let seen = null;
  const fakeQuery = (params) => { seen = params; return (async function* () { yield { type: 'result', subtype: 'success', result: JSON.stringify({ version: '9.9.9', from: null, plugins: {}, summary: 's' }) }; })(); };
  const gathered = { manifests: { status: 'ok', entries: [] }, changelog: { status: 'ok', blocks: [] }, docsChanged: { status: 'ok', added: [], changed: [], removed: [] }, sdk: { status: 'ok', latest: '0' }, types: { status: 'unavailable', reason: 'x' }, claudeVersion: { status: 'ok', value: '9.9.9' }, previousVersion: { status: 'ok', value: null } };
  await analyze(gathered, { query: fakeQuery, now: () => new Date() });
  assert.match(seen.options.systemPrompt, /CLI flag concerns only a plugin whose manifest lists that command under `cli`/);
});

test('(m) usage of the single SDK call is recorded next to the result', async () => {
  const fakeQuery = () => (async function* () {
    yield { type: 'result', subtype: 'success', result: JSON.stringify({ version: '9.9.9', from: null, plugins: {}, summary: 's' }),
      usage: { input_tokens: 11000, output_tokens: 900, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 }, total_cost_usd: 0.05, duration_ms: 1234, num_turns: 1 };
  })();
  const gathered = { manifests: { status: 'ok', entries: [] }, changelog: { status: 'ok', blocks: [] }, docsChanged: { status: 'ok', added: [], changed: [], removed: [] }, sdk: { status: 'ok', latest: '0' }, types: { status: 'unavailable', reason: 'x' }, claudeVersion: { status: 'ok', value: '9.9.9' }, previousVersion: { status: 'ok', value: null } };
  const out = await analyze(gathered, { query: fakeQuery, now: () => new Date() });
  assert.equal(out.usage.inputTokens, 11000);
  assert.equal(out.usage.outputTokens, 900);
  assert.equal(out.usage.totalCostUsd, 0.05);
  assert.ok(out.usage.promptChars > 0);
});

test('(n) the system prompt asks to surface an SDK version gap as couldServe', async () => {
  let seen = null;
  const fakeQuery = (params) => { seen = params; return (async function* () { yield { type: 'result', subtype: 'success', result: JSON.stringify({ version: '9.9.9', from: null, plugins: {}, summary: 's' }) }; })(); };
  const gathered = { manifests: { status: 'ok', entries: [] }, changelog: { status: 'ok', blocks: [] }, docsChanged: { status: 'ok', added: [], changed: [], removed: [] }, sdk: { status: 'ok', latest: '0' }, types: { status: 'unavailable', reason: 'x' }, claudeVersion: { status: 'ok', value: '9.9.9' }, previousVersion: { status: 'ok', value: null } };
  await analyze(gathered, { query: fakeQuery, now: () => new Date() });
  assert.match(seen.options.systemPrompt, /newer than the version a plugin declares under sdk\.version, list that gap under couldServe/);
});
