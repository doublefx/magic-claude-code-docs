import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { markDelivered } from '../src/mark-delivered.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(__dirname, '..', 'bin', 'mark-delivered.mjs');

async function freshHomeWithDigest(record) {
  const home = await mkdtemp(path.join(tmpdir(), 'digest-mark-delivered-'));
  const digestsDir = path.join(home, '.claude-code-docs', 'digests');
  await mkdir(digestsDir, { recursive: true });
  const jsonPath = path.join(digestsDir, '3.0.0.json');
  await writeFile(jsonPath, JSON.stringify(record, null, 2) + '\n', 'utf8');
  return { home, jsonPath };
}

function sampleRecord() {
  return {
    result: { version: '3.0.0', from: '2.9.9', plugins: { a: { breaks: [], couldServe: [], noise: 1 } }, summary: 'x' },
    sources: { claudeVersion: { status: 'ok', value: '3.0.0' } },
    gatheredAt: '2026-09-05T00:00:00.000Z',
    analyzedAt: '2026-09-05T00:05:00.000Z',
    deliveredAt: null,
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

test('(a) sets deliveredAt and deliveryNote, rest of the record byte-preserved (parsed-equal)', async () => {
  const record = sampleRecord();
  const { home, jsonPath } = await freshHomeWithDigest(record);

  const outcome = await markDelivered({
    home,
    version: '3.0.0',
    note: 'posted to Atrium room harness-changes-digest',
    now: () => new Date('2026-09-05T12:00:00.000Z'),
  });

  assert.equal(outcome.alreadyDelivered, false);
  const onDisk = JSON.parse(await readFile(jsonPath, 'utf8'));
  assert.equal(onDisk.deliveredAt, '2026-09-05T12:00:00.000Z');
  assert.equal(onDisk.deliveryNote, 'posted to Atrium room harness-changes-digest');

  // Every other field is untouched.
  const { deliveredAt, deliveryNote, ...restOnDisk } = onDisk;
  const { deliveredAt: _origDeliveredAt, ...restOriginal } = record;
  assert.deepEqual(restOnDisk, restOriginal);
});

test('(b) idempotent: calling again on an already-delivered record is a no-op, note unchanged', async () => {
  const record = sampleRecord();
  record.deliveredAt = '2026-09-01T00:00:00.000Z';
  record.deliveryNote = 'first delivery note';
  const { home, jsonPath } = await freshHomeWithDigest(record);

  const outcome = await markDelivered({
    home,
    version: '3.0.0',
    note: 'a second, different note',
    now: () => new Date('2026-09-05T12:00:00.000Z'),
  });

  assert.equal(outcome.alreadyDelivered, true);
  const onDisk = JSON.parse(await readFile(jsonPath, 'utf8'));
  assert.equal(onDisk.deliveredAt, '2026-09-01T00:00:00.000Z');
  assert.equal(onDisk.deliveryNote, 'first delivery note');
});

test('(c) missing <version>.json throws with code MISSING', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'digest-mark-delivered-'));
  await assert.rejects(
    () => markDelivered({ home, version: '9.9.9', note: 'x' }),
    (e) => e.code === 'MISSING',
  );
});

test('(d) CLI: missing --version or --note -> exit 1', async () => {
  const { code, stderr } = await runBin(['--note', 'x']);
  assert.equal(code, 1);
  assert.match(stderr, /--version.*--note.*required/);
});

test('(e) CLI: missing digest file -> exit 2', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'digest-mark-delivered-'));
  const { code, stderr } = await runBin(['--home', home, '--version', '9.9.9', '--note', 'x']);
  assert.equal(code, 2);
  assert.match(stderr, /could not read/);
});

test('(f) CLI: happy path writes the file and prints its path', async () => {
  const record = sampleRecord();
  const { home, jsonPath } = await freshHomeWithDigest(record);
  const { code, stdout } = await runBin(['--home', home, '--version', '3.0.0', '--note', 'posted somewhere']);
  assert.equal(code, 0);
  assert.equal(stdout.trim(), jsonPath);
  const onDisk = JSON.parse(await readFile(jsonPath, 'utf8'));
  assert.equal(onDisk.deliveryNote, 'posted somewhere');
  assert.ok(onDisk.deliveredAt);
});
