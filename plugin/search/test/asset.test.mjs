import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { encodeAsset, decodeAsset, loadAssetVectors } from '../src/asset.mjs';

// Deterministic 64-hex-char stand-in for a real sha256 chunk hash — valid
// hex, decodes to exactly 32 bytes, which is all encodeAsset/decodeAsset
// care about.
function fakeHash(n) {
  return n.toString(16).padStart(64, '0');
}

async function freshHome() {
  return mkdtemp(path.join(tmpdir(), 'asset-home-'));
}

test('(a) encodeAsset/decodeAsset round trip preserves dims, count, and every vector', () => {
  const map = new Map([
    [fakeHash(1), new Float32Array([0.1, 0.2, 0.3])],
    [fakeHash(2), new Float32Array([0.4, 0.5, 0.6])],
  ]);
  const { bin, json } = encodeAsset(map, { model: 'fake', dims: 3, docsVersion: '2026.9.6.1' });
  const meta = JSON.parse(json);
  assert.equal(meta.model, 'fake');
  assert.equal(meta.dims, 3);
  assert.equal(meta.count, 2);
  assert.equal(meta.docsVersion, '2026.9.6.1');
  assert.ok(meta.builtAt);

  const decoded = decodeAsset(bin);
  assert.equal(decoded.dims, 3);
  assert.equal(decoded.count, 2);
  for (const [hash, vec] of map) {
    const got = decoded.map.get(hash);
    assert.ok(got, `hash ${hash} missing from decoded map`);
    assert.deepEqual(Array.from(got), Array.from(vec));
  }
});

test('(a2) decodeAsset rejects bad magic and a truncated buffer', () => {
  assert.throws(() => decodeAsset(Buffer.from('not an embeddings asset at all')), /magic/);

  const { bin } = encodeAsset(new Map([[fakeHash(1), new Float32Array([1, 2])]]), { model: 'fake', dims: 2 });
  assert.throws(() => decodeAsset(bin.subarray(0, bin.length - 1)), /length mismatch/);
});

test('(a3) encodeAsset rejects a vector with the wrong dimension', () => {
  assert.throws(
    () => encodeAsset(new Map([[fakeHash(1), new Float32Array([1, 2, 3])]]), { model: 'fake', dims: 2 }),
    /3 dims, expected 2/,
  );
});

test('(b) loadAssetVectors uses a cached copy and never calls fetch', async () => {
  const home = await freshHome();
  try {
    const version = '2026.9.6.1';
    const cacheDir = path.join(home, '.claude-code-docs', 'index', 'assets', version);
    await mkdir(cacheDir, { recursive: true });
    const map = new Map([[fakeHash(1), new Float32Array([1, 2])]]);
    const { bin } = encodeAsset(map, { model: 'fake', dims: 2 });
    await writeFile(path.join(cacheDir, 'embeddings.bin'), bin);

    let fetchCalls = 0;
    const fetch = async () => {
      fetchCalls += 1;
      throw new Error('must not be called when a cache hit exists');
    };

    const result = await loadAssetVectors({ home, version, fetch });
    assert.equal(fetchCalls, 0);
    assert.equal(result.source, 'cache');
    assert.equal(result.reason, null);
    assert.equal(result.map.size, 1);
    assert.deepEqual(Array.from(result.map.get(fakeHash(1))), [1, 2]);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('(c) loadAssetVectors downloads on a cache miss and caches the result for next time', async () => {
  const home = await freshHome();
  try {
    const version = '2026.9.6.2';
    const map = new Map([[fakeHash(1), new Float32Array([1, 2])]]);
    const { bin } = encodeAsset(map, { model: 'fake', dims: 2 });

    let fetchCalls = 0;
    const fetch = async (url) => {
      fetchCalls += 1;
      assert.match(url, new RegExp(`releases/download/v${version}/embeddings\\.bin$`));
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () => bin.buffer.slice(bin.byteOffset, bin.byteOffset + bin.byteLength),
      };
    };

    const first = await loadAssetVectors({ home, version, fetch });
    assert.equal(fetchCalls, 1);
    assert.equal(first.source, 'download');
    assert.equal(first.map.size, 1);

    const second = await loadAssetVectors({ home, version, fetch });
    assert.equal(fetchCalls, 1, 'second call must hit the cache written by the first, never fetch again');
    assert.equal(second.source, 'cache');
    assert.equal(second.map.size, 1);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('(d) loadAssetVectors returns an empty map with a reason on network failure or a non-OK response, never throws', async () => {
  const home = await freshHome();
  try {
    const throwing = async () => {
      throw new Error('network down');
    };
    const r1 = await loadAssetVectors({ home, version: '2026.9.6.3', fetch: throwing });
    assert.equal(r1.map.size, 0);
    assert.ok(r1.reason);

    const notOk = async () => ({ ok: false, status: 404 });
    const r2 = await loadAssetVectors({ home, version: '2026.9.6.4', fetch: notOk });
    assert.equal(r2.map.size, 0);
    assert.ok(r2.reason);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('(e) loadAssetVectors with no version returns an empty map without touching fetch', async () => {
  const home = await freshHome();
  try {
    let fetchCalls = 0;
    const fetch = async () => {
      fetchCalls += 1;
      return { ok: true, status: 200, arrayBuffer: async () => new ArrayBuffer(0) };
    };
    const result = await loadAssetVectors({ home, version: '', fetch });
    assert.equal(fetchCalls, 0);
    assert.equal(result.map.size, 0);
    assert.ok(result.reason);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
