import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';

// A compact binary asset carrying one embedding vector per chunk content
// hash, keyed by the SAME hash `src/chunk.mjs` already computes
// (content-derived, deterministic) — never by page/ord, which drift across
// re-chunking. Format:
//
//   "MCDE" (4 bytes) | version (1 byte) | count (uint32 LE) | dims (uint16 LE)
//   then `count` records of: 32-byte hash (the full sha256 digest, NOT a
//   truncated prefix — chunk.mjs already produces exactly 32 bytes once the
//   64-hex-char string is decoded, so there is nothing to truncate) +
//   `dims` little-endian float32 values.
//
// A sibling embeddings.json carries { model, dims, count, docsVersion,
// builtAt } for humans and for CI logs; the binary alone is authoritative
// for `loadAssetVectors`.
const MAGIC = Buffer.from('MCDE', 'ascii');
const VERSION = 1;
const HASH_BYTES = 32;
const HEADER_BYTES = MAGIC.length + 1 + 4 + 2; // 11

/**
 * encodeAsset(map, meta) -> { bin: Buffer, json: string }
 * `map` is a Map<hashHex, Float32Array|number[]> (or a plain object with the
 * same shape). `meta` carries { model, dims, docsVersion?, builtAt? }; `dims`
 * is required and every vector must have exactly that length.
 */
export function encodeAsset(map, meta) {
  if (!meta || typeof meta.dims !== 'number') {
    throw new Error('encodeAsset requires meta.dims');
  }
  const dims = meta.dims;
  const entries = map instanceof Map ? [...map.entries()] : Object.entries(map);
  const count = entries.length;

  const header = Buffer.alloc(HEADER_BYTES);
  let off = 0;
  MAGIC.copy(header, off);
  off += MAGIC.length;
  header.writeUInt8(VERSION, off);
  off += 1;
  header.writeUInt32LE(count, off);
  off += 4;
  header.writeUInt16LE(dims, off);

  const recordSize = HASH_BYTES + dims * 4;
  const body = Buffer.alloc(recordSize * count);
  entries.forEach(([hashHex, vec], i) => {
    const rOff = i * recordSize;
    const hashBuf = Buffer.from(hashHex, 'hex');
    if (hashBuf.length !== HASH_BYTES) {
      throw new Error(`encodeAsset: hash "${hashHex}" decodes to ${hashBuf.length} bytes, expected ${HASH_BYTES}`);
    }
    hashBuf.copy(body, rOff);
    const f32 = Float32Array.from(vec);
    if (f32.length !== dims) {
      throw new Error(`encodeAsset: vector for "${hashHex}" has ${f32.length} dims, expected ${dims}`);
    }
    Buffer.from(f32.buffer, f32.byteOffset, f32.byteLength).copy(body, rOff + HASH_BYTES);
  });

  const bin = Buffer.concat([header, body]);
  const json = JSON.stringify(
    {
      model: meta.model ?? null,
      dims,
      count,
      docsVersion: meta.docsVersion ?? null,
      builtAt: meta.builtAt ?? new Date().toISOString(),
    },
    null,
    2,
  );
  return { bin, json };
}

/**
 * decodeAsset(buffer) -> { map: Map<hashHex, Float32Array>, dims, count }
 * Never returns a partially-decoded result: a bad magic, an unsupported
 * version, or a length mismatch all throw rather than silently truncating.
 */
export function decodeAsset(buffer) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  if (buf.length < HEADER_BYTES || !buf.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('decodeAsset: bad magic — not an embeddings.bin asset');
  }
  const version = buf.readUInt8(MAGIC.length);
  if (version !== VERSION) {
    throw new Error(`decodeAsset: unsupported asset version ${version}`);
  }
  const count = buf.readUInt32LE(MAGIC.length + 1);
  const dims = buf.readUInt16LE(MAGIC.length + 1 + 4);
  const recordSize = HASH_BYTES + dims * 4;
  const expectedLen = HEADER_BYTES + recordSize * count;
  if (buf.length !== expectedLen) {
    throw new Error(`decodeAsset: length mismatch — expected ${expectedLen} bytes for ${count} x ${dims}d records, got ${buf.length}`);
  }

  const map = new Map();
  for (let i = 0; i < count; i += 1) {
    const rOff = HEADER_BYTES + i * recordSize;
    const hashHex = buf.subarray(rOff, rOff + HASH_BYTES).toString('hex');
    // Copy into a fresh, byte-aligned buffer before viewing as Float32Array —
    // the source buffer's offset is not guaranteed to be a multiple of 4.
    const copy = Buffer.from(buf.subarray(rOff + HASH_BYTES, rOff + recordSize));
    const vec = new Float32Array(copy.buffer, copy.byteOffset, dims);
    map.set(hashHex, vec);
  }
  return { map, dims, count };
}

/**
 * loadAssetVectors({ home, version, fetch, timeoutMs }) -> Promise<{ map, dims, reason, source }>
 *
 * Never throws. Resolution order:
 *   1. a cached copy at <home>/.claude-code-docs/index/assets/<version>/embeddings.bin
 *   2. a download from the plugin's GitHub release for that version, cached
 *      atomically (write to a temp file, rename over) for next time
 *   3. an empty map with a `reason` string — no cache, no network, or a
 *      decode failure all land here rather than propagating an exception,
 *      because a missing/broken asset must degrade to "embed locally", never
 *      abort the build.
 *
 * `fetch` is injectable (defaults to the global fetch) so tests never touch
 * the network.
 */
export async function loadAssetVectors({ home, version, fetch: fetchImpl = fetch, timeoutMs = 30_000 } = {}) {
  if (!version) {
    return { map: new Map(), dims: null, reason: 'no docs version given', source: null };
  }

  const cacheDir = path.join(home, '.claude-code-docs', 'index', 'assets', String(version));
  const cachePath = path.join(cacheDir, 'embeddings.bin');

  if (fs.existsSync(cachePath)) {
    try {
      const buf = await fsp.readFile(cachePath);
      const { map, dims } = decodeAsset(buf);
      return { map, dims, reason: null, source: 'cache' };
    } catch (err) {
      // Corrupt cache: fall through and try to re-download instead of
      // failing the whole build over a bad local file.
    }
  }

  const url = `https://github.com/doublefx/magic-claude-code-docs/releases/download/v${version}/embeddings.bin`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let res;
    try {
      res = await fetchImpl(url, { signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
    if (!res || !res.ok) {
      return { map: new Map(), dims: null, reason: `download failed: HTTP ${res ? res.status : 'no response'}`, source: null };
    }
    const arrBuf = await res.arrayBuffer();
    const buf = Buffer.from(arrBuf);
    const { map, dims } = decodeAsset(buf);

    await fsp.mkdir(cacheDir, { recursive: true });
    const tmpPath = path.join(cacheDir, `embeddings.bin.tmp-${process.pid}`);
    await fsp.writeFile(tmpPath, buf);
    await fsp.rename(tmpPath, cachePath);

    return { map, dims, reason: null, source: 'download' };
  } catch (err) {
    return { map: new Map(), dims: null, reason: `download failed: ${err.message}`, source: null };
  }
}
