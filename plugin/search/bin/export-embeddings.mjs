#!/usr/bin/env node
import { parseArgs } from 'node:util';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { chunkPage } from '../src/chunk.mjs';
import { createEmbedder } from '../src/embed.mjs';
import { encodeAsset, decodeAsset } from '../src/asset.mjs';
import { readVersionMarker } from '../src/index.mjs';

// A tiny, self-contained deterministic embedder for --fake dry runs (CI
// smoke tests, this package's own tests). Deliberately NOT the shared
// test/helpers/fakeEmbed.mjs: a production bin script must not depend on
// the test tree.
function makeFakeEmbed(dims) {
  function hashToken(str) {
    let h = 0;
    for (let i = 0; i < str.length; i += 1) h = (h * 31 + str.charCodeAt(i)) >>> 0;
    return h;
  }
  return async function embed(texts) {
    return texts.map((text) => {
      const vec = new Float32Array(dims);
      const tokens = text.toLowerCase().match(/[a-z0-9]+/g) || [];
      for (const tok of tokens) vec[hashToken(tok) % dims] += 1;
      let norm = 0;
      for (let i = 0; i < dims; i += 1) norm += vec[i] * vec[i];
      norm = Math.sqrt(norm) || 1;
      for (let i = 0; i < dims; i += 1) vec[i] /= norm;
      return vec;
    });
  };
}

const { values } = parseArgs({
  options: {
    home: { type: 'string' },
    docs: { type: 'string' },
    out: { type: 'string' },
    previous: { type: 'string' },
    version: { type: 'string' },
    fake: { type: 'boolean', default: false },
  },
});

if (!values.docs || !values.out) {
  console.error(
    'usage: export-embeddings.mjs --home <dir> --docs <dir> --out <dir> [--previous <embeddings.bin>] [--fake]',
  );
  process.exit(1);
}

const docsDir = values.docs;
const home = values.home ?? docsDir;
const outDir = values.out;

const manifestPath = path.join(docsDir, 'docs_manifest.json');
const manifest = JSON.parse(await fsp.readFile(manifestPath, 'utf8'));
const files = manifest.files ?? manifest;

// Build the full hash->text map for the mirror. Chunk identity is the
// content-derived hash `src/chunk.mjs` already computes — several chunks
// across pages can legitimately share one hash (identical text), and only
// need one embedding between them.
const hashToText = new Map();
let totalChunks = 0;
for (const name of Object.keys(files)) {
  if (!name.endsWith('.md')) continue;
  const content = await fsp.readFile(path.join(docsDir, name), 'utf8');
  for (const chunk of chunkPage(content)) {
    totalChunks += 1;
    if (!hashToText.has(chunk.hash)) hashToText.set(chunk.hash, chunk.text);
  }
}

let previousMap = new Map();
let previousDims = null;
if (values.previous) {
  const buf = await fsp.readFile(values.previous);
  const decoded = decodeAsset(buf);
  previousMap = decoded.map;
  previousDims = decoded.dims;
}

const reused = new Map();
const toEmbed = [];
for (const [hash, text] of hashToText) {
  const prevVector = previousMap.get(hash);
  if (prevVector) reused.set(hash, prevVector);
  else toEmbed.push([hash, text]);
}

const embed = values.fake ? makeFakeEmbed(previousDims ?? 32) : createEmbedder({ home });

const resultMap = new Map(reused);
let dims = previousDims;
const EMBED_BATCH = 64;
for (let i = 0; i < toEmbed.length; i += EMBED_BATCH) {
  const batch = toEmbed.slice(i, i + EMBED_BATCH);
  const vectors = await embed(batch.map(([, text]) => text));
  if (dims === null && vectors.length > 0) dims = vectors[0].length;
  batch.forEach(([hash], idx) => resultMap.set(hash, vectors[idx]));
}
if (dims === null) {
  // Degenerate case: no chunks at all, nothing decided a dimension. Fall
  // back rather than writing an asset with an undefined shape.
  dims = previousDims ?? 32;
}

// `--version` overrides the marker file for callers like the release
// workflow, whose checkout of `plugin/docs` never carries the
// `.magic-claude-docs-plugin` marker (that file is written only by the
// SessionStart sync hook, into `~/.claude-code-docs`, at runtime). Reading
// it here is the fallback for ad hoc/local runs against an already-synced
// docs mirror.
const version = values.version ?? (await readVersionMarker(docsDir));
const meta = {
  model: values.fake ? 'fake' : 'Xenova/all-MiniLM-L6-v2',
  dims,
  docsVersion: version || null,
  builtAt: new Date().toISOString(),
};

const { bin, json } = encodeAsset(resultMap, meta);
await fsp.mkdir(outDir, { recursive: true });
await fsp.writeFile(path.join(outDir, 'embeddings.bin'), bin);
await fsp.writeFile(path.join(outDir, 'embeddings.json'), json);

console.log(
  JSON.stringify({
    totalChunks,
    uniqueHashes: hashToText.size,
    reused: reused.size,
    embedded: toEmbed.length,
    dims,
    docsVersion: meta.docsVersion,
    out: outDir,
  }),
);
