#!/usr/bin/env node
import { parseArgs } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { buildIndex, readVersionMarker } from '../src/index.mjs';
import { createEmbedder } from '../src/embed.mjs';
import { loadAssetVectors } from '../src/asset.mjs';

const { values } = parseArgs({
  options: {
    home: { type: 'string' },
    docs: { type: 'string' },
    json: { type: 'boolean', default: false },
  },
});

const home = values.home ?? os.homedir();
const docsDir = values.docs ?? path.join(home, '.claude-code-docs');
const embed = createEmbedder({ home });

// Try the pre-computed, CI-built vectors first (cached after the first
// lookup for this docs version; never throws, degrades to embedding
// locally on any cache-miss/network/decode failure). This is what turns the
// very first `search` call from a ~20-minute cold embed into a download.
const version = await readVersionMarker(docsDir);
const asset = await loadAssetVectors({ home, version });

const t0 = Date.now();
const stats = await buildIndex({ home, docsDir, embed, assetVectors: asset.map });
const tookMs = Date.now() - t0;

if (values.json) {
  console.log(JSON.stringify({ ...stats, tookMs, assetSource: asset.source, assetReason: asset.reason }));
} else {
  const kind = stats.fullRebuild ? 'full rebuild' : 'incremental update';
  const assetNote = asset.source ? ` (${stats.fromAsset} from the ${asset.source}d embeddings asset)` : '';
  console.log(
    `${kind}: ${stats.pages} pages / ${stats.chunks} chunks (${stats.embedded} embedded locally${assetNote}) in ${tookMs}ms -> ${stats.dbPath}`,
  );
}
