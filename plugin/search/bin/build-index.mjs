#!/usr/bin/env node
import { parseArgs } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { buildIndex } from '../src/index.mjs';
import { createEmbedder } from '../src/embed.mjs';

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

const t0 = Date.now();
const stats = await buildIndex({ home, docsDir, embed });
const tookMs = Date.now() - t0;

if (values.json) {
  console.log(JSON.stringify({ ...stats, tookMs }));
} else {
  const kind = stats.fullRebuild ? 'full rebuild' : 'incremental update';
  console.log(
    `${kind}: ${stats.pages} pages / ${stats.chunks} chunks (${stats.embedded} embedded) in ${tookMs}ms -> ${stats.dbPath}`,
  );
}
