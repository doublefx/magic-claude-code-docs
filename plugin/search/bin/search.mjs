#!/usr/bin/env node
import { parseArgs } from 'node:util';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { search } from '../src/search.mjs';
import { buildIndex } from '../src/index.mjs';
import { createEmbedder } from '../src/embed.mjs';

if (process.env.MAGIC_CLAUDE_DOCS_SEARCH === 'off') {
  console.log('semantic search disabled');
  process.exit(0);
}

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    home: { type: 'string' },
    docs: { type: 'string' },
    mode: { type: 'string', default: 'fusion' },
    json: { type: 'boolean', default: false },
    top: { type: 'string', default: '8' },
  },
});

const home = values.home ?? os.homedir();
const docsDir = values.docs ?? path.join(home, '.claude-code-docs');
const query = positionals.join(' ').trim();

if (!query) {
  console.error('usage: search.mjs [--home <dir>] [--docs <dir>] [--mode fts|vector|fusion] [--top N] [--json] <question>');
  process.exit(1);
}

const embed = createEmbedder({ home });
const dbPath = path.join(docsDir, 'index', 'docs.sqlite');
if (!fs.existsSync(dbPath)) {
  console.error('Building the search index (first use) — this takes a few seconds and downloads a small model once.');
  await buildIndex({ home, docsDir, embed });
}

const results = await search({ home, docsDir, query, mode: values.mode, embed, topK: Number(values.top) });

if (values.json) {
  console.log(JSON.stringify(results, null, 2));
} else if (results.disabled) {
  console.log(results.message);
} else if (results.length === 0) {
  console.log('No results.');
} else {
  for (const r of results) {
    const heading = r.heading ? ` > ${r.heading}` : '';
    console.log(`- ${r.page}${heading}  (score ${r.score.toFixed(4)})`);
    console.log(`  ${r.excerpt}`);
  }
}
