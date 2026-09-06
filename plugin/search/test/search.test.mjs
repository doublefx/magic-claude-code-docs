import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { search } from '../src/search.mjs';
import { buildIndex } from '../src/index.mjs';
import { makeFakeEmbed } from './helpers/fakeEmbed.mjs';

async function writeCorpus(files) {
  const home = await mkdtemp(path.join(tmpdir(), 'search-query-home-'));
  const docsDir = path.join(home, '.claude-code-docs');
  await mkdir(docsDir, { recursive: true });
  const manifestFiles = {};
  for (const [name, content] of Object.entries(files)) {
    await writeFile(path.join(docsDir, name), content);
    manifestFiles[name] = { title: name, hash: `hash-${name}` };
  }
  await writeFile(path.join(docsDir, 'docs_manifest.json'), JSON.stringify({ files: manifestFiles }));
  return { home, docsDir };
}

test('(d) fts mode finds an exact term', async () => {
  const { home, docsDir } = await writeCorpus({
    'plugins.md': '# Plugins\n\n## Environment variables\n\nA plugin reads CLAUDE_PLUGIN_ROOT to find its own directory.\n',
    'unrelated.md': '# Unrelated\n\nThis page is about something else entirely, like gardening.\n',
  });
  try {
    await buildIndex({ home, docsDir, embed: makeFakeEmbed() });
    const results = await search({ home, docsDir, query: 'CLAUDE_PLUGIN_ROOT', mode: 'fts' });
    assert.ok(results.length > 0);
    assert.equal(results[0].page, 'plugins.md');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('(e) vector mode ranks a paraphrase above an unrelated page', async () => {
  // Query and target share NO literal words (verified below); the fake
  // embedder maps "stop"->"cancel", "hook"->"action", "blocking"->"refusing",
  // "command"->"call" to a shared canonical token, which is what makes the
  // paraphrase resolve to the right page under cosine similarity — a
  // stand-in for a real embedding model recognising the words are synonyms.
  const target = 'A PreToolUse action can cancel a tool call before it runs, refusing execution.';
  const unrelated = 'Install pnpm globally using the corepack command.';
  const query = 'how do I stop a hook from blocking a command';

  const stopwords = new Set(['a', 'the', 'do', 'i', 'from', 'before', 'it']);
  const meaningful = (s) => new Set([...s.toLowerCase().match(/[a-z0-9]+/g)].filter((w) => !stopwords.has(w)));
  const queryWords = meaningful(query);
  const targetWords = meaningful(target);
  assert.equal([...queryWords].filter((w) => targetWords.has(w)).length, 0, 'test setup must be a genuine paraphrase, not a keyword match');

  const { home, docsDir } = await writeCorpus({
    'a.md': `# A\n\n${target}\n`,
    'b.md': `# B\n\n${unrelated}\n`,
  });
  try {
    const synonyms = { stop: 'cancel', hook: 'action', blocking: 'refusing', command: 'call' };
    const embed = makeFakeEmbed({ synonyms });
    await buildIndex({ home, docsDir, embed });

    const results = await search({ home, docsDir, query, mode: 'vector', embed, topK: 2 });
    assert.equal(results[0].page, 'a.md');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('(f) fusion returns at most 8 results, each with page + excerpt', async () => {
  const files = {};
  for (let i = 0; i < 12; i++) {
    files[`page-${i}.md`] = `# Page ${i}\n\n## Section\n\nThis page talks about hooks and blocking behaviour, item ${i}.\n`;
  }
  const { home, docsDir } = await writeCorpus(files);
  try {
    const embed = makeFakeEmbed();
    await buildIndex({ home, docsDir, embed });
    const results = await search({ home, docsDir, query: 'hooks blocking behaviour', mode: 'fusion', embed });
    assert.ok(results.length <= 8);
    assert.ok(results.length > 0);
    for (const r of results) {
      assert.equal(typeof r.page, 'string');
      assert.equal(typeof r.excerpt, 'string');
      assert.ok('heading' in r);
      assert.equal(typeof r.score, 'number');
    }
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('(g) kill switch: MAGIC_CLAUDE_DOCS_SEARCH=off short-circuits with no query run', async () => {
  const { home, docsDir } = await writeCorpus({ 'a.md': '# A\n\nsome content\n' });
  const prev = process.env.MAGIC_CLAUDE_DOCS_SEARCH;
  process.env.MAGIC_CLAUDE_DOCS_SEARCH = 'off';
  try {
    // Note: no buildIndex() call at all — if the kill switch didn't
    // short-circuit before opening the (non-existent) db, this would throw.
    const result = await search({ home, docsDir, query: 'anything', mode: 'fusion' });
    assert.equal(result.disabled, true);
    assert.equal(result.message, 'semantic search disabled');
  } finally {
    if (prev === undefined) delete process.env.MAGIC_CLAUDE_DOCS_SEARCH;
    else process.env.MAGIC_CLAUDE_DOCS_SEARCH = prev;
    await rm(home, { recursive: true, force: true });
  }
});
