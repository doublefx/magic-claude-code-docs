import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, cp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildIndex } from '../src/index.mjs';
import { openDb } from '../src/db.mjs';
import { chunkPage } from '../src/chunk.mjs';
import { makeFakeEmbed } from './helpers/fakeEmbed.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DOCS = path.join(__dirname, 'fixtures', 'docs');

async function freshDocsHome() {
  const home = await mkdtemp(path.join(tmpdir(), 'search-home-'));
  const docsDir = path.join(home, '.claude-code-docs');
  await cp(FIXTURE_DOCS, docsDir, { recursive: true });
  return { home, docsDir };
}

async function expectedTotalChunks(docsDir) {
  const manifest = JSON.parse(await readFile(path.join(docsDir, 'docs_manifest.json'), 'utf8'));
  let total = 0;
  for (const name of Object.keys(manifest.files)) {
    const content = await readFile(path.join(docsDir, name), 'utf8');
    total += chunkPage(content).length;
  }
  return total;
}

test('(b) build index from fixtures — row counts equal chunks produced', async () => {
  const { home, docsDir } = await freshDocsHome();
  try {
    const embed = makeFakeEmbed();
    const expected = await expectedTotalChunks(docsDir);
    const stats = await buildIndex({ home, docsDir, embed });

    assert.equal(stats.pages, 5);
    assert.equal(stats.chunks, expected);
    assert.equal(stats.fullRebuild, true);

    const db = openDb(stats.dbPath);
    try {
      const chunkCount = db.prepare('SELECT COUNT(*) AS c FROM chunks').get().c;
      const ftsCount = db.prepare('SELECT COUNT(*) AS c FROM chunks_fts').get().c;
      const pageCount = db.prepare('SELECT COUNT(*) AS c FROM pages').get().c;
      assert.equal(chunkCount, expected);
      assert.equal(ftsCount, expected);
      assert.equal(pageCount, 5);
    } finally {
      db.close();
    }
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('(c) incremental — only a changed page is re-embedded, an unchanged page is skipped', async () => {
  const { home, docsDir } = await freshDocsHome();
  try {
    const firstEmbed = makeFakeEmbed();
    const firstStats = await buildIndex({ home, docsDir, embed: firstEmbed });
    assert.ok(firstStats.embedded > 0);

    // Change ONE page's content and bump its manifest hash, exactly like a
    // real `gather` run would after re-fetching a changed doc.
    const manifestPath = path.join(docsDir, 'docs_manifest.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    manifest.files['memory.md'].hash = 'hash-memory-v2';
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    await writeFile(
      path.join(docsDir, 'memory.md'),
      '# Memory\n\nClaude Code can remember facts across sessions using a memory file.\n\n## New section\n\nThis is brand new content that did not exist before.\n',
    );
    const expectedNewTotal = await expectedTotalChunks(docsDir);

    const secondEmbed = makeFakeEmbed();
    const secondStats = await buildIndex({ home, docsDir, embed: secondEmbed });

    assert.equal(secondStats.fullRebuild, false);
    assert.equal(secondStats.chunks, expectedNewTotal);
    // Exactly ONE chunk was sent for re-embedding: the new "New section"
    // chunk. memory.md's unchanged first chunk (same heading, same body)
    // must be skipped by its own chunk hash even though its page hash
    // changed; every OTHER page must be skipped entirely by the page hash.
    const embeddedTexts = secondEmbed.calls.flat();
    assert.equal(embeddedTexts.length, 1);
    assert.match(embeddedTexts[0], /New section/);
    assert.equal(secondStats.embedded, 1);

    const db = openDb(secondStats.dbPath);
    try {
      const hooksCount = db.prepare('SELECT COUNT(*) AS c FROM chunks WHERE page = ?').get('hooks.md').c;
      const memoryCount = db.prepare('SELECT COUNT(*) AS c FROM chunks WHERE page = ?').get('memory.md').c;
      assert.ok(hooksCount > 0, 'unrelated page must be untouched, not deleted');
      assert.ok(memoryCount > 0);
    } finally {
      db.close();
    }
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('(c2) incremental — a page removed from the manifest has its chunks and page row deleted', async () => {
  const { home, docsDir } = await freshDocsHome();
  try {
    await buildIndex({ home, docsDir, embed: makeFakeEmbed() });

    const manifestPath = path.join(docsDir, 'docs_manifest.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    delete manifest.files['settings.md'];
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    await rm(path.join(docsDir, 'settings.md'));

    const stats = await buildIndex({ home, docsDir, embed: makeFakeEmbed() });
    assert.equal(stats.pages, 4);

    const db = openDb(stats.dbPath);
    try {
      const chunkCount = db.prepare('SELECT COUNT(*) AS c FROM chunks WHERE page = ?').get('settings.md').c;
      const pageRow = db.prepare('SELECT * FROM pages WHERE name = ?').get('settings.md');
      assert.equal(chunkCount, 0);
      assert.equal(pageRow, undefined);
    } finally {
      db.close();
    }
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('(h) a write that silently inserts nothing fails loudly via the row-count check', async () => {
  const { home, docsDir } = await freshDocsHome();
  try {
    function brokenOpenDb(dbPath) {
      const real = openDb(dbPath);
      const originalPrepare = real.prepare.bind(real);
      real.prepare = (sql) => {
        const stmt = originalPrepare(sql);
        if (sql.startsWith('INSERT INTO chunks ')) {
          // Reports a plausible success without actually inserting anything —
          // exactly the "success that wrote nothing" failure the row-count
          // check exists to catch.
          let fakeId = 1_000_000;
          return {
            run: () => ({ changes: 1, lastInsertRowid: fakeId++ }),
            get: stmt.get.bind(stmt),
            all: stmt.all.bind(stmt),
          };
        }
        return stmt;
      };
      return real;
    }

    await assert.rejects(
      () => buildIndex({ home, docsDir, embed: makeFakeEmbed(), openDbFn: brokenOpenDb }),
      /row count mismatch/,
    );
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
