import { createHash } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { chunkPage } from './chunk.mjs';
import { openDb, floatsToBlob } from './db.mjs';

async function readVersionMarker(docsDir) {
  const markerPath = path.join(docsDir, '.magic-claude-docs-plugin');
  try {
    return (await fsp.readFile(markerPath, 'utf8')).trim();
  } catch {
    return '';
  }
}

function loadPreviousChunks(db, name) {
  const rows = db.prepare('SELECT id, ord, hash FROM chunks WHERE page = ?').all(name);
  const map = new Map();
  for (const r of rows) map.set(Number(r.ord), { id: Number(r.id), hash: r.hash });
  return map;
}

// Chunk + diff + write one page. `previousChunks` is a Map<ord, {id, hash}>
// from the existing db (null for a fresh/full build). Verifies, after every
// write, that the row count for this page matches what was intended — a
// write that silently inserts nothing must fail loudly here, never read back
// as a quiet success.
async function upsertPage(db, docsDir, name, meta, embed, previousChunks) {
  const content = await fsp.readFile(path.join(docsDir, name), 'utf8');
  const chunks = chunkPage(content);

  const insertChunk = db.prepare(
    'INSERT INTO chunks (page, ord, heading, hash, text, embedding) VALUES (?, ?, ?, ?, ?, ?)',
  );
  const updateChunk = db.prepare('UPDATE chunks SET heading = ?, hash = ?, text = ?, embedding = ? WHERE id = ?');
  const setEmbedding = db.prepare('UPDATE chunks SET embedding = ? WHERE id = ?');
  const insertFts = db.prepare('INSERT INTO chunks_fts (rowid, text) VALUES (?, ?)');
  const updateFts = db.prepare('UPDATE chunks_fts SET text = ? WHERE rowid = ?');
  const deleteChunk = db.prepare('DELETE FROM chunks WHERE id = ?');
  const deleteFts = db.prepare('DELETE FROM chunks_fts WHERE rowid = ?');

  const needingEmbed = []; // { id, text }

  for (const chunk of chunks) {
    const prev = previousChunks?.get(chunk.ord);
    if (prev && prev.hash === chunk.hash) {
      continue; // unchanged chunk: no write, no re-embed
    }
    if (prev) {
      updateChunk.run(chunk.headingPath, chunk.hash, chunk.text, null, prev.id);
      updateFts.run(chunk.text, prev.id);
      needingEmbed.push({ id: prev.id, text: chunk.text });
    } else {
      const info = insertChunk.run(name, chunk.ord, chunk.headingPath, chunk.hash, chunk.text, null);
      const id = Number(info.lastInsertRowid);
      insertFts.run(id, chunk.text);
      needingEmbed.push({ id, text: chunk.text });
    }
  }

  if (previousChunks) {
    const newOrds = new Set(chunks.map((c) => c.ord));
    for (const [ord, info] of previousChunks) {
      if (!newOrds.has(ord)) {
        deleteChunk.run(info.id);
        deleteFts.run(info.id);
      }
    }
  }

  let embedded = 0;
  if (needingEmbed.length > 0) {
    const vectors = await embed(needingEmbed.map((r) => r.text));
    needingEmbed.forEach((r, i) => {
      setEmbedding.run(floatsToBlob(vectors[i]), r.id);
      embedded += 1;
    });
  }

  db.prepare(
    `INSERT INTO pages (name, hash, title) VALUES (?, ?, ?)
     ON CONFLICT(name) DO UPDATE SET hash = excluded.hash, title = excluded.title`,
  ).run(name, meta.hash ?? '', meta.title ?? null);

  const actualCount = db.prepare('SELECT COUNT(*) AS c FROM chunks WHERE page = ?').get(name).c;
  if (actualCount !== chunks.length) {
    throw new Error(
      `row count mismatch for page "${name}": expected ${chunks.length} chunks after write, found ${actualCount}`,
    );
  }
  const ftsCount = db
    .prepare('SELECT COUNT(*) AS c FROM chunks_fts WHERE rowid IN (SELECT id FROM chunks WHERE page = ?)')
    .get(name).c;
  if (ftsCount !== chunks.length) {
    throw new Error(
      `FTS row count mismatch for page "${name}": expected ${chunks.length}, found ${ftsCount}`,
    );
  }

  return { chunkCount: chunks.length, embedded };
}

function mdPages(files) {
  return Object.entries(files).filter(([name]) => name.endsWith('.md'));
}

async function populateAll(db, docsDir, files, embed) {
  let chunks = 0;
  let embedded = 0;
  let pages = 0;
  for (const [name, meta] of mdPages(files)) {
    pages += 1;
    const result = await upsertPage(db, docsDir, name, meta, embed, null);
    chunks += result.chunkCount;
    embedded += result.embedded;
  }
  return { pages, chunks, embedded };
}

async function incrementalUpdate(db, docsDir, files, embed) {
  const existing = db.prepare('SELECT name, hash FROM pages').all();
  const existingByName = new Map(existing.map((p) => [p.name, p.hash]));
  const manifestNames = new Set(mdPages(files).map(([name]) => name));

  let chunks = 0;
  let embedded = 0;
  let pages = 0;

  for (const [name, meta] of mdPages(files)) {
    pages += 1;
    if (existingByName.get(name) === meta.hash) {
      chunks += db.prepare('SELECT COUNT(*) AS c FROM chunks WHERE page = ?').get(name).c;
      continue; // page unchanged per manifest hash: skip entirely
    }
    const previousChunks = loadPreviousChunks(db, name);
    const result = await upsertPage(db, docsDir, name, meta, embed, previousChunks);
    chunks += result.chunkCount;
    embedded += result.embedded;
  }

  for (const name of existingByName.keys()) {
    if (manifestNames.has(name)) continue;
    const ids = db.prepare('SELECT id FROM chunks WHERE page = ?').all(name).map((r) => r.id);
    for (const id of ids) {
      db.prepare('DELETE FROM chunks WHERE id = ?').run(id);
      db.prepare('DELETE FROM chunks_fts WHERE rowid = ?').run(id);
    }
    db.prepare('DELETE FROM pages WHERE name = ?').run(name);
  }

  return { pages, chunks, embedded };
}

/**
 * Build or incrementally update the search index for the docs mirror at
 * `docsDir` (default `<home>/.claude-code-docs`).
 *
 * Incremental by default: a page whose manifest SHA-256 hasn't changed is
 * skipped entirely; within a changed page, only chunks whose own hash
 * changed are re-embedded. A rebuild is instead done FULLY, into a temp file
 * that is atomically renamed over the live index, whenever the mirror's
 * plugin-version marker (`.magic-claude-docs-plugin`) differs from the
 * version recorded in the index's own `meta` table (or the index doesn't
 * exist yet) — this guards against partial-migration drift across plugin
 * versions rather than trusting per-page hashes across a version bump.
 *
 * `embed(texts: string[]) => Promise<Float32Array[]>` is the only required
 * injection seam; `openDbFn` (default: `openDb` from ./db.mjs) exists so
 * tests can wrap the real db and simulate a write that silently inserts
 * nothing, proving the row-count check actually fires.
 */
export async function buildIndex({ home, docsDir, embed, openDbFn = openDb } = {}) {
  if (!embed) throw new Error('buildIndex requires an embed(texts) function');
  const resolvedDocsDir = docsDir ?? path.join(home, '.claude-code-docs');
  const manifestPath = path.join(resolvedDocsDir, 'docs_manifest.json');
  const manifest = JSON.parse(await fsp.readFile(manifestPath, 'utf8'));
  const files = manifest.files ?? manifest;

  const indexDir = path.join(resolvedDocsDir, 'index');
  await fsp.mkdir(indexDir, { recursive: true });
  const dbPath = path.join(indexDir, 'docs.sqlite');
  const version = await readVersionMarker(resolvedDocsDir);

  let db;
  let fullRebuild = !fs.existsSync(dbPath);
  if (!fullRebuild) {
    db = openDbFn(dbPath);
    const row = db.prepare('SELECT value FROM meta WHERE key = ?').get('pluginVersion');
    if (!row || row.value !== version) fullRebuild = true;
  }

  if (fullRebuild) {
    if (db) db.close();
    const tmpPath = path.join(indexDir, `docs.sqlite.tmp-${process.pid}-${createHash('md5').update(String(Date.now())).digest('hex').slice(0, 8)}`);
    await fsp.rm(tmpPath, { force: true });
    db = openDbFn(tmpPath);
    const stats = await populateAll(db, resolvedDocsDir, files, embed);
    db.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)').run('pluginVersion', version);
    db.close();
    await fsp.rename(tmpPath, dbPath);
    return { ...stats, dbPath, fullRebuild: true };
  }

  const stats = await incrementalUpdate(db, resolvedDocsDir, files, embed);
  db.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)').run('pluginVersion', version);
  db.close();
  return { ...stats, dbPath, fullRebuild: false };
}
