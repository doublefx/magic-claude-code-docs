import { DatabaseSync } from 'node:sqlite';

// Schema:
//   pages(name PK, hash, title)               — one row per mirrored doc page
//   chunks(id, page, ord, heading, hash, text, embedding BLOB)
//   chunks_fts(text)                          — FTS5, NOT external-content
//
// chunks_fts is a plain (non `content=`) FTS5 table that duplicates the chunk
// text rather than referencing `chunks` as external content. That doubles
// text storage, which is negligible at this corpus size (a few thousand
// short chunks), and in exchange the incremental indexer keeps it in sync
// with explicit INSERT/UPDATE/DELETE statements keyed on `chunks.id` used as
// the FTS5 rowid — no triggers, no external-content bookkeeping to get
// wrong.
const SCHEMA = `
  CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
  );
  CREATE TABLE IF NOT EXISTS pages (
    name TEXT PRIMARY KEY,
    hash TEXT NOT NULL,
    title TEXT
  );
  CREATE TABLE IF NOT EXISTS chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page TEXT NOT NULL,
    ord INTEGER NOT NULL,
    heading TEXT,
    hash TEXT NOT NULL,
    text TEXT NOT NULL,
    embedding BLOB
  );
  CREATE INDEX IF NOT EXISTS idx_chunks_page ON chunks(page);
  CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    text, tokenize = 'porter unicode61'
  );
`;

export function openDb(path) {
  const db = new DatabaseSync(path);
  db.exec(SCHEMA);
  return db;
}

export function floatsToBlob(floats) {
  const f32 = Float32Array.from(floats);
  return Buffer.from(f32.buffer, f32.byteOffset, f32.byteLength);
}

export function blobToFloats(blob) {
  // node:sqlite returns BLOB columns as Uint8Array.
  const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
  const copy = Buffer.from(buf); // ensure a byte-aligned, standalone backing buffer
  return new Float32Array(copy.buffer, copy.byteOffset, copy.byteLength / 4);
}
