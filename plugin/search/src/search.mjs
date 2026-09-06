import path from 'node:path';
import { openDb, blobToFloats } from './db.mjs';

const RRF_K = 60;
const DEFAULT_CANDIDATE_LIMIT = 50;

function buildFtsQuery(query) {
  const terms = query.toLowerCase().match(/[a-z0-9]+/g) || [];
  if (terms.length === 0) return null;
  // Quote every term and OR them together: robust against punctuation the
  // user's free-text question may contain that FTS5's own query syntax
  // would otherwise choke on (hyphens, colons, quotes, ...).
  return terms.map((t) => `"${t.replace(/"/g, '""')}"`).join(' OR ');
}

function ftsSearch(db, query, limit) {
  const ftsQuery = buildFtsQuery(query);
  if (!ftsQuery) return [];
  const rows = db
    .prepare('SELECT rowid AS id, bm25(chunks_fts) AS rank FROM chunks_fts WHERE chunks_fts MATCH ? ORDER BY rank LIMIT ?')
    .all(ftsQuery, limit);
  // FTS5 bm25() is a cost (lower = better); negate so higher = better,
  // matching the direction cosine similarity already uses.
  return rows.map((r) => ({ id: Number(r.id), score: -r.rank }));
}

function cosine(a, b) {
  let dot = 0;
  let na = 0;
  let nb = 0;
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

function vectorSearch(db, queryVec, limit) {
  const rows = db.prepare('SELECT id, embedding FROM chunks WHERE embedding IS NOT NULL').all();
  const scored = rows.map((r) => ({ id: Number(r.id), score: cosine(queryVec, blobToFloats(r.embedding)) }));
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit);
}

// Reciprocal Rank Fusion: each result list contributes 1/(k+rank) to any id
// it contains (rank is 1-indexed within that list); ids missing from a list
// simply don't get that list's contribution.
function rrfFuse(lists, k = RRF_K) {
  const scores = new Map();
  for (const list of lists) {
    list.forEach((item, idx) => {
      const prev = scores.get(item.id) ?? 0;
      scores.set(item.id, prev + 1 / (k + idx + 1));
    });
  }
  return [...scores.entries()].map(([id, score]) => ({ id, score })).sort((a, b) => b.score - a.score);
}

function excerpt(text, len = 200) {
  const clean = text.replace(/\s+/g, ' ').trim();
  return clean.length > len ? `${clean.slice(0, len)}…` : clean;
}

function formatResults(db, ranked, topK) {
  return ranked.slice(0, topK).map((r) => {
    const chunk = db.prepare('SELECT page, heading, text FROM chunks WHERE id = ?').get(r.id);
    return {
      page: chunk.page,
      heading: chunk.heading || null,
      score: r.score,
      excerpt: excerpt(chunk.text),
    };
  });
}

/**
 * Query the search index. `mode` is one of 'fts' | 'vector' | 'fusion'
 * (default 'fusion'). `embed` is required for 'vector' and 'fusion'.
 * Returns [] rather than throwing when the index has no matching rows.
 * Honours the MAGIC_CLAUDE_DOCS_SEARCH=off kill switch by returning
 * `{ disabled: true, message }` instead of running any query.
 */
export async function search({ home, docsDir, query, mode = 'fusion', embed, topK = 8, candidateLimit = DEFAULT_CANDIDATE_LIMIT }) {
  if (process.env.MAGIC_CLAUDE_DOCS_SEARCH === 'off') {
    return { disabled: true, message: 'semantic search disabled' };
  }
  if (!query || !query.trim()) return [];
  const resolvedDocsDir = docsDir ?? path.join(home, '.claude-code-docs');
  const dbPath = path.join(resolvedDocsDir, 'index', 'docs.sqlite');
  const db = openDb(dbPath);
  try {
    if (mode === 'fts') {
      return formatResults(db, ftsSearch(db, query, candidateLimit), topK);
    }
    if (mode === 'vector') {
      if (!embed) throw new Error('search mode "vector" requires an embed(texts) function');
      const [queryVec] = await embed([query]);
      return formatResults(db, vectorSearch(db, queryVec, candidateLimit), topK);
    }
    if (mode !== 'fusion') throw new Error(`unknown search mode: ${mode}`);
    if (!embed) throw new Error('search mode "fusion" requires an embed(texts) function');
    const ftsRanked = ftsSearch(db, query, candidateLimit);
    const [queryVec] = await embed([query]);
    const vectorRanked = vectorSearch(db, queryVec, candidateLimit);
    return formatResults(db, rrfFuse([ftsRanked, vectorRanked]), topK);
  } finally {
    db.close();
  }
}
