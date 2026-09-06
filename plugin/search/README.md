# search — semantic search over the docs mirror

SQLite only: no service, no Chroma, no `sqlite-vec`/HNSW. `node:sqlite`
(built into Node 22+, no flag needed) stores everything in one file,
`<home>/.claude-code-docs/index/docs.sqlite`.

## Schema
`pages(name, hash, title)` · `chunks(id, page, ord, heading, hash, text,
embedding BLOB)` · `chunks_fts` — a plain (non external-content) FTS5 table
over `chunks.text`, kept in sync by hand on `chunks.id` as its rowid; see
`src/db.mjs` for why.

## Chunking
Each page is split by markdown headings, then windowed into ~800-char slices
with ~100-char overlap; every chunk keeps its heading path as a text prefix.

## Embeddings
`@xenova/transformers` (`Xenova/all-MiniLM-L6-v2`, WASM, downloaded once
into `<home>/.claude-code-docs/index/models/`) behind an injectable
`embed(texts) -> Float32Array[]` seam (`src/embed.mjs`) — tests use a
deterministic fake, never the network (`test/helpers/fakeEmbed.mjs`).

## Ranking
FTS5 `bm25()` and brute-force cosine similarity are combined by Reciprocal
Rank Fusion (k=60); `--mode fts|vector|fusion` picks one directly.

## Incremental indexing
A page whose manifest SHA-256 is unchanged is skipped entirely; inside a
changed page only chunks whose own hash changed are re-embedded. A full
rebuild (into a temp file, atomically renamed over the live index) happens
instead whenever the mirror's plugin-version marker differs from what the
index last recorded.

## Kill switch
`MAGIC_CLAUDE_DOCS_SEARCH=off` makes `search` print "semantic search
disabled" and exit 0, without touching the index.

## CLI
```
node bin/build-index.mjs [--home <dir>] [--docs <dir>] [--json]
node bin/search.mjs [--home <dir>] [--docs <dir>] [--mode fts|vector|fusion] [--top N] [--json] <question>
```

## Tests
`pnpm test` runs `node --test` — chunking, incremental build/diff, all three
search modes, the kill switch, and a row-count check proven to fire on a
write that silently inserts nothing.
