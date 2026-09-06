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

## Pre-computed embeddings asset (CI-built, plugin-downloaded)
Embedding the whole mirror cold takes ~20 minutes (14,312 chunks). To keep a
fresh adopter's *first* `search` call to a few seconds instead, CI computes
every vector once and ships it as a release asset; the plugin downloads it
instead of running the model locally.

- **Format** (`src/asset.mjs`): `embeddings.bin` is `"MCDE"` + a version byte
  + `count` (uint32 LE) + `dims` (uint16 LE), then `count` records of a
  32-byte hash (the full sha256 digest `src/chunk.mjs` already computes for
  each chunk — decoded from its 64-hex-char form, not a truncated prefix) +
  `dims` little-endian float32 values. A sibling `embeddings.json` carries
  `{ model, dims, count, docsVersion, builtAt }` for humans and CI logs.
  `encodeAsset`/`decodeAsset` are pure and round-trip tested.
- **Lookup** (`loadAssetVectors({ home, version, fetch })`, still
  `src/asset.mjs`): checks
  `<home>/.claude-code-docs/index/assets/<version>/embeddings.bin` first,
  else downloads
  `https://github.com/doublefx/magic-claude-code-docs/releases/download/v<version>/embeddings.bin`
  (30s timeout, cached atomically on success), else returns an empty map and
  a `reason` string. **Never throws** — a missing/broken asset degrades to
  embedding locally, it never aborts the build.
- **Build integration**: `buildIndex({ ..., assetVectors })` (`src/index.mjs`)
  fills any chunk whose content hash is in `assetVectors` from there instead
  of calling `embed()`; the returned stats split `fromAsset` (filled from the
  map) from `embedded` (actually sent to `embed()`). Both `bin/build-index.mjs`
  and `bin/search.mjs`'s first-use path call `loadAssetVectors` before
  building, so this applies automatically — no flag needed.
- **Producing the asset**: `bin/export-embeddings.mjs` (see CLI below) is
  what CI runs after each docs release; `--previous <embeddings.bin>` makes
  it incremental — only chunks whose hash isn't already in the previous
  asset get (re-)embedded — mirroring the same hash-based identity the
  index itself uses. `.github/workflows/embeddings.yml` fires on
  `release: published`, downloads the nearest prior release's
  `embeddings.bin` (tolerating its absence), runs the export, and uploads
  both files back onto the SAME release.

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
node bin/export-embeddings.mjs --home <dir> --docs <dir> --out <dir> [--previous <embeddings.bin>] [--version <v>] [--fake]
```
`export-embeddings.mjs` is the CI-side tool: it writes `embeddings.bin` +
`embeddings.json` into `--out`. `--version` overrides the
`.magic-claude-docs-plugin` marker (needed in CI, whose `plugin/docs`
checkout never carries that runtime-written file); `--fake` swaps in a tiny
deterministic embedder for dry runs/tests, never the real model.

## Tests
`pnpm test` runs `node --test` — chunking, incremental build/diff, all three
search modes, the kill switch, the asset encode/decode/download round trip,
a build that prefers `assetVectors` over `embed()` for matching hashes, and
a row-count check proven to fire on a write that silently inserts nothing.
