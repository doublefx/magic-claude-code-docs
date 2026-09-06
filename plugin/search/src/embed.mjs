import path from 'node:path';

// Lazy singleton so a process that never calls the real embedder (every test
// in this package) never imports @xenova/transformers or touches the
// network. Model weights (~25 MB, downloaded once) are pinned to a cache dir
// inside the docs mirror's own home rather than the package's node_modules,
// so a fresh adopter machine keeps the download out of the plugin's install
// footprint and re-uses it across rebuilds.
let extractorPromise;

/**
 * Create the real, injectable `embed(texts) => Promise<Float32Array[]>` seam
 * backed by @xenova/transformers' Xenova/all-MiniLM-L6-v2 (WASM, 384-dim,
 * mean-pooled + L2-normalized). `home` decides the model cache directory;
 * network access and local-model fallback are both explicit, never implicit.
 */
export function createEmbedder({ home }) {
  return async function embed(texts) {
    if (!extractorPromise) {
      extractorPromise = (async () => {
        const { env, pipeline } = await import('@xenova/transformers');
        env.cacheDir = path.join(home, '.claude-code-docs', 'index', 'models');
        env.allowLocalModels = false;
        return pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2');
      })();
    }
    const extractor = await extractorPromise;
    // Batched: one ONNX run per BATCH texts instead of one per text. Measured
    // 2026-09-06 on this machine: text-by-text took >14 min for the mirror.
    // 32 pushed the WASM runtime past 1 GB RSS and the build was killed for low
    // memory (2026-09-06); 8 keeps it near the text-by-text footprint.
    const BATCH = Math.max(1, Number(process.env.MAGIC_CLAUDE_DOCS_EMBED_BATCH) || 8);
    const vectors = [];
    for (let i = 0; i < texts.length; i += BATCH) {
      const batch = texts.slice(i, i + BATCH);
      const output = await extractor(batch, { pooling: 'mean', normalize: true });
      const [rows, dims] = output.dims;
      const data = output.data;
      for (let r = 0; r < rows; r += 1) {
        vectors.push(Float32Array.from(data.subarray(r * dims, (r + 1) * dims)));
      }
    }
    return vectors;
  };
}
