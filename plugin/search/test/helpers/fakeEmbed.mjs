// A deterministic, zero-dependency, zero-network stand-in for the real
// embedder used by every test in this package. Produces a small
// bag-of-canonical-tokens vector, L2-normalized so cosine similarity behaves
// like a real sentence embedding's would. `synonyms` maps a literal token to
// a canonical one BEFORE hashing, which is what lets a test construct a
// genuine paraphrase case (query and target share no literal words, but
// share canonical ones) without downloading a real model.
function hashToken(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return h;
}

function vectorize(text, dimension, synonyms) {
  const vec = new Float32Array(dimension);
  const tokens = text.toLowerCase().match(/[a-z0-9]+/g) || [];
  for (const tok of tokens) {
    const canonical = synonyms[tok] || tok;
    vec[hashToken(canonical) % dimension] += 1;
  }
  let norm = 0;
  for (let i = 0; i < dimension; i++) norm += vec[i] * vec[i];
  norm = Math.sqrt(norm) || 1;
  for (let i = 0; i < dimension; i++) vec[i] /= norm;
  return vec;
}

/**
 * makeFakeEmbed({ dimension, synonyms }) -> embed
 * `embed.calls` accumulates every texts[] array passed in, in order, so a
 * test can assert exactly which (and how many) chunks were sent for
 * re-embedding.
 */
export function makeFakeEmbed({ dimension = 32, synonyms = {} } = {}) {
  const calls = [];
  async function embed(texts) {
    calls.push(texts.slice());
    return texts.map((text) => vectorize(text, dimension, synonyms));
  }
  embed.calls = calls;
  return embed;
}
