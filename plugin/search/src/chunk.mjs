import { createHash } from 'node:crypto';

// Windowing knobs: ~800 chars per chunk with ~100 chars of overlap between
// consecutive windows inside the same heading section.
const WINDOW_SIZE = 800;
const OVERLAP = 100;

const HEADING_RE = /^(#{1,6})\s+(.*)$/;

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

// Split a markdown page into heading-delimited segments. Each segment carries
// the heading PATH (array of heading texts, outermost first) that is active
// at that point in the document, and the raw body text that follows the
// heading line (the heading line itself is folded into the path, not the
// body). A page with no headings at all yields a single segment with an
// empty path and the whole page as its body.
function splitByHeadings(markdown) {
  const lines = markdown.split('\n');
  const stack = []; // { level, text }
  const segments = [];
  let current = { path: [], body: [] };

  function flush() {
    const body = current.body.join('\n').trim();
    if (body.length > 0) segments.push({ path: current.path.slice(), body });
  }

  for (const line of lines) {
    const m = HEADING_RE.exec(line);
    if (m) {
      flush();
      const level = m[1].length;
      const text = m[2].trim();
      while (stack.length && stack[stack.length - 1].level >= level) stack.pop();
      stack.push({ level, text });
      current = { path: stack.map((s) => s.text), body: [] };
    } else {
      current.body.push(line);
    }
  }
  flush();
  return segments;
}

// Window one segment's body into ~WINDOW_SIZE-char slices with ~OVERLAP
// overlap between consecutive slices. Every slice is prefixed with the
// segment's heading path so the heading text survives chunking even when a
// section is long enough to be split into several chunks.
function windowSegment(segment) {
  const { path, body } = segment;
  const prefix = path.length ? `${path.join(' > ')}\n\n` : '';
  if (body.length <= WINDOW_SIZE) return [prefix + body];

  const stride = WINDOW_SIZE - OVERLAP;
  const windows = [];
  let start = 0;
  while (start < body.length) {
    const end = Math.min(start + WINDOW_SIZE, body.length);
    windows.push(prefix + body.slice(start, end));
    if (end >= body.length) break;
    start += stride;
  }
  return windows;
}

/**
 * Chunk one markdown page into { ord, headingPath, text, hash } records.
 * `ord` is a per-page, zero-based, deterministic sequence number (stable
 * across builds as long as the page content and this algorithm don't
 * change) — the incremental indexer diffs on (page, ord).
 */
export function chunkPage(markdown) {
  const segments = splitByHeadings(markdown);
  const chunks = [];
  let ord = 0;
  for (const segment of segments) {
    for (const text of windowSegment(segment)) {
      chunks.push({ ord, headingPath: segment.path.join(' > '), text, hash: sha256(text) });
      ord += 1;
    }
  }
  return chunks;
}
