import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chunkPage } from '../src/chunk.mjs';

test('(a1) heading path is kept in every chunk of a section', () => {
  const md = '# Title\n\n## Sub heading\n\nSome body text under the sub heading.\n';
  const chunks = chunkPage(md);
  assert.equal(chunks.length, 1);
  assert.equal(chunks[0].headingPath, 'Title > Sub heading');
  assert.match(chunks[0].text, /^Title > Sub heading\n\n/);
  assert.match(chunks[0].text, /Some body text under the sub heading\./);
});

test('(a2) a page with no headings still yields one chunk with an empty path', () => {
  const md = 'Just a paragraph with no heading at all.';
  const chunks = chunkPage(md);
  assert.equal(chunks.length, 1);
  assert.equal(chunks[0].headingPath, '');
  assert.equal(chunks[0].text, 'Just a paragraph with no heading at all.');
});

test('(a3) a long section is windowed with overlap between consecutive chunks', () => {
  const body = Array.from({ length: 200 }, (_, i) => `sentence-${i}`).join(' ');
  const md = `# Big section\n\n${body}\n`;
  const chunks = chunkPage(md);
  assert.ok(chunks.length > 1, 'expected the long section to be split into several chunks');

  // Every chunk still carries the heading path.
  for (const c of chunks) assert.match(c.text, /^Big section\n\n/);

  // Overlap: the tail of chunk[0]'s body (after stripping the heading
  // prefix) reappears at the head of chunk[1]'s body.
  const strip = (t) => t.replace(/^Big section\n\n/, '');
  const first = strip(chunks[0].text);
  const second = strip(chunks[1].text);
  const tailOfFirst = first.slice(-50);
  assert.ok(second.startsWith(tailOfFirst.slice(-30)) || second.includes(tailOfFirst.slice(-30)));
});

test('(a4) chunking is deterministic: same content -> same ords and hashes', () => {
  const md = '# A\n\nHello world.\n\n## B\n\nMore text here that is different.\n';
  const first = chunkPage(md);
  const second = chunkPage(md);
  assert.deepEqual(
    first.map((c) => [c.ord, c.hash]),
    second.map((c) => [c.ord, c.hash]),
  );
});

test('(a5) heading levels build a nested path and reset on sibling headings', () => {
  const md = [
    '# Root',
    '',
    '## First',
    '',
    'first body',
    '',
    '### Nested',
    '',
    'nested body',
    '',
    '## Second',
    '',
    'second body',
    '',
  ].join('\n');
  const chunks = chunkPage(md);
  const paths = chunks.map((c) => c.headingPath);
  assert.deepEqual(paths, ['Root > First', 'Root > First > Nested', 'Root > Second']);
});
