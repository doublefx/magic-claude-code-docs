// Marks a digest as delivered: sets `deliveredAt` (ISO timestamp) and
// `deliveryNote` on `<home>/.claude-code-docs/digests/<version>.json`,
// written atomically (temp file + rename), byte-identical apart from those
// two fields. Idempotent: a record that already carries `deliveredAt` is
// left untouched and reported as such.

import path from 'node:path';
import { readFile, writeFile, rename } from 'node:fs/promises';

export async function markDelivered({ home, version, note, now = () => new Date() }) {
  const digestsDir = path.join(home, '.claude-code-docs', 'digests');
  const jsonPath = path.join(digestsDir, `${version}.json`);

  let record;
  try {
    record = JSON.parse(await readFile(jsonPath, 'utf8'));
  } catch (e) {
    const err = new Error(`mark-delivered: could not read ${jsonPath}: ${String(e.message || e)}`);
    err.code = 'MISSING';
    throw err;
  }

  if (record.deliveredAt) {
    return { jsonPath, record, alreadyDelivered: true };
  }

  record.deliveredAt = now().toISOString();
  record.deliveryNote = note;

  const content = JSON.stringify(record, null, 2) + '\n';
  const tmp = `${jsonPath}.tmp-${process.pid}`;
  await writeFile(tmp, content, 'utf8');
  await rename(tmp, jsonPath);

  return { jsonPath, record, alreadyDelivered: false };
}
