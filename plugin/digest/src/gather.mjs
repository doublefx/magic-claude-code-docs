// Model-free "gather" phase for the plugin-update digest.
//
// Every external effect (process spawning, network fetch, the wall clock, and
// even the two config-dir roots) is a parameter so the whole module can be
// unit-tested without touching this machine's real Claude Code install.
//
// Design choices made here that the spec left open (stated so a reader does
// not mistake them for the spec itself):
//   - `exec(command, args, { env, timeoutMs })` -> `{ code, stdout, stderr }`,
//     never throws for a non-zero exit (only for a genuine spawn failure).
//   - `fetch(url, opts)` may resolve to either a Fetch-API-shaped Response
//     (has `.json()`, `.ok`, `.status`) or a plain already-parsed object
//     (what a test double naturally returns); both are handled.
//   - The "no previous snapshot" case reports `added` as a flat array of
//     filenames plus a top-level `note`, rather than wrapping every entry.
//   - `types.diff` is a simplified `+`/`-`/` ` line-prefixed diff computed by
//     an in-process LCS, not literal `diff -u` output.
//   - The CLI's `--dry-run` also persists `<version>.snapshot.json` and
//     `digests/latest` on a real (non-dry) run, so the very next run has a
//     previousVersion and a snapshot to compare against — the spec's fields
//     3 and 2 need those files to exist for anything past the first run.

import { readFile, readdir, stat, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';

const NPM_SDK_LATEST_URL =
  'https://registry.npmjs.org/@anthropic-ai/claude-agent-sdk/latest';

// ---------------------------------------------------------------------------
// version helpers — no dependency, tolerant of 3- or 4-part dotted versions
// ---------------------------------------------------------------------------

export function isVersionLike(name) {
  return /^\d+(\.\d+)*$/.test(String(name));
}

export function parseVersionParts(v) {
  return String(v)
    .trim()
    .split('.')
    .map((part) => {
      const n = parseInt(part, 10);
      return Number.isNaN(n) ? 0 : n;
    });
}

export function compareVersions(a, b) {
  const pa = parseVersionParts(a);
  const pb = parseVersionParts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na !== nb) return na - nb;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// default injectable effects
// ---------------------------------------------------------------------------

function defaultExec(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      command,
      args,
      { timeout: options.timeoutMs, env: options.env ?? process.env },
      (error, stdout, stderr) => {
        if (error && typeof error.code !== 'number' && !error.killed) {
          // genuine spawn failure (ENOENT, etc.) — let the caller decide
          reject(error);
          return;
        }
        resolve({
          code: error ? (typeof error.code === 'number' ? error.code : 1) : 0,
          stdout: stdout ?? '',
          stderr: stderr ?? (error ? String(error.message || error) : ''),
          timedOut: Boolean(error && error.killed),
        });
      },
    );
    if (child.stdin) {
      // equivalent of `</dev/null`: never let the child wait on stdin
      child.stdin.end();
    }
  });
}

async function safe(fn, onError) {
  try {
    return await fn();
  } catch (e) {
    return onError(String((e && e.message) || e));
  }
}

async function pathExistsNonEmptyFile(p) {
  try {
    const st = await stat(p);
    return st.isFile() && st.size > 0;
  } catch {
    return false;
  }
}

async function listDirs(p) {
  try {
    const entries = await readdir(p, { withFileTypes: true });
    return entries.filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// 1. claudeVersion
// ---------------------------------------------------------------------------

async function gatherClaudeVersion({ exec, home, override }) {
  if (override) {
    return { status: 'ok', value: override, source: 'override' };
  }

  try {
    const { code, stdout } = await exec('claude', ['--version'], {
      timeoutMs: 5000,
    });
    if (code === 0) {
      const m = String(stdout).match(/(\d+\.\d+\.\d+)/);
      if (m) return { status: 'ok', value: m[1], source: 'cli' };
    }
  } catch {
    // fall through to the versions-dir fallback
  }

  try {
    const dir = path.join(home, '.local', 'share', 'claude', 'versions');
    const dirs = (await listDirs(dir)).filter(isVersionLike);
    if (dirs.length) {
      dirs.sort(compareVersions);
      return {
        status: 'ok',
        value: dirs[dirs.length - 1],
        source: 'versions-dir',
      };
    }
  } catch {
    // ignore, handled below
  }

  return {
    status: 'unavailable',
    reason: 'claude --version failed and no versions directory was found',
  };
}

// ---------------------------------------------------------------------------
// 2. previousVersion
// ---------------------------------------------------------------------------

async function gatherPreviousVersion({ home, override }) {
  if (override !== undefined) {
    return { status: 'ok', value: override ?? null, source: 'override' };
  }
  const p = path.join(home, '.claude-code-docs', 'digests', 'latest');
  try {
    const content = await readFile(p, 'utf8');
    const trimmed = content.trim();
    return { status: 'ok', value: trimmed || null };
  } catch (e) {
    if (e && e.code === 'ENOENT') {
      return { status: 'ok', value: null, note: 'first run' };
    }
    return {
      status: 'ok',
      value: null,
      note: `could not read latest pointer: ${String(e.message || e)}`,
    };
  }
}

// ---------------------------------------------------------------------------
// 3. changelog
// ---------------------------------------------------------------------------

const UPDATE_RE =
  /<Update label="([^"]*)" description="([^"]*)">([\s\S]*?)<\/Update>/g;

export function parseChangelog(content) {
  const blocks = [];
  for (const m of content.matchAll(UPDATE_RE)) {
    blocks.push({ version: m[1], date: m[2], body: m[3].trim() });
  }
  return blocks;
}

async function gatherChangelog({ pluginRoot, claudeVersion, previousVersion }) {
  if (!claudeVersion) {
    return {
      status: 'unavailable',
      reason: 'no claudeVersion to select a range against',
      blocks: [],
    };
  }
  const p = path.join(pluginRoot, 'docs', 'changelog.md');
  try {
    const content = await readFile(p, 'utf8');
    const blocks = parseChangelog(content);
    let selected;
    if (previousVersion == null) {
      selected = blocks.filter((b) => compareVersions(b.version, claudeVersion) === 0);
    } else {
      selected = blocks.filter(
        (b) =>
          compareVersions(b.version, previousVersion) > 0 &&
          compareVersions(b.version, claudeVersion) <= 0,
      );
    }
    return { status: 'ok', blocks: selected };
  } catch (e) {
    return { status: 'unavailable', reason: String(e.message || e), blocks: [] };
  }
}

// ---------------------------------------------------------------------------
// 4. docsChanged
// ---------------------------------------------------------------------------

async function gatherDocsChanged({ pluginRoot, home, previousVersion }) {
  const manifestPath = path.join(pluginRoot, 'docs', 'docs_manifest.json');
  try {
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    const files = manifest.files || {};
    const snapshot = {};
    for (const [name, entry] of Object.entries(files)) {
      snapshot[name] = (entry && entry.hash) || null;
    }

    if (previousVersion == null) {
      return {
        status: 'ok',
        added: Object.keys(snapshot),
        changed: [],
        removed: [],
        note: 'no previous snapshot',
        snapshot,
      };
    }

    const snapPath = path.join(
      home,
      '.claude-code-docs',
      'digests',
      `${previousVersion}.snapshot.json`,
    );
    let previousSnapshot = null;
    try {
      previousSnapshot = JSON.parse(await readFile(snapPath, 'utf8'));
    } catch {
      previousSnapshot = null;
    }

    if (!previousSnapshot) {
      return {
        status: 'ok',
        added: Object.keys(snapshot),
        changed: [],
        removed: [],
        note: 'no previous snapshot',
        snapshot,
      };
    }

    const added = [];
    const changed = [];
    const removed = [];
    for (const [name, hash] of Object.entries(snapshot)) {
      if (!(name in previousSnapshot)) added.push(name);
      else if (previousSnapshot[name] !== hash) changed.push(name);
    }
    for (const name of Object.keys(previousSnapshot)) {
      if (!(name in snapshot)) removed.push(name);
    }
    return { status: 'ok', added, changed, removed, snapshot };
  } catch (e) {
    return {
      status: 'unavailable',
      reason: String(e.message || e),
      added: [],
      changed: [],
      removed: [],
      snapshot: {},
    };
  }
}

// ---------------------------------------------------------------------------
// 5. sdk
// ---------------------------------------------------------------------------

async function gatherSdk({ fetchFn }) {
  if (typeof fetchFn !== 'function') {
    return { status: 'unavailable', reason: 'no fetch implementation available' };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetchFn(NPM_SDK_LATEST_URL, { signal: controller.signal });
    let data = res;
    if (res && typeof res.json === 'function') {
      if ('ok' in res && res.ok === false) {
        return { status: 'unavailable', reason: `HTTP ${res.status ?? 'error'}` };
      }
      data = await res.json();
    }
    if (!data || typeof data.version !== 'string') {
      return { status: 'unavailable', reason: 'response carried no version field' };
    }
    return { status: 'ok', latest: data.version };
  } catch (e) {
    return { status: 'unavailable', reason: String(e.message || e) };
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// 6. types
// ---------------------------------------------------------------------------

// Small line-based LCS diff. O(n*m); guarded for pathologically large inputs.
export function computeLineDiff(oldLines, newLines) {
  const n = oldLines.length;
  const m = newLines.length;
  if (n * m > 4_000_000) {
    const ops = [];
    for (const line of oldLines) ops.push({ type: 'del', line });
    for (const line of newLines) ops.push({ type: 'add', line });
    return ops;
  }
  const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] =
        oldLines[i] === newLines[j]
          ? dp[i + 1][j + 1] + 1
          : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const ops = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (oldLines[i] === newLines[j]) {
      ops.push({ type: 'ctx', line: oldLines[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      ops.push({ type: 'del', line: oldLines[i] });
      i++;
    } else {
      ops.push({ type: 'add', line: newLines[j] });
      j++;
    }
  }
  while (i < n) ops.push({ type: 'del', line: oldLines[i++] });
  while (j < m) ops.push({ type: 'add', line: newLines[j++] });
  return ops;
}

export function formatDiff(ops) {
  const lines = [];
  let addedLines = 0;
  let removedLines = 0;
  for (const op of ops) {
    if (op.type === 'add') {
      lines.push('+' + op.line);
      addedLines++;
    } else if (op.type === 'del') {
      lines.push('-' + op.line);
      removedLines++;
    } else {
      lines.push(' ' + op.line);
    }
  }
  return { diff: lines.join('\n'), addedLines, removedLines };
}

async function gatherTypes({ home, claudeVersion, previousVersion, exec }) {
  if (!claudeVersion) {
    return { status: 'unavailable', reason: 'no claudeVersion to gather types for' };
  }

  const dir = path.join(home, '.claude-code-docs', 'types', claudeVersion);
  const dtsPath = path.join(dir, 'claude-code.d.ts');

  const alreadyPresent = await pathExistsNonEmptyFile(dtsPath);
  let ranCommand = false;
  let outputTail = null;

  if (!alreadyPresent) {
    ranCommand = true;
    try {
      await mkdir(dir, { recursive: true });
    } catch (e) {
      return {
        status: 'unavailable',
        reason: `could not create types directory: ${String(e.message || e)}`,
      };
    }

    let execResult;
    try {
      execResult = await exec(
        'claude',
        ['-p', `/plugin-types ${dir}`, '--output-format', 'text'],
        {
          env: { ...process.env, CLAUDE_CODE_ENABLE_FUNCTION_HOOKS: '1' },
          timeoutMs: 120000,
        },
      );
    } catch (e) {
      return {
        status: 'unavailable',
        reason: `plugin-types command failed to run: ${String(e.message || e)}`,
      };
    }

    outputTail = `${execResult.stdout || ''}\n${execResult.stderr || ''}`
      .trim()
      .split('\n')
      .slice(-20)
      .join('\n');

    if (execResult.code !== 0) {
      return {
        status: 'unavailable',
        reason: `plugin-types exited ${execResult.code}: ${outputTail}`,
      };
    }

    const present = await pathExistsNonEmptyFile(dtsPath);
    if (!present) {
      return {
        status: 'unavailable',
        reason: `claude-code.d.ts missing or empty after the command ran: ${outputTail}`,
      };
    }
  }

  let diffResult = { diff: null, note: 'no previous types' };
  if (previousVersion != null) {
    const prevPath = path.join(
      home,
      '.claude-code-docs',
      'types',
      previousVersion,
      'claude-code.d.ts',
    );
    try {
      const [prevContent, curContent] = await Promise.all([
        readFile(prevPath, 'utf8'),
        readFile(dtsPath, 'utf8'),
      ]);
      const ops = computeLineDiff(prevContent.split('\n'), curContent.split('\n'));
      diffResult = formatDiff(ops);
    } catch {
      diffResult = { diff: null, note: 'no previous types' };
    }
  }

  return {
    status: 'ok',
    dir,
    path: dtsPath,
    ranCommand,
    ...diffResult,
  };
}

// ---------------------------------------------------------------------------
// 7. manifests
// ---------------------------------------------------------------------------

async function gatherManifestsForConfigDir(configDir) {
  const results = [];
  const cacheDir = path.join(configDir, 'plugins', 'cache');
  const marketplaces = await listDirs(cacheDir);
  for (const marketplace of marketplaces) {
    const marketplaceDir = path.join(cacheDir, marketplace);
    const plugins = await listDirs(marketplaceDir);
    for (const plugin of plugins) {
      const pluginDir = path.join(marketplaceDir, plugin);
      const versions = (await listDirs(pluginDir)).filter(isVersionLike);
      const versionsWithManifest = [];
      for (const v of versions) {
        const mp = path.join(pluginDir, v, 'usage-manifest.json');
        try {
          await stat(mp);
          versionsWithManifest.push(v);
        } catch {
          // no manifest at this version dir — not a candidate
        }
      }
      if (!versionsWithManifest.length) continue;
      versionsWithManifest.sort(compareVersions);
      const highest = versionsWithManifest[versionsWithManifest.length - 1];
      const manifestPath = path.join(pluginDir, highest, 'usage-manifest.json');
      let manifest = null;
      let error;
      try {
        manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
      } catch (e) {
        error = String(e.message || e);
      }
      results.push({
        plugin,
        marketplace,
        version: highest,
        path: manifestPath,
        configDir,
        manifest,
        ...(error ? { error } : {}),
      });
    }
  }
  return results;
}

async function gatherManifests({ home }) {
  try {
    const claudeEntries = await gatherManifestsForConfigDir(path.join(home, '.claude'));
    const workEntries = await gatherManifestsForConfigDir(
      path.join(home, '.claude-work'),
    );
    return { status: 'ok', entries: [...claudeEntries, ...workEntries] };
  } catch (e) {
    return { status: 'unavailable', reason: String(e.message || e), entries: [] };
  }
}

// ---------------------------------------------------------------------------
// orchestrator
// ---------------------------------------------------------------------------

export async function gather(options = {}) {
  const {
    home,
    pluginRoot,
    claudeVersion: claudeVersionOverride,
    previousVersion: previousVersionOverride,
    fetch: fetchFn = globalThis.fetch,
    exec: execFn = defaultExec,
    now = () => new Date(),
  } = options;

  if (!home) throw new TypeError('gather: home is required');
  if (!pluginRoot) throw new TypeError('gather: pluginRoot is required');

  const claudeVersionField = await safe(
    () => gatherClaudeVersion({ exec: execFn, home, override: claudeVersionOverride }),
    (reason) => ({ status: 'unavailable', reason }),
  );
  const claudeVersion = claudeVersionField.status === 'ok' ? claudeVersionField.value : null;

  const previousVersionField = await safe(
    () => gatherPreviousVersion({ home, override: previousVersionOverride }),
    (reason) => ({ status: 'ok', value: null, note: reason }),
  );
  const previousVersion = previousVersionField.value ?? null;

  const [changelogField, docsChangedField, sdkField, typesField, manifestsField] =
    await Promise.all([
      safe(
        () => gatherChangelog({ pluginRoot, claudeVersion, previousVersion }),
        (reason) => ({ status: 'unavailable', reason, blocks: [] }),
      ),
      safe(
        () => gatherDocsChanged({ pluginRoot, home, previousVersion }),
        (reason) => ({
          status: 'unavailable',
          reason,
          added: [],
          changed: [],
          removed: [],
          snapshot: {},
        }),
      ),
      safe(
        () => gatherSdk({ fetchFn }),
        (reason) => ({ status: 'unavailable', reason }),
      ),
      safe(
        () => gatherTypes({ home, claudeVersion, previousVersion, exec: execFn }),
        (reason) => ({ status: 'unavailable', reason }),
      ),
      safe(
        () => gatherManifests({ home }),
        (reason) => ({ status: 'unavailable', reason, entries: [] }),
      ),
    ]);

  return {
    claudeVersion: claudeVersionField,
    previousVersion: previousVersionField,
    changelog: changelogField,
    docsChanged: docsChangedField,
    sdk: sdkField,
    types: typesField,
    manifests: manifestsField,
    gatheredAt: now().toISOString(),
  };
}
