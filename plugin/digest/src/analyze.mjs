import { compareVersions } from './gather.mjs';
// "analyze" phase for the plugin-update digest — one model call per Claude
// Code version, over the gather() output shape (see src/gather.mjs).
//
// Design choices made here that the ADR left open:
//   - `query` is injectable (tests never load the real SDK); the default is
//     lazily imported so `node --test` never touches the Agent SDK module.
//   - The model is instructed to answer ONLY a JSON object; we still extract
//     robustly (first `{` to last `}`) because models wrap JSON in prose.
//   - A plugin whose manifest failed to parse (gather.mjs's `error` field) is
//     never sent to the model for classification — OUR code adds its
//     `manifestInvalid: true` bucket entry after validation, unconditionally.
//   - A types diff longer than 400 lines is truncated per side (added/removed
//     block), never truncated mid-line, with a trailing marker line.

const TYPES_DIFF_LINE_CAP = 400;

export class AnalyzeError extends Error {
  constructor(message, { rawText } = {}) {
    super(message);
    this.name = 'AnalyzeError';
    this.rawText = rawText;
  }
}

// ---------------------------------------------------------------------------
// manifest entries -> the plugin-keyed shape both buildPrompt and analyze use
// ---------------------------------------------------------------------------

// Key manifest entries by plugin name. The same plugin installed in several
// config dirs (~/.claude and ~/.claude-work) or several versions is ONE plugin:
// keep the highest version, record the other installs on `installs`. Only a
// same-named plugin from a DIFFERENT marketplace gets the `marketplace/plugin`
// key, so no distinct plugin is ever silently merged or dropped.
export function keyManifestEntries(entries) {
  const byPlugin = new Map();
  for (const entry of entries) {
    (byPlugin.get(entry.plugin) ?? byPlugin.set(entry.plugin, []).get(entry.plugin)).push(entry);
  }
  const keyed = new Map();
  for (const [plugin, list] of byPlugin) {
    const byMarketplace = new Map();
    for (const entry of list) {
      const m = entry.marketplace ?? '';
      (byMarketplace.get(m) ?? byMarketplace.set(m, []).get(m)).push(entry);
    }
    for (const [marketplace, installs] of byMarketplace) {
      installs.sort((a, b) => compareVersions(String(b.version ?? '0'), String(a.version ?? '0')));
      const best = { ...installs[0], installs: installs.map((e) => ({ configDir: e.configDir, version: e.version })) };
      const key = byMarketplace.size === 1 ? plugin : `${marketplace}/${plugin}`;
      keyed.set(key, best);
    }
  }
  return keyed;
}

function truncatedLines(lines, cap) {
  if (lines.length <= cap) return lines;
  return [...lines.slice(0, cap), `… truncated (${lines.length - cap} more lines)`];
}

// ---------------------------------------------------------------------------
// buildPrompt — pure
// ---------------------------------------------------------------------------

export function buildPrompt(gathered) {
  const parts = [];

  parts.push('# Claude Code plugin-update digest — analysis request');
  parts.push('');
  parts.push(
    `Claude Code version: ${gathered?.claudeVersion?.value ?? 'unknown'} ` +
      `(previous: ${gathered?.previousVersion?.value ?? 'none'})`,
  );

  parts.push('');
  parts.push('## Changelog entries in range');
  const blocks = gathered?.changelog?.blocks ?? [];
  if (!blocks.length) {
    parts.push('(none)');
  } else {
    for (const b of blocks) {
      parts.push(`### ${b.version} — ${b.date}`);
      parts.push(b.body);
      parts.push('');
    }
  }

  parts.push('## Docs pages changed');
  const dc = gathered?.docsChanged ?? {};
  parts.push(`added: ${(dc.added ?? []).join(', ') || '(none)'}`);
  parts.push(`changed: ${(dc.changed ?? []).join(', ') || '(none)'}`);
  parts.push(`removed: ${(dc.removed ?? []).join(', ') || '(none)'}`);

  parts.push('');
  parts.push('## Agent SDK version');
  const sdk = gathered?.sdk ?? {};
  parts.push(
    sdk.status === 'ok' ? `latest on npm: ${sdk.latest}` : `unavailable: ${sdk.reason ?? ''}`,
  );

  const keyed = keyManifestEntries(gathered?.manifests?.entries ?? []);
  for (const [key, entry] of keyed) {
    const manifestSdkVersion = entry?.manifest?.sdk?.version ?? 'unknown';
    parts.push('');
    parts.push(`SDK version declared by plugin "${key}": ${manifestSdkVersion}`);
  }

  parts.push('');
  parts.push('## Plugin-types diff (previous version -> current version)');
  const types = gathered?.types ?? {};
  if (types.status !== 'ok' || typeof types.diff !== 'string' || !types.diff) {
    parts.push('(no diff available)');
  } else {
    const lines = types.diff.split('\n');
    parts.push(truncatedLines(lines, TYPES_DIFF_LINE_CAP).join('\n'));
  }

  parts.push('');
  parts.push('## Every plugin usage-manifest.json');
  if (keyed.size === 0) {
    parts.push('(none found)');
  } else {
    for (const [key, entry] of keyed) {
      parts.push(`### ${key}`);
      if (entry.error) {
        parts.push(`(manifest failed to parse: ${entry.error} — do not classify this plugin)`);
      } else {
        parts.push('```json');
        parts.push(JSON.stringify(entry.manifest, null, 2));
        parts.push('```');
      }
      parts.push('');
    }
  }

  parts.push('## Instructions');
  parts.push(
    `The "plugins" object must contain EXACTLY these keys, spelled as given, one entry each: ${[...keyed.keys()].map((k) => JSON.stringify(k)).join(', ') || '(none)'}.`,
  );
  parts.push(
    'Answer ONLY a single JSON object matching this schema, no prose before or after it:',
  );
  parts.push('```json');
  parts.push(
    JSON.stringify(
      {
        version: 'string',
        from: 'string|null',
        plugins: {
          '<pluginName>': {
            breaks: [{ item: 'string', evidence: 'string', manifestRef: 'string' }],
            couldServe: [{ item: 'string', evidence: 'string' }],
            noise: 0,
          },
        },
        summary: 'string',
      },
      null,
      2,
    ),
  );
  parts.push('```');
  parts.push(
    'For every plugin with a valid manifest above: "breaks" lists a declared usage that ' +
      'changed or was removed by the changelog/docs/types changes; "couldServe" lists a new ' +
      'capability the plugin does not use yet but plausibly could, citing the changelog ' +
      'sentence as evidence; "noise" is a count of everything else considered and dismissed. ' +
      'Do not include a plugin whose manifest failed to parse.',
  );

  return parts.join('\n');
}

// ---------------------------------------------------------------------------
// JSON extraction + validation
// ---------------------------------------------------------------------------

function extractJson(text) {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end < start) {
    throw new AnalyzeError('model answer contained no JSON object', { rawText: text });
  }
  const candidate = text.slice(start, end + 1);
  try {
    return JSON.parse(candidate);
  } catch (e) {
    throw new AnalyzeError(`model answer was not valid JSON: ${e.message}`, { rawText: text });
  }
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function validateBucketArray(arr, requiredKeys, path, rawText) {
  if (!Array.isArray(arr)) {
    throw new AnalyzeError(`${path} must be an array`, { rawText });
  }
  for (let i = 0; i < arr.length; i++) {
    const item = arr[i];
    if (!isPlainObject(item)) {
      throw new AnalyzeError(`${path}[${i}] must be an object`, { rawText });
    }
    for (const key of requiredKeys) {
      if (typeof item[key] !== 'string') {
        throw new AnalyzeError(`${path}[${i}].${key} must be a string`, { rawText });
      }
    }
  }
}

// Validates parsed JSON against the schema and against the manifest-plugin
// set actually gathered. Throws AnalyzeError on any mismatch — the caller
// never writes a partial result.
export function validateResult(parsed, gathered, rawText) {
  if (!isPlainObject(parsed)) {
    throw new AnalyzeError('model answer root is not an object', { rawText });
  }
  if (typeof parsed.version !== 'string') {
    throw new AnalyzeError('"version" must be a string', { rawText });
  }
  if (parsed.from !== null && typeof parsed.from !== 'string') {
    throw new AnalyzeError('"from" must be a string or null', { rawText });
  }
  if (typeof parsed.summary !== 'string') {
    throw new AnalyzeError('"summary" must be a string', { rawText });
  }
  if (!isPlainObject(parsed.plugins)) {
    throw new AnalyzeError('"plugins" must be an object', { rawText });
  }

  const keyed = keyManifestEntries(gathered?.manifests?.entries ?? []);
  const validPluginKeys = new Set([...keyed.entries()].filter(([, e]) => !e.error).map(([k]) => k));

  for (const key of validPluginKeys) {
    const entry = parsed.plugins[key];
    if (!isPlainObject(entry)) {
      throw new AnalyzeError(`missing or invalid "plugins.${key}"`, { rawText });
    }
    validateBucketArray(entry.breaks, ['item', 'evidence', 'manifestRef'], `plugins.${key}.breaks`, rawText);
    validateBucketArray(entry.couldServe, ['item', 'evidence'], `plugins.${key}.couldServe`, rawText);
    if (typeof entry.noise !== 'number') {
      throw new AnalyzeError(`"plugins.${key}.noise" must be a number`, { rawText });
    }
  }

  // Every invalid-manifest plugin gets our own flagged entry, unconditionally
  // — never trust (or require) the model to have produced one.
  const outPlugins = { ...parsed.plugins };
  for (const [key, entry] of keyed) {
    if (entry.error) {
      outPlugins[key] = { breaks: [], couldServe: [], noise: 0, manifestInvalid: true };
    }
  }

  return { ...parsed, plugins: outPlugins };
}

// ---------------------------------------------------------------------------
// renderMarkdown — pure
// ---------------------------------------------------------------------------

export function renderMarkdown(result, gathered) {
  const lines = [];
  lines.push(`# Digest — Claude Code ${result.version}${result.from ? ` (from ${result.from})` : ''}`);
  lines.push('');
  lines.push(result.summary || '(no summary)');
  lines.push('');
  lines.push('| plugin | breaks | could serve | noise |');
  lines.push('|---|---|---|---|');

  const pluginNames = Object.keys(result.plugins).sort();
  for (const name of pluginNames) {
    const p = result.plugins[name];
    const label = p.manifestInvalid ? `${name} (invalid manifest)` : name;
    lines.push(`| ${label} | ${p.breaks.length} | ${p.couldServe.length} | ${p.noise} |`);
  }

  lines.push('');
  for (const name of pluginNames) {
    const p = result.plugins[name];
    lines.push(`## ${name}`);
    if (p.manifestInvalid) {
      lines.push('- manifest could not be parsed; not classified.');
      lines.push('');
      continue;
    }
    if (!p.breaks.length && !p.couldServe.length) {
      lines.push('- nothing to report.');
    }
    for (const b of p.breaks) {
      lines.push(`- BREAKS: ${b.item} — ${b.evidence} (${b.manifestRef})`);
    }
    for (const c of p.couldServe) {
      lines.push(`- could serve: ${c.item} — ${c.evidence}`);
    }
    lines.push('');
  }

  lines.push('## Sources');
  const src = [
    ['claudeVersion', gathered?.claudeVersion],
    ['previousVersion', gathered?.previousVersion],
    ['changelog', gathered?.changelog],
    ['docsChanged', gathered?.docsChanged],
    ['sdk', gathered?.sdk],
    ['types', gathered?.types],
    ['manifests', gathered?.manifests],
  ];
  for (const [name, field] of src) {
    const status = field?.status ?? 'unavailable';
    const reason = field?.reason ? ` — ${field.reason}` : '';
    lines.push(`- ${name}: ${status}${reason}`);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// analyze — orchestrator
// ---------------------------------------------------------------------------

let cachedDefaultQuery = null;
async function defaultQueryLoader() {
  if (!cachedDefaultQuery) {
    const mod = await import('@anthropic-ai/claude-agent-sdk');
    cachedDefaultQuery = mod.query;
  }
  return cachedDefaultQuery;
}

const SYSTEM_PROMPT =
  'You classify a Claude Code release against installed plugins\' declared usage. ' +
  'Match every change to the manifest section it would touch: a CLI flag concerns only a plugin whose manifest lists that command under `cli`; an SDK query option concerns only `sdk.queryOptions`; a hook event or payload field concerns only `hooks`; a front matter key concerns only `frontmatter`; a setting concerns a plugin only if it reads that setting or its effect is named in `invariants`. A change that touches none of a plugin\'s sections is noise for that plugin, however interesting in general. When the latest published Agent SDK version is newer than the version a plugin declares under sdk.version, list that gap under couldServe for that plugin, naming both versions. ' +
  'Answer ONLY the requested JSON object, with no surrounding prose, no markdown fences.';

export async function analyze(gathered, options = {}) {
  const { query: queryOverride, model = 'claude-sonnet-5', now = () => new Date() } = options;

  const prompt = buildPrompt(gathered);

  const queryFn = queryOverride ?? (await defaultQueryLoader());

  const stream = queryFn({
    prompt,
    options: {
      model,
      settingSources: [],
      allowedTools: [],
      maxTurns: 1,
      permissionMode: 'bypassPermissions',
      systemPrompt: SYSTEM_PROMPT,
    },
  });

  let text = null;
  let usage = null;
  for await (const message of stream) {
    if (message?.type === 'result' && message.subtype === 'success') {
      text = message.result;
      // Token accounting of the ONE call, kept in the digest so the cost is
      // readable afterwards (no static prefix: settingSources is empty).
      usage = {
        inputTokens: message.usage?.input_tokens ?? null,
        cacheReadInputTokens: message.usage?.cache_read_input_tokens ?? null,
        cacheCreationInputTokens: message.usage?.cache_creation_input_tokens ?? null,
        outputTokens: message.usage?.output_tokens ?? null,
        totalCostUsd: message.total_cost_usd ?? null,
        durationMs: message.duration_ms ?? null,
        numTurns: message.num_turns ?? null,
        model,
        promptChars: prompt.length,
      };
    }
  }
  if (typeof text !== 'string') {
    throw new AnalyzeError('model stream produced no successful result message', {
      rawText: null,
    });
  }

  const parsed = extractJson(text);
  const validated = validateResult(parsed, gathered, text);

  return { result: validated, analyzedAt: now().toISOString(), usage };
}
