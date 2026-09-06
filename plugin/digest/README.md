# digest — gather phase
`gather()` collects, per source, what changed between two Claude Code versions:
installed version, changelog range, changed doc hashes, latest Agent SDK on npm,
a plugin-types `.d.ts` diff, and every `usage-manifest.json` under `~/.claude`
and `~/.claude-work` plugin caches. Each field carries `status: "ok" |
"unavailable"` (+ `reason`); one source failing never hides the others.
## CLI
```
node bin/gather.mjs --plugin-root <path> [--home <dir>] [--dry-run] [--claude-version <v>]
```
Writes `<home>/.claude-code-docs/digests/<version>.gather.json` + snapshot +
`latest` pointer, prints the output path. `--dry-run` prints JSON to stdout.
## Injection seams
`gather({ home, pluginRoot, claudeVersion?, previousVersion?, fetch?, exec?, now? })`
— `fetch`, `exec(cmd, args, {env,timeoutMs}) -> {code,stdout,stderr}`, `now()`.
## Tests
`pnpm test` runs `node --test` over `test/gather.test.mjs` and `test/fixtures/`.

# digest — analyze phase
`analyze(gathered, { query?, model?, now? })` makes one model call per Claude
Code version over a `gather()` result, and returns a validated classification
per plugin (against its `usage-manifest.json`): `breaks` (a declared usage that
changed or was removed), `couldServe` (a new capability the plugin doesn't use
yet but plausibly could), and `noise` (a count), plus a `summary`. A plugin
whose manifest failed to parse is never sent to the model — our own code flags
it `manifestInvalid: true` after validation. `query` defaults to a lazy import
of `@anthropic-ai/claude-agent-sdk`'s `query`, so tests never load the SDK.
`buildPrompt` and `renderMarkdown` are exported pure functions.

## CLI
```
node bin/analyze.mjs [--home <dir>] [--gather <path>] [--version <v>] [--model <name>] [--dry-run] [--fake <file>]
```
Reads `<home>/.claude-code-docs/digests/<version>.gather.json` (version from
`digests/latest` unless `--version`/`--gather` is given), writes
`<version>.json` (`{ result, sources, gatheredAt, analyzedAt, deliveredAt: null }`),
`<version>.md`, `<version>.snapshot.json`, and finally `latest` — written LAST
and atomically (temp file + rename), so `latest` never points at a version
whose other files aren't fully on disk yet. A `<version>.lock` file guards
against a concurrent run: younger than 30 minutes → exit 3, nothing written;
older → overwritten. `--dry-run` prints the prompt size and the would-be
output paths without calling anything. `--fake <file>` injects the file's
content as the model's raw answer text, for end-to-end testing without a real
model call — **the real model call is made only by `bin/analyze.mjs` without
`--fake`, one call per Claude Code version.**

## Tests
`pnpm test` also runs `test/analyze.test.mjs` (unit tests on `buildPrompt`,
`analyze`, `renderMarkdown` with an injected fake `query`, plus subprocess
tests of the CLI's `--fake` path and its lock).
