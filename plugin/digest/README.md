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
