---
name: digest
description: Check what changed in Claude Code between the last digested version and the one now running, and whether it breaks or could serve any of this machine's plugins. One model call per Claude Code version, cached for every other session.
when_to_use: The session-start signal line says the running Claude Code version is ahead of the last digested one; the user says "digest", "run the digest", or asks "what changed in Claude Code for our plugins"; "digest status" or "digest show" to read without running anything.
argument-hint: "[show [version] | status]"
allowed-tools: Bash(node *), Bash(corepack pnpm install *), Bash(cat *), Bash(ls *), Bash(timeout 5 claude --version*), Read
effort: low
---

# Claude Code update digest

Turns a Claude Code version bump into: what breaks in a plugin's declared usage, what new
capability it could adopt, and — for the current plugin — a posted summary plus tracker cards.

## Sub-commands

`$ARGUMENTS` may be empty (run the full flow below), `show [version]` (print a past digest and
stop), or `status` (report state and stop). Handle `show`/`status` first; only fall through to
the full flow when neither matches.

### `show [version]`

No version given → `cat ~/.claude-code-docs/digests/latest` for the version, then print
`~/.claude-code-docs/digests/<version>.md` in full. A version given → print that file directly.
Missing file → say which versions exist (`ls ~/.claude-code-docs/digests/*.md`).

### `status`

Run and report all three, plain language, no further action:
```
cat ~/.claude-code-docs/digests/latest 2>/dev/null || echo "(none digested yet)"
timeout 5 claude --version </dev/null
```
Pending = the running version differs from the digested one. Say so plainly ("a digest is
pending for 2.1.262" / "up to date at 2.1.261").

## Full flow

### 1. Find the plugin root

`${CLAUDE_PLUGIN_ROOT}` is substituted directly into this skill's own text by Claude Code
before you read it — run:
```
echo "${CLAUDE_PLUGIN_ROOT}"
```
If that prints a real path (not empty, not the literal string), the digest package is at
`<that path>/digest/`. If it prints empty or literal (this skill invoked outside its normal
plugin context), fall back to resolving it yourself:
```
node -e "const j=require(require('os').homedir()+'/.claude/plugins/installed_plugins.json');const e=(j.plugins['magic-claude-docs@magic-claude-docs']||[])[0];console.log(e?e.installPath:'')"
```
An empty result there too means fall back to the highest version directory under
`~/.claude/plugins/cache/magic-claude-docs/magic-claude-docs/`. Call the resolved path
`<pluginRoot>` for every command below.

### 2. Gather

```
node <pluginRoot>/digest/bin/gather.mjs --home "$HOME" --plugin-root <pluginRoot>
```
Prints the gather file's path. Read that file's `claudeVersion.value` — call it `<version>`.

### 3. Analyze — only if not already done, and only after telling the user

Check first: does `~/.claude-code-docs/digests/<version>.json` already exist? If yes, skip this
step entirely (idempotent — never re-run analyze for a version already digested).

If it does not exist, tell the user this costs one Sonnet model call (about two minutes). The
analysis needs the Agent SDK, which is not shipped with the plugin: if
`<pluginRoot>/digest/node_modules/@anthropic-ai/claude-agent-sdk` is absent, install it first
(pnpm only, never npm; the lockfile is shipped):
```
corepack pnpm install --frozen-lockfile --dir <pluginRoot>/digest
```
Then run:
```
node <pluginRoot>/digest/bin/analyze.mjs --home "$HOME" --version <version>
```
Exit code `3` means another session holds the analyze lock — say so and stop; do not retry.
Any other non-zero exit — report the error and stop.

### 4. Deliver — only if `deliveredAt` is `null` in `<version>.json`

Read `~/.claude-code-docs/digest-targets.json` (may be absent — treat as `{}`). Its shape is
`{ "<pluginKey>": { "boardId": "...", "listId": "...", "atriumMention": "<agent name>" } }`
(the same file gather.mjs reads for `manifestPath` entries — extra keys are ignored by gather,
read only by this step).

**(a) Atrium.** Post `<version>.md`'s full content to the Atrium room named
`harness-changes-digest` with the `speak` tool, mentioning every `atriumMention` value found in
the targets file for a plugin that has at least one `breaks` or `couldServe` item. Do this even
when the targets file is missing or has no entries for the affected plugins — never skip the
Atrium post for a missing mapping.

**(b) Planka cards.** For each plugin in `<version>.json`'s `result.plugins` with at least one
`breaks` or `couldServe` item: look up its entry in the targets file. No entry → skip the card
for that plugin and collect its name. Entry found → on that plugin's `boardId`, call
`get_board` to resolve label ids by name (`P0`, `P2`, `research`, `effort:S`), then
`create_card` on `listId` with `dependsOn: "none"`, title
`Digest <version>: <plugin> — N breaks, M could serve` (N/M = the item counts), description =
that plugin's `breaks` and `couldServe` items with their evidence, labels: `P0` if `breaks` is
non-empty else `P2`, plus `research` and `effort:S`.

After both: if any plugin had no targets-file entry, say so in one line ("no board configured
for: X, Y") — never fail the whole delivery over a missing mapping.

### 5. Mark delivered

```
node <pluginRoot>/digest/bin/mark-delivered.mjs --home "$HOME" --version <version> --note "<where it was posted — e.g. 'Atrium harness-changes-digest; cards on magic-claude-docs, magic-claude-mem'>"
```
Exit `2` means `<version>.json` is missing — something upstream failed; report and stop. Running
this on an already-delivered version is a safe no-op.
