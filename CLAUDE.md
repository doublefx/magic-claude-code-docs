# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A community mirror of Claude Code documentation from https://code.claude.com/docs/en/. Documentation is auto-fetched every 3 hours via GitHub Actions, plus the Claude Code changelog from https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md.

Distributed as a Claude Code plugin (`magic-claude-docs`) via marketplace.

**Not affiliated with Anthropic.**

## Architecture

### Documentation Pipeline

```
Anthropic docs site (code.claude.com/docs/en/*.md)
    ↓ llms.txt discovery + markdown fetch
scripts/fetch_claude_docs.py (Python, runs in GitHub Actions)
    ↓ writes files + manifest
plugin/docs/*.md + plugin/docs/docs_manifest.json
    ↓ git commit + push (by CI bot)
GitHub repository (main branch)
    ↓ plugin auto-update (marketplace)
~/.claude/plugins/cache/magic-claude-docs/...
    ↓ SessionStart hook (cp -R)
~/.claude-code-docs/ (user's local documentation)
    ↓ SKILL.md reads files
/magic-claude-docs:docs command output
```

### Repository Structure

```
.claude-plugin/marketplace.json     # Marketplace descriptor (repo root)
plugin/
  .claude-plugin/plugin.json        # Plugin manifest + SessionStart hook
  skills/docs/SKILL.md              # /magic-claude-docs:docs skill
  docs/                             # 60+ markdown files + manifest (CI-managed)
    docs_manifest.json              # File index with URLs, hashes, timestamps
    recent_changes.md               # CI-generated recent changes
scripts/
  fetch_claude_docs.py              # Documentation fetcher (CI only)
  requirements.txt                  # Python dependencies (CI only)
.github/
  workflows/update-docs.yml         # CI: sentinel check → fetch → version bump
  workflows/release.yml             # CI: release on plugin.json version change
  sentinels/                        # SHA-256 hashes for llms.txt + docs_map
```

### Key Components

- **`scripts/fetch_claude_docs.py`** — Fetcher that discovers pages from llms.txt index, downloads markdown, validates content, tracks changes via SHA-256 hashes in manifest. Also fetches the changelog and docs map.
- **`plugin/skills/docs/SKILL.md`** — Skill definition for `/magic-claude-docs:docs`. Reads docs from `~/.claude-code-docs/` (populated by SessionStart hook). Handles topic lookup, search, listing, and "what's new".
- **`plugin/.claude-plugin/plugin.json`** — Plugin manifest with date-based versioning (`YYYY.M.D.N`). Includes a `SessionStart` hook that syncs docs from plugin cache to `~/.claude-code-docs/`.
- **`.claude-plugin/marketplace.json`** — Marketplace descriptor at repo root, pointing `source` to `./plugin`.
- **`plugin/docs/docs_manifest.json`** — Git-tracked manifest mapping filenames to original URLs, content hashes, and timestamps. Managed by the fetcher — never edit manually.

### GitHub Actions Workflows

- **`.github/workflows/update-docs.yml`** — Runs every 3 hours. Sentinel check (llms.txt + docs_map hashes) skips fetch if upstream unchanged. On changes: fetches docs, generates `recent_changes.md`, bumps plugin version, commits to `main`.
- **`.github/workflows/release.yml`** — Creates a GitHub release when `plugin/.claude-plugin/plugin.json` version changes.

### User Installation

```bash
claude plugin marketplace add https://github.com/doublefx/magic-claude-code-docs
claude plugin install magic-claude-docs
```

After install, users have:
- Plugin cached at `~/.claude/plugins/cache/magic-claude-docs/...`
- `~/.claude-code-docs/` synced on each session start via hook
- `/magic-claude-docs:docs` skill available

## Important Details

- **Version** is in `plugin/.claude-plugin/plugin.json` using date-based format `YYYY.M.D.N`. CI bumps it on content changes. This drives plugin cache refresh for users with auto-update enabled.
- **The manifest (`plugin/docs/docs_manifest.json`) is git-tracked.** Never edit manually — the fetcher manages it.
- **Private files** (`scripts/`, `.github/`, `CLAUDE.md`, `README.md`) are NOT shipped in the plugin — they stay in git only.
- **Auto-update** is disabled by default for third-party marketplaces. Users should enable it after install.

## Serena Memories

Development commands, style conventions, and task completion checklists are maintained in Serena memories. Read these at session start:
- `suggested_commands` — how to run the fetcher
- `style_and_conventions` — shell and Python coding patterns for this project
- `task_completion_checklist` — what to verify before considering work done

## For /docs Command

When responding to `/magic-claude-docs:docs` commands:
1. Follow the instructions in the SKILL.md at `plugin/skills/docs/SKILL.md`
2. Read documentation files from `~/.claude-code-docs/` directory
3. Use the manifest (`~/.claude-code-docs/docs_manifest.json`) to know available topics and their source URLs

## Package manager — pnpm only, never npm or yarn

Owner decision (2026-09-05), after the npm supply-chain attack wave: any Node tooling added to
this repository uses pnpm. Nothing here is Node today (Python fetcher + shell hooks); the rule
applies to the first `package.json` that lands. Distilled from the owner's `yarn-to-pnpm` skill
(generic half only):

- `package.json` pins `"packageManager": "pnpm@<version>+sha512.<hash>"`; every environment
  enables it with `corepack enable pnpm` before the first `pnpm` call (CI steps included).
- `pnpm-lock.yaml` and `pnpm-workspace.yaml` are COMMITTED, never git-ignored; CI installs with
  `pnpm install --frozen-lockfile`, always. Count check: every `pnpm install` line in a workflow
  carries `--frozen-lockfile`.
- `pnpm-workspace.yaml` carries the security policy, explicit even where it matches defaults:
  `minimumReleaseAge: 1440`, `strictDepBuilds: true`, `trustPolicy: no-downgrade`,
  `blockExoticSubdeps: true`; packages that legitimately need a build script go under
  `allowBuilds:` one by one, on the first "ignored build scripts" error, never blanket.
  ⚠ `pnpm.allowBuilds` / `onlyBuiltDependencies` misplaced (wrong file or key) is a silent no-op.
- Ephemeral tools: `pnpm dlx <tool>` when nothing is installed; `pnpm exec <tool>` only for a
  devDependency with `node_modules` present. `pnpm dlx` applies the workspace trust policy too.
- `pnpm pack`, never `npm pack` (only pnpm applies `publishConfig`). `npm audit` reports on a tree
  npm resolves, not the one pnpm installed: use `pnpm audit`.
- pnpm does not run `pre`/`post` scripts on this machine: never rely on them.
- Converting `yarn <script> -- <args>`: drop the lone `--`, pnpm forwards it to the script.
- Equivalents: `yarn install` → `pnpm install --frozen-lockfile` · `yarn run X` / `npm run X` →
  `pnpm run X` · `npx X` → `pnpm dlx X` · `yarn add -D X` → `pnpm add -D X` ·
  `resolutions` → `overrides:` in `pnpm-workspace.yaml`.
