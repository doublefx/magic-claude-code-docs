# Claude Code Documentation Mirror

[![Last Update](https://img.shields.io/github/last-commit/doublefx/magic-claude-code-docs/main.svg?label=docs%20updated)](https://github.com/doublefx/magic-claude-code-docs/commits/main)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue)]()
[![Tests](https://github.com/doublefx/magic-claude-code-docs/actions/workflows/test.yml/badge.svg)](https://github.com/doublefx/magic-claude-code-docs/actions/workflows/test.yml)

Local mirror of Claude Code documentation from https://code.claude.com/docs/en/, updated every 3 hours via GitHub Actions.

**Not affiliated with Anthropic.**

## Why This Exists

- **Offline access** - Read Claude Code docs without a browser
- **Automatic updates** - CI fetches latest documentation every 3 hours
- **Track changes** - See what changed with `/magic-claude-docs:docs what's new`
- **Claude Code changelog** - Quick access to official release notes
- **Better integration** - Claude can explore full documentation via the `/magic-claude-docs:docs` skill

## Installation

### As a Claude Code Plugin (Recommended)

```bash
# Add the marketplace source (one-time)
claude plugin marketplace add https://github.com/doublefx/magic-claude-code-docs

# Install the plugin
claude plugin install magic-claude-docs
```

After installation, **enable auto-update** for fresh docs:
1. Auto-update is disabled by default for third-party plugins
2. Enable it in your plugin settings to receive documentation updates automatically
3. Without auto-update, docs will remain at the version you installed

### Prerequisites

- **Claude Code** - The CLI tool from Anthropic

## Usage

```bash
/magic-claude-docs:docs              # List all available topics
/magic-claude-docs:docs hooks        # Read hooks documentation
/magic-claude-docs:docs mcp          # Read MCP documentation
/magic-claude-docs:docs what's new   # Opens with the latest weekly digest, then recent mirror changes
/magic-claude-docs:docs week 34      # Read a specific weekly digest
/magic-claude-docs:docs changelog    # Read Claude Code release notes
```

### Search and Discovery

```bash
# Natural language queries
/magic-claude-docs:docs what environment variables exist?
/magic-claude-docs:docs explain the differences between hooks and MCP

# Search across all docs
/magic-claude-docs:docs find all mentions of authentication
```

## How It Works

1. **CI fetches docs** every 3 hours from `code.claude.com/docs/en/`
2. **Sentinel check** compares `llms.txt` and `docs_map.md` hashes to skip unnecessary fetches
3. **Plugin auto-update** delivers new docs to your local machine on session start
4. **SessionStart hook** re-copies docs from plugin cache to `~/.claude-code-docs/` only when the
   installed plugin version has changed — a marker file next to the docs holds the last-synced
   version, so an unchanged plugin skips the copy on every other session start
5. **SKILL.md** reads from `~/.claude-code-docs/` when you invoke `/magic-claude-docs:docs`

## Session-start signal

At the start of a session, a second `SessionStart` hook checks whether anything has changed
since last time and, if so, prints a single line into the session's context — for example:

```
magic-claude-docs: plugin 2026.9.4.3 installed, 2026.9.5.2 published (restart or /reload-plugins to update) · Claude Code 2.1.262, last digested 2.1.261 (run /magic-claude-docs:digest)
```

It stays **silent** when nothing has drifted — no installed-vs-published plugin mismatch, no
Claude Code version ahead of what this plugin has already digested. Only the half that
actually differs is shown; the other is dropped.

The line's "published" reading comes from a small cache file at
`~/.claude-code-docs/.published-version`. The hook never blocks startup on a network call: it
reads that cache, prints (or stays quiet), then — only if the cache is more than 3 hours old,
matching the upstream CI's own fetch cadence — kicks off a detached background refresh of that
cache for the *next* session to read. A slow or failed network fetch never delays or breaks the
current session.

## Per-version digest

`/magic-claude-docs:digest` turns a Claude Code version bump into a report: what a plugin's
declared usage-manifest entries broke, what new capability the plugin could adopt, and a noise
count for the rest. Run it when the session-start signal above says a digest is pending, or on
demand.

- **One model call per version, and only once** — `bin/analyze.mjs` is skipped entirely if
  `~/.claude-code-docs/digests/<version>.json` already exists; the skill tells you before
  spending that call.
- **Delivery** posts the digest's markdown to the Atrium room `harness-changes-digest` and opens
  one tracker card per plugin with at least one break or adoptable capability, using
  `~/.claude-code-docs/digest-targets.json` to map a plugin to its board — see
  `plugin/digest/digest-targets.example.json` for the shape. A plugin missing from that file
  still gets its Atrium mention; only its card is skipped, and the skill says so.
- **Sub-commands**: `/magic-claude-docs:digest status` (latest digested version vs. running
  version, whether one is pending) and `/magic-claude-docs:digest show [version]` (print a past
  digest without running anything).

See `plugin/digest/README.md` for the gather/analyze/mark-delivered CLIs this skill drives.

## Usage manifest

`plugin/usage-manifest.json` lists what this plugin consumes from the Claude Code harness: hook
events and the fields they read, skill front matter keys, files under `~/.claude-code-docs/`,
environment variables, CLI calls and the invariants it relies on. The same file, same shape, ships
in the workflow-toolbox, claude-mem and atrium plugins; the per-version digest diffs each Claude
Code release against these manifests to tell every plugin what concerns it.

## Uninstalling

```bash
claude plugin uninstall magic-claude-docs
rm -rf ~/.claude-code-docs  # Optional: remove cached documentation
```

## For Contributors

The `.github/workflows/test.yml` workflow runs the hook test suites (`tests/*.test.sh`) and the `plugin/digest/` test suite (`pnpm test`) on every push and pull request that touches `plugin/hooks/`, `plugin/digest/`, `plugin/skills/`, or `tests/`.

### Architecture

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

### Running the Fetcher Locally

```bash
pip install -r scripts/requirements.txt
python scripts/fetch_claude_docs.py
```

### Key Files

- `scripts/fetch_claude_docs.py` - Documentation fetcher (discovers pages from llms.txt, downloads markdown)
- `plugin/skills/docs/SKILL.md` - Skill definition for the `/magic-claude-docs:docs` command
- `plugin/.claude-plugin/plugin.json` - Plugin manifest with version and SessionStart hook
- `.claude-plugin/marketplace.json` - Marketplace descriptor pointing to `./plugin`
- `.github/workflows/update-docs.yml` - CI workflow (sentinel check, fetch, version bump)

## License

Documentation content belongs to Anthropic.
This mirror tool is open source - contributions welcome!
