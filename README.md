# Claude Code Documentation Mirror

[![Last Update](https://img.shields.io/github/last-commit/doublefx/magic-claude-code-docs/main.svg?label=docs%20updated)](https://github.com/doublefx/magic-claude-code-docs/commits/main)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue)]()

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
/magic-claude-docs:docs what's new   # See recent documentation changes
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
4. **SessionStart hook** syncs docs from plugin cache to `~/.claude-code-docs/` for fast access
5. **SKILL.md** reads from `~/.claude-code-docs/` when you invoke `/magic-claude-docs:docs`

## Session-start signal

At the start of a session, a second `SessionStart` hook checks whether anything has changed
since last time and, if so, prints a single line into the session's context — for example:

```
magic-claude-docs: plugin 2026.9.4.3 installed, 2026.9.5.2 published (restart or /reload-plugins to update) · Claude Code 2.1.262, last digested 2.1.261 (see /magic-claude-docs:docs what's new)
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

## Uninstalling

```bash
claude plugin uninstall magic-claude-docs
rm -rf ~/.claude-code-docs  # Optional: remove cached documentation
```

## For Contributors

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
