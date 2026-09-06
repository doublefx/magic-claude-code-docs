---
name: docs
description: Search and browse Claude Code documentation offline. Use /magic-claude-docs:docs <topic> to read a specific doc, or just /magic-claude-docs:docs to list all topics.
---

# Claude Code Documentation

Community mirror of Claude Code documentation from https://code.claude.com/docs/en/

**Not affiliated with Anthropic.**

## Instructions

Parse `$ARGUMENTS` to determine what the user wants:

### No arguments (empty or whitespace)
List all available documentation topics. Read the manifest file at `~/.claude-code-docs/docs_manifest.json`. Extract all filenames from the `files` object, EXCLUDING weekly-digest filenames (`NNNN-wNN.md`, listed separately below), strip the `.md` extension, sort alphabetically, and present as a bulleted list grouped by category where possible.

Before the topic list, add a **"Weekly digests"** heading. Glob `~/.claude-code-docs/*-w*.md` (files matching `NNNN-wNN.md`), sort by year then week number ascending, and list them (e.g. "2026-w17, 2026-w18, … 2026-w34"). Keep this list separate from the topic list below it.

Also mention:
- Use `/magic-claude-docs:docs <topic>` to read a specific document
- Use `/magic-claude-docs:docs what's new` to see recent changes
- Use `/magic-claude-docs:docs week 34` (or `weekly`, `digest 34`) to read a specific weekly digest

### "what's new" or "whats new" or "recent" or "changes"
1. Find the **latest weekly digest**: glob `~/.claude-code-docs/*-w*.md` matching `NNNN-wNN.md`, pick the one with the highest year then highest week number. If one exists, read and display it in full (title, summary paragraph, release range, and its sections) — this is the primary answer, shown first.
2. Then read `~/.claude-code-docs/recent_changes.md` and display its contents under a heading **"Pages changed in the mirror (last 30 days)"**.
3. If no weekly digest page exists, skip step 1 and show only `recent_changes.md`. If neither exists, inform the user that change tracking is not yet available and suggest checking the GitHub repository at https://github.com/doublefx/magic-claude-code-docs/commits/main/plugin/docs.

### "weekly", "week NN", "week N", or "digest NN"
Extract the week number `NN` from the request (zero-pad to two digits). Look for `~/.claude-code-docs/<YYYY>-w<NN>.md`. If the year is ambiguous (not stated), pick the highest year for which that week's file exists. Read and display the full page. If no file matches that week, tell the user which weeks are available (glob `~/.claude-code-docs/*-w*.md`, sort ascending) instead of guessing.

### Specific topic (e.g., "hooks", "mcp", "setup")
1. Strip `.md` extension if present
2. Look for `~/.claude-code-docs/<topic>.md`
3. If found: Read and display the full content. Append the official source link from the manifest's `original_url` field.
4. If not found: Search for partial matches among all filenames in the manifest. Present matching topics as suggestions. If no matches, list all available topics.

### Search query (multi-word or question-like input)
Extract keywords (strip common stop words: "tell", "me", "about", "explain", "what", "is", "how", "do", "to", "show", "the", "for", "in", "are"). Search filenames and manifest titles for matches. Present matching topics with their titles from the manifest.

### "search <question>"
Semantic search over the full text of the mirror (not just filenames/titles), for a question that a filename match won't resolve — e.g. "search how do I stop a hook from blocking the session". Run:
```
node "${CLAUDE_PLUGIN_ROOT}/search/bin/search.mjs" --home "$HOME" "<question>"
```
First use: if `${CLAUDE_PLUGIN_ROOT}/search/node_modules/@xenova/transformers` is missing, first run `corepack pnpm install --frozen-lockfile --dir "${CLAUDE_PLUGIN_ROOT}/search"`. The command then builds the index on its own first call — this downloads a small (~25 MB) embedding model once and takes a few seconds; every later call is fast. If the command prints "semantic search disabled" (the `MAGIC_CLAUDE_DOCS_SEARCH=off` kill switch), tell the user and fall back to the filename/title search above. ⚠ The very first build embeds the whole mirror (about 14,000 passages): measured at roughly 20 minutes on a 12-core machine (2026-09-06), once; later updates re-embed only changed pages and take well under a second. Tell the user before starting it and let it run; a killed build leaves only a temp file and restarts cleanly.

Present each result as: the page name, its heading path, and its excerpt — then offer to open the full page with `/magic-claude-docs:docs <topic>`. Don't just dump raw command output; read the results and summarize them for the question asked.

## File Locations

All documentation files are at `~/.claude-code-docs/`. This directory is populated by a SessionStart hook that syncs docs from the plugin cache. Use the Read tool with the user's actual home directory path (e.g., `/home/<user>/.claude-code-docs/<filename>.md`). Expand `~` to the real home directory path.

The manifest at `~/.claude-code-docs/docs_manifest.json` contains:
- `files` object: keys are filenames, values have `original_url`, `title`, `hash`, `last_updated`
- `fetch_metadata`: `last_fetch_completed`, `total_files`, etc.

## Response Format

Always start responses with:
```
COMMUNITY MIRROR: https://github.com/doublefx/magic-claude-code-docs
OFFICIAL DOCS: https://code.claude.com/docs/en/
```

When displaying a document, append:
```
Source: <original_url from manifest>
```
