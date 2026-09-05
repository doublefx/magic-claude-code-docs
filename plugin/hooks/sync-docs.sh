#!/usr/bin/env bash
# sync-docs.sh — SessionStart (startup) hook for the magic-claude-docs plugin.
#
# Purpose: mirror the plugin's bundled docs into ~/.claude-code-docs, but only
# when the installed plugin VERSION has actually changed since the last sync
# — not on every session start. Today's inline hook wiped and recopied 189
# files unconditionally on every startup; this replaces it.
#
# Contract:
#   - never exits non-zero — a startup hook must not break a session
#   - no output on the happy path (skip or successful copy)
#   - no `set -e` (a startup hook must survive any single failed command)
#
# Skip condition: the marker file already contains the installed plugin
# version AND the target's docs_manifest.json exists. Anything else (marker
# missing, empty, stale, or the manifest missing) triggers a full re-copy.
#
# The marker is written LAST, only after the copy completes, so an
# interrupted copy leaves the marker stale (or absent) and the NEXT start
# retries rather than believing a half-finished copy is current.

# Deliberately no `set -e`.

HOME="${HOME:-}"
CLAUDE_PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-}"

D="$HOME/.claude-code-docs"
MARKER="$D/.magic-claude-docs-plugin"
MANIFEST="$D/docs_manifest.json"
SRC_DOCS="${CLAUDE_PLUGIN_ROOT}/docs"
PLUGIN_JSON="${CLAUDE_PLUGIN_ROOT}/.claude-plugin/plugin.json"

# extract_json_version <file>
# Prints the value of the top-level "version" key. Uses jq when present, a
# grep/sed fallback otherwise. Prints nothing (no error) when unavailable.
# Copied verbatim in shape from plugin/hooks/version-signal.sh rather than
# reinvented, so the two hooks agree on how a plugin.json version is read.
extract_json_version() {
  f="$1"
  [ -f "$f" ] || return 0
  if command -v jq >/dev/null 2>&1; then
    jq -r '.version // empty' "$f" 2>/dev/null
  else
    grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" 2>/dev/null \
      | head -1 \
      | sed -E 's/^"version"[[:space:]]*:[[:space:]]*"([^"]*)"$/\1/'
  fi
}

# Nothing to sync from — mirror today's behaviour: no-op, exit 0.
[ -d "$SRC_DOCS" ] || exit 0

installed_version="$(extract_json_version "$PLUGIN_JSON")"

marker_version=""
if [ -f "$MARKER" ]; then
  marker_version="$(cat "$MARKER" 2>/dev/null)"
fi

# An empty or missing marker reads as "unknown", which forces a copy — same
# as a genuine version mismatch.
if [ -n "$installed_version" ] && [ -n "$marker_version" ] \
   && [ "$installed_version" = "$marker_version" ] \
   && [ -f "$MANIFEST" ]; then
  exit 0
fi

mkdir -p "$D" 2>/dev/null || exit 0

# `rm -rf "$D"/*` deliberately does NOT remove dotfiles (the glob `*` does
# not match names starting with `.`), so the marker itself and the
# `.published-version` / `.published-version.fetched_at` caches written by
# version-signal.sh survive this wipe by construction. Keep it that way —
# do not switch this to `rm -rf "$D"/{*,.[!.]*}` or similar.
# Wipe only what this hook manages. `digests/` and `types/` are written by the
# per-version digest (ADR on the digest card) and must survive a plugin update;
# dotfiles (marker, .published-version cache) are untouched by the glob anyway.
for entry in "$D"/*; do
  [ -e "$entry" ] || continue
  case "$(basename "$entry")" in
    digests|types) continue ;;
  esac
  rm -rf "$entry" 2>/dev/null
done
cp -R "$SRC_DOCS/." "$D/" 2>/dev/null

# Write the version LAST: if the copy above was interrupted (killed, disk
# full), the marker is not updated and the next start retries the copy
# instead of believing a partial copy is current.
if [ -n "$installed_version" ]; then
  vtmp="$MARKER.tmp.$$"
  if printf '%s' "$installed_version" > "$vtmp" 2>/dev/null; then
    mv -f "$vtmp" "$MARKER" 2>/dev/null
  fi
fi

exit 0
