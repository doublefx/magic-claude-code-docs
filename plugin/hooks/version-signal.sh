#!/usr/bin/env bash
# version-signal.sh — SessionStart (startup) hook for the magic-claude-docs plugin.
#
# Purpose: tell a session, in AT MOST one line, that something changed since
# last time — the installed plugin version differs from what is published
# upstream, or the Claude Code binary has moved past the last digested
# version. Prints NOTHING when nothing differs.
#
# Contract this script must honour (see the card's Definition of Done):
#   - at most one line on stdout, nothing on stdout when nothing changed
#   - never writes to stderr on the normal path
#   - NEVER exits non-zero — a startup hook must not break a session
#   - stays fast: no blocking network call on the happy path
#
# The "published version" the happy-path line reads is a CACHE FILE written
# by a PREVIOUS run of this same script. This run only ever reads that cache
# in the foreground; if the cache is stale (>3h, matching the upstream CI's
# own 3-hourly cadence) it kicks off a REFRESH for the *next* run, detached
# so it can never block or fail this one.
#
# All inputs are optional. Each missing one degrades to "that half stays
# silent" rather than erroring.

# Never let an unset variable or a failed command abort this script — a
# startup hook must always exit 0. Deliberately no `set -e`.

HOME="${HOME:-}"
CLAUDE_PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-}"

CACHE_DIR="$HOME/.claude-code-docs"
CACHE_FILE="$CACHE_DIR/.published-version"
STAMP_FILE="$CACHE_DIR/.published-version.fetched_at"
DIGEST_FILE="$HOME/.claude-code-docs/digests/latest"
VERSIONS_DIR="$HOME/.local/share/claude/versions"
PUBLISHED_URL="https://raw.githubusercontent.com/doublefx/magic-claude-code-docs/main/plugin/.claude-plugin/plugin.json"
REFRESH_INTERVAL_SECS=10800   # 3 hours — matches the upstream CI's own cadence

# --- helpers ---------------------------------------------------------------

# extract_json_version <file>
# Prints the value of top-level "version" key. Uses jq when present, a
# grep/sed fallback otherwise. Prints nothing (no error) when unavailable.
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

# do_refresh_published — runs ONLY in the detached background re-exec
# (invoked as: version-signal.sh __refresh_published__). Fetches the
# upstream plugin.json, extracts its version, writes it to CACHE_FILE via a
# temp-file + atomic mv, then stamps the fetch time (success or failure —
# the stamp is what prevents a hammering retry loop on a dead network).
do_refresh_published() {
  mkdir -p "$CACHE_DIR" 2>/dev/null || exit 0

  tmp="$(mktemp "$CACHE_DIR/.published-version.tmp.XXXXXX" 2>/dev/null)" || exit 0

  if curl -fsS --max-time 5 "$PUBLISHED_URL" -o "$tmp" >/dev/null 2>&1; then
    ver="$(extract_json_version "$tmp")"
    if [ -n "$ver" ]; then
      vtmp="${tmp}.v"
      if printf '%s' "$ver" > "$vtmp" 2>/dev/null; then
        mv -f "$vtmp" "$CACHE_FILE" 2>/dev/null
      fi
    fi
  fi
  rm -f "$tmp" 2>/dev/null

  stmp="${STAMP_FILE}.tmp.$$"
  if date +%s > "$stmp" 2>/dev/null; then
    mv -f "$stmp" "$STAMP_FILE" 2>/dev/null
  fi
  exit 0
}

# cache_is_fresh — true when STAMP_FILE exists and is younger than
# REFRESH_INTERVAL_SECS. A missing or unparsable stamp counts as stale.
cache_is_fresh() {
  [ -f "$STAMP_FILE" ] || return 1
  last="$(cat "$STAMP_FILE" 2>/dev/null)"
  case "$last" in
    ''|*[!0-9]*) return 1 ;;
  esac
  now="$(date +%s 2>/dev/null)" || return 1
  age=$((now - last))
  [ "$age" -lt "$REFRESH_INTERVAL_SECS" ]
}

# maybe_refresh_published_async — kicks off a DETACHED background re-exec of
# this script (own PID, own session via setsid/nohup, all fds redirected)
# that performs do_refresh_published. Never blocks; never affects this run's
# exit code or output. Skipped entirely when the cache is still fresh.
maybe_refresh_published_async() {
  if cache_is_fresh; then
    return 0
  fi
  if command -v setsid >/dev/null 2>&1; then
    setsid "$0" __refresh_published__ </dev/null >/dev/null 2>&1 &
  else
    nohup "$0" __refresh_published__ </dev/null >/dev/null 2>&1 &
  fi
  disown 2>/dev/null || true
  return 0
}

# get_installed_version — reads the plugin's OWN version from the plugin.json
# shipped next to this hook (via CLAUDE_PLUGIN_ROOT). Silent if unset/absent.
get_installed_version() {
  [ -n "$CLAUDE_PLUGIN_ROOT" ] || return 0
  extract_json_version "$CLAUDE_PLUGIN_ROOT/.claude-plugin/plugin.json"
}

# get_published_version — reads ONLY the cache written by a previous run.
# Never makes a network call itself (that is maybe_refresh_published_async's
# job, for the NEXT run). Silent if the cache does not exist yet.
get_published_version() {
  [ -f "$CACHE_FILE" ] || return 0
  cat "$CACHE_FILE" 2>/dev/null
}

# get_claude_code_version — the running Claude Code binary's version.
# Primary: `claude --version`, guarded with </dev/null (never let it enter
# a REPL) and a 5s timeout (never let it hang a startup hook).
# Fallback: highest version-named directory under ~/.local/share/claude/versions.
# Silent (empty, non-fatal) if neither source resolves.
get_claude_code_version() {
  out=""
  if command -v timeout >/dev/null 2>&1; then
    out="$(timeout 5 claude --version </dev/null 2>/dev/null)"
  else
    out="$(claude --version </dev/null 2>/dev/null)"
  fi
  if [ -n "$out" ]; then
    ver="$(printf '%s' "$out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    if [ -n "$ver" ]; then
      printf '%s' "$ver"
      return 0
    fi
  fi
  if [ -d "$VERSIONS_DIR" ]; then
    ver="$(ls "$VERSIONS_DIR" 2>/dev/null | sort -V | tail -1)"
    if [ -n "$ver" ]; then
      printf '%s' "$ver"
      return 0
    fi
  fi
  return 0
}

# get_digested_version — the last Claude Code version whose changelog this
# plugin has already surfaced (written by a later card; this script only
# reads it). Silent if absent.
get_digested_version() {
  [ -f "$DIGEST_FILE" ] || return 0
  tr -d '[:space:]' < "$DIGEST_FILE" 2>/dev/null
}

# --- detached refresh re-exec entry point -----------------------------------

if [ "${1:-}" = "__refresh_published__" ]; then
  do_refresh_published
  exit 0
fi

# --- main --------------------------------------------------------------

installed_version="$(get_installed_version)"
published_version="$(get_published_version)"
claude_version="$(get_claude_code_version)"
digested_version="$(get_digested_version)"

line_parts=""

if [ -n "$installed_version" ] && [ -n "$published_version" ] && [ "$installed_version" != "$published_version" ]; then
  # Which side is newer decides the hint: an installed build AHEAD of the
  # published one (a --plugin-dir checkout) must not be told to "update".
  newest="$(printf '%s\n%s\n' "$installed_version" "$published_version" | sort -V | tail -1)"
  if [ "$newest" = "$published_version" ]; then
    line_parts="plugin ${installed_version} installed, ${published_version} published (restart or /reload-plugins to update)"
  else
    line_parts="plugin ${installed_version} installed, ahead of published ${published_version}"
  fi
fi

if [ -n "$claude_version" ] && [ -n "$digested_version" ] && [ "$claude_version" != "$digested_version" ]; then
  cc_part="Claude Code ${claude_version}, last digested ${digested_version} (see /magic-claude-docs:docs what's new)"
  if [ -n "$line_parts" ]; then
    line_parts="${line_parts} · ${cc_part}"
  else
    line_parts="$cc_part"
  fi
fi

if [ -n "$line_parts" ]; then
  printf 'magic-claude-docs: %s\n' "$line_parts"
fi

maybe_refresh_published_async

exit 0
