#!/usr/bin/env bash
# Tests for plugin/hooks/version-signal.sh
#
# Run: bash tests/version-signal.test.sh
# Exit 0 on success; non-zero with the failing case named on stderr/stdout.
#
# Each case gets its own temp HOME and temp CLAUDE_PLUGIN_ROOT, shadows
# `claude` and `curl` with stubs on PATH (never touches the real network),
# and inspects stdout / files / the curl stub's call marker.

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/plugin/hooks/version-signal.sh"

FAILED=0
fail() {
  echo "FAIL: $1"
  FAILED=1
}
pass() {
  echo "PASS: $1"
}

# wait_for_nonempty_file <path> <timeout_secs> — polls for a file to become
# non-empty, since the published-version refresh runs detached in the
# background and may write its marker a beat after this process returns.
wait_for_nonempty_file() {
  path="$1"
  timeout="${2:-3}"
  waited=0
  while [ ! -s "$path" ]; do
    sleep 0.1
    waited=$(awk "BEGIN{print $waited+0.1}")
    if awk "BEGIN{exit !($waited > $timeout)}"; then
      return 1
    fi
  done
  return 0
}

# make_stub_bin <dir> — creates a fresh stub bin dir with a `claude` stub
# (prints "2.1.261 (Claude Code)") and a `curl` stub (records invocation to
# $CURL_CALLS_FILE, never touches the network, writes a minimal plugin.json
# to the -o target so callers parsing it succeed deterministically).
make_stub_bin() {
  stub_dir="$1"
  mkdir -p "$stub_dir"

  cat > "$stub_dir/claude" <<'EOS'
#!/usr/bin/env bash
if [ "${1:-}" = "--version" ]; then
  echo "2.1.261 (Claude Code)"
  exit 0
fi
exit 0
EOS
  chmod +x "$stub_dir/claude"

  cat > "$stub_dir/curl" <<EOS
#!/usr/bin/env bash
echo "called \$*" >> "\$CURL_CALLS_FILE"
# Parse -o TARGET out of the args and write a fixture plugin.json there.
out=""
prev=""
for a in "\$@"; do
  if [ "\$prev" = "-o" ]; then
    out="\$a"
  fi
  prev="\$a"
done
if [ -n "\$out" ]; then
  printf '{"version":"%s"}' "\${CURL_STUB_PUBLISHED_VERSION:-9.9.9}" > "\$out"
fi
exit 0
EOS
  chmod +x "$stub_dir/curl"
}

# run_case <name> — sets up isolated HOME/PLUGIN_ROOT/PATH, no execution here;
# caller runs the script itself and then asserts.
setup_case() {
  CASE_HOME="$(mktemp -d)"
  CASE_PLUGIN_ROOT="$(mktemp -d)"
  CASE_STUB_BIN="$(mktemp -d)"
  make_stub_bin "$CASE_STUB_BIN"
  export CURL_CALLS_FILE="$CASE_HOME/.curl_calls"
  : > "$CURL_CALLS_FILE"
  mkdir -p "$CASE_PLUGIN_ROOT/.claude-plugin"
}

cleanup_case() {
  rm -rf "$CASE_HOME" "$CASE_PLUGIN_ROOT" "$CASE_STUB_BIN" 2>/dev/null || true
}

write_installed_version() {
  printf '{\n  "name": "magic-claude-docs",\n  "version": "%s"\n}\n' "$1" \
    > "$CASE_PLUGIN_ROOT/.claude-plugin/plugin.json"
}

write_published_cache() {
  mkdir -p "$CASE_HOME/.claude-code-docs"
  printf '%s' "$1" > "$CASE_HOME/.claude-code-docs/.published-version"
}

write_stamp() {
  # $1 = age in seconds (how long ago the stamp should read)
  mkdir -p "$CASE_HOME/.claude-code-docs"
  now="$(date +%s)"
  stamp=$((now - $1))
  printf '%s' "$stamp" > "$CASE_HOME/.claude-code-docs/.published-version.fetched_at"
}

write_digest() {
  mkdir -p "$CASE_HOME/.claude-code-docs/digests"
  printf '%s' "$1" > "$CASE_HOME/.claude-code-docs/digests/latest"
}

run_script() {
  HOME="$CASE_HOME" \
  CLAUDE_PLUGIN_ROOT="$CASE_PLUGIN_ROOT" \
  PATH="$CASE_STUB_BIN:$PATH" \
  CURL_CALLS_FILE="$CURL_CALLS_FILE" \
  bash "$SCRIPT"
}

# --- Case (a): all equal -> empty stdout ------------------------------------
setup_case
write_installed_version "1.0.0"
write_published_cache "1.0.0"
write_digest "2.1.261"   # matches the claude stub's own version
out="$(run_script)"
if [ -z "$out" ]; then
  pass "(a) all equal -> empty stdout"
else
  fail "(a) all equal -> expected empty stdout, got: [$out]"
fi
cleanup_case

# --- Case (b): installed != cached published -> one line naming both -------
setup_case
write_installed_version "1.0.0"
write_published_cache "2.0.0"
write_digest "2.1.261"
out="$(run_script)"
if printf '%s' "$out" | grep -q "1.0.0" && printf '%s' "$out" | grep -q "2.0.0" \
   && [ "$(printf '%s' "$out" | grep -c .)" -le 1 ]; then
  pass "(b) plugin version mismatch -> one line naming both"
else
  fail "(b) plugin version mismatch -> unexpected output: [$out]"
fi
cleanup_case

# --- Case (b2): published newer -> hint says update; installed newer -> "ahead" ----
setup_case
write_installed_version "1.0.0"
write_published_cache "1.0.1"
write_digest "2.1.261"
out="$(run_script)"
if printf '%s' "$out" | grep -q "restart or /reload-plugins to update"; then
  pass "(b2) published newer -> update hint"
else
  fail "(b2) published newer -> expected update hint, got: [$out]"
fi
cleanup_case
setup_case
write_installed_version "1.0.1"
write_published_cache "1.0.0"
write_digest "2.1.261"
out="$(run_script)"
if printf '%s' "$out" | grep -q "ahead of published 1.0.0" \
   && ! printf '%s' "$out" | grep -q "reload-plugins"; then
  pass "(b3) installed newer -> ahead wording, no update hint"
else
  fail "(b3) installed newer -> expected ahead wording, got: [$out]"
fi
cleanup_case

# --- Case (c): claude != digested -> one line -------------------------------
setup_case
write_installed_version "1.0.0"
write_published_cache "1.0.0"
write_digest "2.0.0"   # differs from stub's 2.1.261
out="$(run_script)"
if printf '%s' "$out" | grep -q "2.1.261" && printf '%s' "$out" | grep -q "2.0.0" \
   && [ "$(printf '%s' "$out" | grep -c .)" -le 1 ]; then
  pass "(c) claude/digest mismatch -> one line"
else
  fail "(c) claude/digest mismatch -> unexpected output: [$out]"
fi
cleanup_case

# --- Case (d): both differ -> still exactly one line ------------------------
setup_case
write_installed_version "1.0.0"
write_published_cache "2.0.0"
write_digest "2.0.0"
out="$(run_script)"
nlines="$(printf '%s' "$out" | grep -c .)"
if [ "$nlines" -eq 1 ] && printf '%s' "$out" | grep -q "1.0.0" \
   && printf '%s' "$out" | grep -q "2.0.0" && printf '%s' "$out" | grep -q "2.1.261"; then
  pass "(d) both differ -> exactly one line"
else
  fail "(d) both differ -> expected exactly one line with all four versions, got: [$out] (nlines=$nlines)"
fi
cleanup_case

# --- Case (e): no cache file, no digest file -> empty stdout, exit 0, curl called once ---
setup_case
write_installed_version "1.0.0"
# no published cache, no digest, no stamp file -> cache considered stale -> refresh fires
out="$(run_script)"
rc=$?
if [ -z "$out" ] && [ "$rc" -eq 0 ]; then
  if wait_for_nonempty_file "$CURL_CALLS_FILE" 3; then
    calls="$(grep -c . "$CURL_CALLS_FILE")"
    if [ "$calls" -eq 1 ]; then
      pass "(e) no cache/digest -> empty stdout, exit 0, curl invoked once"
    else
      fail "(e) expected curl invoked exactly once, got $calls calls"
    fi
  else
    fail "(e) curl stub was never invoked (background refresh did not fire)"
  fi
else
  fail "(e) expected empty stdout and exit 0, got out=[$out] rc=$rc"
fi
cleanup_case

# --- Case (f): cache younger than 3h -> curl stub NOT invoked ---------------
setup_case
write_installed_version "1.0.0"
write_published_cache "1.0.0"
write_stamp 60   # 1 minute old, well under the 3h threshold
run_script >/dev/null
sleep 0.5
if [ ! -s "$CURL_CALLS_FILE" ]; then
  pass "(f) fresh cache -> curl stub not invoked"
else
  fail "(f) fresh cache -> curl stub was invoked unexpectedly: $(cat "$CURL_CALLS_FILE")"
fi
cleanup_case

# --- Case (g): claude missing from PATH, no versions dir -> still exit 0 ----
setup_case
write_installed_version "1.0.0"
write_published_cache "1.0.0"
EMPTY_BIN="$(mktemp -d)"
out="$(HOME="$CASE_HOME" CLAUDE_PLUGIN_ROOT="$CASE_PLUGIN_ROOT" \
       PATH="$EMPTY_BIN:/usr/bin:/bin" CURL_CALLS_FILE="$CURL_CALLS_FILE" \
       bash "$SCRIPT")"
rc=$?
rm -rf "$EMPTY_BIN"
if [ "$rc" -eq 0 ] && [ -z "$out" ]; then
  pass "(g) claude missing from PATH, no versions dir -> exit 0"
else
  fail "(g) expected exit 0 and empty stdout, got out=[$out] rc=$rc"
fi
cleanup_case

echo "---"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL TESTS PASSED"
  exit 0
else
  echo "SOME TESTS FAILED"
  exit 1
fi
