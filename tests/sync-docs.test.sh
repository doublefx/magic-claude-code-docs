#!/usr/bin/env bash
# Tests for plugin/hooks/sync-docs.sh
#
# Run: bash tests/sync-docs.test.sh
# Exit 0 on success; non-zero with the failing case named on stdout.
#
# Each case gets its own temp HOME and temp CLAUDE_PLUGIN_ROOT (a fake
# plugin.json + a small fake docs/ tree with 3 files including
# docs_manifest.json). No network, no jq dependency assumed either way —
# whichever extract_json_version path this machine takes, both the script
# and the fixtures agree on the version string produced.

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/plugin/hooks/sync-docs.sh"

FAILED=0
fail() {
  echo "FAIL: $1"
  FAILED=1
}
pass() {
  echo "PASS: $1"
}

# make_fake_plugin_root <dir> <version> — a plugin root with .claude-plugin/
# plugin.json at <version> and a docs/ tree of 3 files incl. a manifest.
make_fake_plugin_root() {
  root="$1"
  version="$2"
  mkdir -p "$root/.claude-plugin" "$root/docs"
  cat > "$root/.claude-plugin/plugin.json" <<EOS
{
  "name": "magic-claude-docs",
  "version": "$version"
}
EOS
  echo "doc one" > "$root/docs/a.md"
  echo "doc two" > "$root/docs/b.md"
  echo '{"files":{}}' > "$root/docs/docs_manifest.json"
}

# run_hook <home> <plugin_root> — runs the script with HOME and
# CLAUDE_PLUGIN_ROOT set, capturing exit code to a file and reading it back
# (never trusting a piped $?).
run_hook() {
  home="$1"
  plugin_root="$2"
  outfile="$3"
  exitfile="$4"
  ( HOME="$home" CLAUDE_PLUGIN_ROOT="$plugin_root" bash "$SCRIPT" >"$outfile" 2>&1 )
  echo "$?" > "$exitfile"
}

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# --- Case (a): first run copies everything, writes the marker -------------
HOME_A="$WORKDIR/home_a"
PLUGIN_A="$WORKDIR/plugin_a"
mkdir -p "$HOME_A"
make_fake_plugin_root "$PLUGIN_A" "1.0.0"

OUT_A="$WORKDIR/out_a.txt"
EXIT_A="$WORKDIR/exit_a.txt"
run_hook "$HOME_A" "$PLUGIN_A" "$OUT_A" "$EXIT_A"
CODE_A="$(cat "$EXIT_A")"

D_A="$HOME_A/.claude-code-docs"
if [ "$CODE_A" = "0" ] \
   && [ -f "$D_A/a.md" ] && [ -f "$D_A/b.md" ] && [ -f "$D_A/docs_manifest.json" ] \
   && [ -f "$D_A/.magic-claude-docs-plugin" ] \
   && [ "$(cat "$D_A/.magic-claude-docs-plugin")" = "1.0.0" ]; then
  pass "(a) first run copies all files and writes the version into the marker"
else
  fail "(a) first run copies all files and writes the version into the marker (exit=$CODE_A)"
fi

# also plant a survivor dotfile here, used by case (e) below
echo "cached-published-version" > "$D_A/.published-version"

# --- Case (b): second run, same version — no mtime changes, marker stable -
# Capture mtimes before the second run.
mtimes_before="$(cd "$D_A" && stat -c '%n %Y' a.md b.md docs_manifest.json .magic-claude-docs-plugin | sort)"
sleep 1 # ensure any accidental rewrite would be observable via mtime

OUT_B="$WORKDIR/out_b.txt"
EXIT_B="$WORKDIR/exit_b.txt"
run_hook "$HOME_A" "$PLUGIN_A" "$OUT_B" "$EXIT_B"
CODE_B="$(cat "$EXIT_B")"

mtimes_after="$(cd "$D_A" && stat -c '%n %Y' a.md b.md docs_manifest.json .magic-claude-docs-plugin | sort)"

if [ "$CODE_B" = "0" ] && [ ! -s "$OUT_B" ] \
   && [ "$mtimes_before" = "$mtimes_after" ] \
   && [ "$(cat "$D_A/.magic-claude-docs-plugin")" = "1.0.0" ]; then
  pass "(b) second run, same version: no file mtime changes, marker unchanged, no output"
else
  fail "(b) second run, same version: no file mtime changes, marker unchanged, no output (exit=$CODE_B mtimes_before=[$mtimes_before] mtimes_after=[$mtimes_after])"
fi

# --- Case (c): version changes -> re-copy (added file appears, stale file removed)
# Bump the fake plugin.json's version, add a new doc, remove b.md from source.
cat > "$PLUGIN_A/.claude-plugin/plugin.json" <<EOS
{
  "name": "magic-claude-docs",
  "version": "2.0.0"
}
EOS
rm -f "$PLUGIN_A/docs/b.md"
echo "doc three" > "$PLUGIN_A/docs/c.md"

OUT_C="$WORKDIR/out_c.txt"
EXIT_C="$WORKDIR/exit_c.txt"
run_hook "$HOME_A" "$PLUGIN_A" "$OUT_C" "$EXIT_C"
CODE_C="$(cat "$EXIT_C")"

if [ "$CODE_C" = "0" ] \
   && [ -f "$D_A/c.md" ] && [ ! -f "$D_A/b.md" ] \
   && [ "$(cat "$D_A/.magic-claude-docs-plugin")" = "2.0.0" ]; then
  pass "(c) version change re-copies: new file appears, stale file removed"
else
  fail "(c) version change re-copies: new file appears, stale file removed (exit=$CODE_C)"
fi

# --- Case (e), checked here since the survivor must persist across (b)/(c) -
if [ -f "$D_A/.published-version" ] && [ "$(cat "$D_A/.published-version")" = "cached-published-version" ]; then
  pass "(e) .published-version dotfile survives re-copies"
else
  fail "(e) .published-version dotfile survives re-copies"
fi

# --- Case (d): marker present, correct version, but docs_manifest.json missing -> copies
HOME_D="$WORKDIR/home_d"
PLUGIN_D="$WORKDIR/plugin_d"
mkdir -p "$HOME_D/.claude-code-docs"
make_fake_plugin_root "$PLUGIN_D" "3.0.0"
echo -n "3.0.0" > "$HOME_D/.claude-code-docs/.magic-claude-docs-plugin"
# docs_manifest.json deliberately absent from the target
# plant a stale marker-only state, no other docs present
echo "stale" > "$HOME_D/.claude-code-docs/stale.md"

OUT_D="$WORKDIR/out_d.txt"
EXIT_D="$WORKDIR/exit_d.txt"
run_hook "$HOME_D" "$PLUGIN_D" "$OUT_D" "$EXIT_D"
CODE_D="$(cat "$EXIT_D")"

if [ "$CODE_D" = "0" ] && [ -f "$HOME_D/.claude-code-docs/docs_manifest.json" ] \
   && [ ! -f "$HOME_D/.claude-code-docs/stale.md" ]; then
  pass "(d) marker matches but docs_manifest.json missing -> copies"
else
  fail "(d) marker matches but docs_manifest.json missing -> copies (exit=$CODE_D)"
fi

# --- Case (g): digests/ and types/ under the target survive a version re-copy
HOME_G="$WORKDIR/home_g"
PLUGIN_G="$WORKDIR/plugin_g"
mkdir -p "$HOME_G/.claude-code-docs"
make_fake_plugin_root "$PLUGIN_G" "1.0.0"
run_hook "$HOME_G" "$PLUGIN_G" "$WORKDIR/out_g1.txt" "$WORKDIR/exit_g1.txt"
mkdir -p "$HOME_G/.claude-code-docs/digests" "$HOME_G/.claude-code-docs/types/1.2.3"
echo -n "2.1.261" > "$HOME_G/.claude-code-docs/digests/latest"
echo -n "x" > "$HOME_G/.claude-code-docs/types/1.2.3/claude-code.d.ts"
make_fake_plugin_root "$PLUGIN_G" "1.0.1"
run_hook "$HOME_G" "$PLUGIN_G" "$WORKDIR/out_g2.txt" "$WORKDIR/exit_g2.txt"
if [ -f "$HOME_G/.claude-code-docs/digests/latest" ] && [ -f "$HOME_G/.claude-code-docs/types/1.2.3/claude-code.d.ts" ] \
   && [ "$(cat "$HOME_G/.claude-code-docs/.magic-claude-docs-plugin")" = "1.0.1" ] \
   && [ -f "$HOME_G/.claude-code-docs/docs_manifest.json" ]; then
  pass "(g) digests/ and types/ survive a version re-copy"
else
  fail "(g) digests/ and types/ were wiped by the re-copy"
fi

# --- Case (f): CLAUDE_PLUGIN_ROOT/docs absent -> exit 0, nothing created ---
HOME_F="$WORKDIR/home_f"
PLUGIN_F="$WORKDIR/plugin_f"
mkdir -p "$HOME_F" "$PLUGIN_F/.claude-plugin"
cat > "$PLUGIN_F/.claude-plugin/plugin.json" <<'EOS'
{ "name": "magic-claude-docs", "version": "1.0.0" }
EOS
# deliberately no docs/ dir under PLUGIN_F

OUT_F="$WORKDIR/out_f.txt"
EXIT_F="$WORKDIR/exit_f.txt"
run_hook "$HOME_F" "$PLUGIN_F" "$OUT_F" "$EXIT_F"
CODE_F="$(cat "$EXIT_F")"

if [ "$CODE_F" = "0" ] && [ ! -s "$OUT_F" ] && [ ! -d "$HOME_F/.claude-code-docs" ]; then
  pass "(f) plugin docs/ absent: exit 0, nothing created"
else
  fail "(f) plugin docs/ absent: exit 0, nothing created (exit=$CODE_F)"
fi

# --- Mutation proof: break the skip condition, show (b)'s case fail, restore --
SAVED_SCRIPT="$WORKDIR/sync-docs.sh.saved"
cp -f "$SCRIPT" "$SAVED_SCRIPT"

# Force an unconditional copy by short-circuiting the skip check to false.
sed -i.bak 's/^if \[ -n "\$installed_version" \] && \[ -n "\$marker_version" \] \\/if false \&\& [ -n "$installed_version" ] \&\& [ -n "$marker_version" ] \\/' "$SCRIPT"
rm -f "$SCRIPT.bak"

HOME_M="$WORKDIR/home_m"
PLUGIN_M="$WORKDIR/plugin_m"
mkdir -p "$HOME_M"
make_fake_plugin_root "$PLUGIN_M" "1.0.0"

OUT_M1="$WORKDIR/out_m1.txt"
EXIT_M1="$WORKDIR/exit_m1.txt"
run_hook "$HOME_M" "$PLUGIN_M" "$OUT_M1" "$EXIT_M1"

D_M="$HOME_M/.claude-code-docs"
mtimes_m_before="$(cd "$D_M" && stat -c '%n %Y' a.md b.md docs_manifest.json | sort)"
sleep 1

OUT_M2="$WORKDIR/out_m2.txt"
EXIT_M2="$WORKDIR/exit_m2.txt"
run_hook "$HOME_M" "$PLUGIN_M" "$OUT_M2" "$EXIT_M2"

mtimes_m_after="$(cd "$D_M" && stat -c '%n %Y' a.md b.md docs_manifest.json | sort)"

if [ "$mtimes_m_before" != "$mtimes_m_after" ]; then
  echo "MUTATION-PROOF: (b) fails on the broken skip condition, as expected (mtimes changed)"
else
  fail "MUTATION-PROOF: expected (b) to fail on the broken script, but mtimes stayed identical — the mutation test is not sensitive to this defect"
fi

# Restore byte-identical and prove it via diff.
cp -f "$SAVED_SCRIPT" "$SCRIPT"
if diff -q "$SAVED_SCRIPT" "$SCRIPT" >/dev/null 2>&1; then
  echo "RESTORE: script restored byte-identical (diff -q clean)"
else
  fail "RESTORE: script did not restore byte-identical to its saved copy"
fi

# Re-run case (b) against the restored script to prove green again.
HOME_R="$WORKDIR/home_r"
PLUGIN_R="$WORKDIR/plugin_r"
mkdir -p "$HOME_R"
make_fake_plugin_root "$PLUGIN_R" "1.0.0"

OUT_R1="$WORKDIR/out_r1.txt"
EXIT_R1="$WORKDIR/exit_r1.txt"
run_hook "$HOME_R" "$PLUGIN_R" "$OUT_R1" "$EXIT_R1"

D_R="$HOME_R/.claude-code-docs"
mtimes_r_before="$(cd "$D_R" && stat -c '%n %Y' a.md b.md docs_manifest.json | sort)"
sleep 1

OUT_R2="$WORKDIR/out_r2.txt"
EXIT_R2="$WORKDIR/exit_r2.txt"
run_hook "$HOME_R" "$PLUGIN_R" "$OUT_R2" "$EXIT_R2"

mtimes_r_after="$(cd "$D_R" && stat -c '%n %Y' a.md b.md docs_manifest.json | sort)"

if [ "$mtimes_r_before" = "$mtimes_r_after" ]; then
  pass "RESTORE-VERIFY: (b) is green again on the restored script"
else
  fail "RESTORE-VERIFY: (b) still fails on the restored script"
fi

echo "---"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL PASS"
  exit 0
else
  echo "SOME FAILED"
  exit 1
fi
