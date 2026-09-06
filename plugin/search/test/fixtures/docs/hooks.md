# Hooks

Hooks let you run a command at specific points in the session lifecycle.

## Blocking a tool call

To cancel a tool's execution before it finishes, a PreToolUse hook can exit
with status code 2. The harness reads that exit code and refuses to run the
tool, showing your stderr text to the model as the reason.

## Session start

A SessionStart hook runs once when a new session begins, before the first
prompt is processed.
