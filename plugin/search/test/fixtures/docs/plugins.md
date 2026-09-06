# Plugins

A plugin bundles skills, agents, hooks, and MCP servers into one installable
unit.

## Skill locations

Plugin skills live under a `skills/` directory inside the plugin package, one
subdirectory per skill, each with its own SKILL.md.

## Environment variables

A plugin's hooks and commands can read `CLAUDE_PLUGIN_ROOT`, which points at
the plugin's own installed directory.
