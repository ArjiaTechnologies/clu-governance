# Claude Code PreToolUse example

This is a project-local configuration example for the experimental CLU
Governance Claude Code adapter. It supports only existing-file `Edit` calls
for `README.md`. Copy its `.claude/` directory into a disposable project only
after reviewing the policy. See
[`docs/claude-code-pretooluse.md`](../../docs/claude-code-pretooluse.md) for
setup, disable, and complete uninstall steps.

The setup creates `.claude/settings.local.json`,
`.claude/clu-governance-policy.json`, and the project-local
`.claude/clu-governance-venv/` executable environment. It does not rely on an
activated shell environment. Remove only those CLU-specific paths or hook
entry when uninstalling; retain unrelated `.claude` configuration.

CLU `allow` remains eligible for separate approval only. The hook returns
Claude Code's `ask` decision; it does not automatically approve or apply an
edit.
