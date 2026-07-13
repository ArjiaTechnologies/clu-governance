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

The `--policy` argument must be an absolute path. The committed Claude Code
configuration uses `${CLAUDE_PROJECT_DIR}`, which Claude expands to an
absolute project path automatically. Direct CLI testers must supply an
absolute policy path themselves.

CLU `allow` remains eligible for separate approval only. The hook returns
Claude Code's `ask` decision; it does not automatically approve or apply an
edit.
