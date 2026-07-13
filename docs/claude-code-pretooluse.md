# Experimental Claude Code PreToolUse adapter

This optional integration is a thin, local command hook over CLU Governance's
agent-neutral `agent-preflight` contract. It is prepared for the unreleased
`0.1.0a3` candidate and supports one narrow shape:

- Claude Code `PreToolUse` events for the existing-file `Edit` tool;
- one unique `old_string` replacement (`replace_all: false`); and
- a project-local CLU source-mutation policy.

It contains no policy rules. It creates a temporary request and rollback
snapshot, calls the existing generic preflight evaluator, translates the
result into Claude Code's documented hook response, and removes the temporary
files before returning.

> **Experimental boundary:** this adapter is a local, composable preflight. It
> does not launch Claude Code, apply an edit, create approval, enforce
> behavior outside its configured hook, or turn CLU eligibility into automatic
> permission. `git-adapt` remains a separate experimental feature limited to
> trusted local, single-user macOS workflows; that limitation does not apply
> to this stdin/stdout Claude Code adapter.

## Compatibility and hook schema

The fixture contract was checked against the current official [Claude Code
Hooks reference](https://code.claude.com/docs/en/hooks) on 2026-07-13. It
uses the documented command-hook stdin fields for `PreToolUse`:

```json
{
  "cwd": "/absolute/project/root",
  "hook_event_name": "PreToolUse",
  "tool_name": "Edit",
  "tool_use_id": "toolu_example",
  "tool_input": {
    "file_path": "/absolute/project/root/README.md",
    "old_string": "before",
    "new_string": "after",
    "replace_all": false
  }
}
```

The adapter requires `cwd`, `hook_event_name`, `tool_name`, and `tool_input`.
It accepts the other documented common hook fields without depending on them.
Its configuration matches `Edit` exactly, so Bash, MCP, notebook, unknown,
and other tool calls are not claimed as governed. If the command is invoked
directly for another tool, it returns an explicit `ask` response and leaves
the normal Claude Code permission flow in charge.

The hook fields and response shape were checked against the official
[Claude Code Hooks reference](https://code.claude.com/docs/en/hooks) on
2026-07-13. The latest version listed by the official changelog at that time
was Claude Code `2.1.205`. No live Claude Code executable or authenticated
session was available in this release-engineering environment, so a minimum
compatible Claude Code version has not yet been independently established. The
first external disposable-project test will record the tester's installed
version. Claude Code `2.1.89` introduced the `defer` PreToolUse decision, but
this adapter does not use `defer` and does not treat that version as a
compatibility anchor. CI runs the adapter's portable stdin/stdout contract on
Ubuntu Linux/x86_64 with Python 3.12.

## Decision mapping

The official [hooks guide](https://code.claude.com/docs/en/hooks-guide)
documents structured `PreToolUse` output with exit code `0`. CLU uses that
shape deliberately:

| CLU preflight result | Claude hook response | Meaning |
| --- | --- | --- |
| `allow` / eligible | `permissionDecision: "ask"` | The edit remains subject to Claude Code's normal permission prompt. This is **not** automatic approval. |
| policy `deny` | `permissionDecision: "deny"` | The edit is blocked with the CLU blocker and a next step. |
| malformed hook input, missing policy, source mismatch, or bounded local failure | `permissionDecision: "deny"` | The adapter fails closed with a stable local blocker and a correction step. |
| non-`Edit` tool (direct invocation only) | `permissionDecision: "ask"` | No CLU governance verdict is claimed; the configured matcher normally prevents this invocation. |

The adapter never emits `permissionDecision: "allow"`. A CLU `allow` means
only eligible for a separate approval or permission decision; it does not
authorize or apply a mutation.

## Setup on Ubuntu Linux/x86_64

Use Python 3.12 and an existing local CLU Governance checkout. The adapter
itself has no runtime network call, no daemon, no global cache, no keychain
entry, and no background service. The following project-local installation is
for Linux and macOS; Windows has not been tested for this experimental
integration.

```bash
# In the disposable Claude Code project you want to test:
mkdir -p .claude
python3.12 -m venv .claude/clu-governance-venv
.claude/clu-governance-venv/bin/python -m pip install --no-deps --no-cache-dir /absolute/path/to/clu-governance
cp /absolute/path/to/clu-governance/examples/claude-code-pretooluse/.claude/settings.local.json .claude/settings.local.json
cp /absolute/path/to/clu-governance/examples/claude-code-pretooluse/.claude/clu-governance-policy.json .claude/clu-governance-policy.json
```

The committed example is deliberately project-local and uses the documented
command-hook exec form. With `args` present, Claude Code directly executes the
exact project-local executable and receives a separate argument vector; no
shell, activation step, pipe, redirect, or command chaining is involved:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "${CLAUDE_PROJECT_DIR}/.claude/clu-governance-venv/bin/clu-governance",
            "args": [
              "claude-pretooluse",
              "--policy",
              "${CLAUDE_PROJECT_DIR}/.claude/clu-governance-policy.json"
            ],
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

The sample policy allows only `README.md` modification by declared actor
`claude_code` in scope `claude_code_edit`. Copy and review it before widening
paths or rules. The adapter does not create either configuration file.

The `--policy` argument must be an absolute path. The committed Claude Code
configuration uses `${CLAUDE_PROJECT_DIR}`, which Claude expands to an
absolute project path automatically. Direct CLI testers must supply an
absolute policy path themselves.

### Safe disposable-project check

In a disposable project containing `README.md`, ask Claude Code to replace a
unique sentence in that file. With the sample policy, the adapter should
return `ask`; Claude Code's normal prompt remains the only permission path.
Ask for an edit to another file (for example `notes.txt`) and the adapter
should return `deny` with `path_not_explicitly_allowed`. Neither result
applies the edit itself, writes an approval record, starts another agent, or
leaves a CLU evidence file.

## Troubleshooting

If you invoke `claude-pretooluse` directly instead of through the committed
Claude Code configuration, pass an absolute path to `--policy`. Claude Code
expands `${CLAUDE_PROJECT_DIR}` to an absolute project path for the committed
hook configuration, but a direct CLI invocation does not perform that
expansion for you.

## State, disable, and uninstall

### Runtime-created default state

Default operation creates zero residual CLU state. For one hook invocation it
creates only a request JSON file and a rollback snapshot in a private
temporary directory, then removes that directory before writing its one JSON
response. It creates no evidence artifact, source file, approval artifact,
repository hook, cache, database, daemon, service, keychain entry, global
configuration, or network connection.

### User-created setup state

The documented setup creates only these project-local paths:

- `.claude/settings.local.json` — the Claude Code hook setting;
- `.claude/clu-governance-policy.json` — the CLU policy copied from the
  example; and
- `.claude/clu-governance-venv/` — the isolated CLU executable used by the
  hook.

An optional caller-selected redirected output file is also user-created if a
caller explicitly redirects stdout outside normal Claude Code operation.

To disable the integration, remove the `PreToolUse` entry from
`.claude/settings.local.json` (or set the documented Claude Code
`"disableAllHooks": true` in that project settings file). Claude Code also
provides `/hooks` to inspect configured hooks.

To uninstall it completely, remove only the CLU `PreToolUse` hook entry (do
not delete unrelated `.claude` configuration), remove
`.claude/clu-governance-policy.json`, remove
`.claude/clu-governance-venv/`, and remove any optional caller-created output
file. There is no daemon, global state, or CLU-created residual directory to
clean up.

## Limits and future adapters

This initial adapter intentionally does not model `Write`, Bash, MCP tools,
notebook tools, compound commands, or arbitrary filesystem effects. A future
adapter must keep this same division: agent input/output translation belongs
in the adapter, while policy evaluation remains in `agent-preflight` and the
existing evaluator.

For optional signed evidence beyond this local contract, see [Future signed
evidence](future-signed-evidence.md).
