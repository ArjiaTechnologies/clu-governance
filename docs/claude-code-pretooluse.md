# Experimental Claude Code PreToolUse adapter

This optional integration is a thin, local command hook over CLU Governance's
agent-neutral `agent-preflight` contract. It supports one narrow shape:

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

The versioned fixture target is Claude Code `2.1.89`: the current official
changelog identifies that release as adding the `defer` PreToolUse decision.
This adapter uses only the ordinary `ask` and `deny` decisions; it does not use
`defer` or `if` filtering. No `claude` executable was installed in this
release-engineering environment, so `2.1.89` is a fixture-level schema target,
not a claim of a live authenticated Claude Code session test. CI runs the
adapter's portable stdin/stdout contract on Ubuntu Linux/x86_64 with Python
3.12.

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

Use Python 3.12 and a local checkout. The adapter itself has no runtime
network call, no daemon, no global cache, no keychain entry, and no background
service.

```bash
git clone https://github.com/ArjiaTechnologies/clu-governance.git
cd clu-governance
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install .

# In the Claude Code project you want to test:
mkdir -p .claude
cp /path/to/clu-governance/examples/claude-code-pretooluse/.claude/settings.local.json .claude/settings.local.json
cp /path/to/clu-governance/examples/claude-code-pretooluse/.claude/clu-governance-policy.json .claude/clu-governance-policy.json
```

The committed example is deliberately project-local:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "clu-governance claude-pretooluse --policy \"$CLAUDE_PROJECT_DIR/.claude/clu-governance-policy.json\""
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

### Safe disposable-project check

In a disposable project containing `README.md`, ask Claude Code to replace a
unique sentence in that file. With the sample policy, the adapter should
return `ask`; Claude Code's normal prompt remains the only permission path.
Ask for an edit to another file (for example `notes.txt`) and the adapter
should return `deny` with `path_not_explicitly_allowed`. Neither result
applies the edit itself, writes an approval record, starts another agent, or
leaves a CLU evidence file.

## State, disable, and uninstall

Default operation creates zero residual CLU state. For one hook invocation it
creates only a request JSON file and a rollback snapshot in a private
temporary directory, then removes that directory before writing its one JSON
response. It creates no evidence artifact, source file, approval artifact,
repository hook, cache, database, daemon, service, keychain entry, global
configuration, or network connection.

Files a user may create explicitly:

- `.claude/settings.local.json` — the project-local Claude Code hook setting;
- `.claude/clu-governance-policy.json` — the project-local policy copied from
  the example; and
- an optional caller-selected redirected stdout file, if the caller chooses to
  persist hook output outside normal Claude Code operation.

To disable the integration, remove the `PreToolUse` entry from
`.claude/settings.local.json` (or set the documented Claude Code
`"disableAllHooks": true` in that project settings file). Claude Code also
provides `/hooks` to inspect configured hooks.

To uninstall it completely, delete the two project-local files above, remove
the CLU virtual environment or package if no other CLU workflow needs it, and
remove any caller-created redirected output file. There is no daemon, global
state, or CLU-created residual directory to clean up.

## Limits and future adapters

This initial adapter intentionally does not model `Write`, Bash, MCP tools,
notebook tools, compound commands, or arbitrary filesystem effects. A future
adapter must keep this same division: agent input/output translation belongs
in the adapter, while policy evaluation remains in `agent-preflight` and the
existing evaluator.

For optional signed evidence beyond this local contract, see [Future signed
evidence](future-signed-evidence.md).
