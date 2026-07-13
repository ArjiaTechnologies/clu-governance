# CLI Contract

Distribution version: `0.1.0a2`
Executable: `clu-governance`

`--version` prints `clu-governance 0.1.0a2`. Valid `--json` commands write one complete JSON object to stdout. Usage errors use stderr and exit `2`; governed denials and structural blocks also use exit `2`; bounded unexpected failures use exit `1`.

## Core commands

- `evaluate` evaluates a request against a local policy and writes a decision artifact. It does not mutate source.
- `agent-preflight` reads one strict JSON envelope from stdin and writes one existing policy-decision JSON object to stdout. It does not write an artifact, record approval, apply a mutation, start an agent, or start a subprocess.
- `verify` verifies a decision artifact hash.
- `demo-init`, `demo-approve`, `demo-execute`, and `demo-run-all` implement the deterministic local demonstration workflow.
- `protected-source-manifest` reports exact active package/distribution ownership without modifying files.
- `verify-bundle` checks the currently observed local adapter bundle without modifying it. An initially nonexistent requested bundle path returns `bundle_path_missing`; a symlinked ancestor remains blocked as `bundle_parent_symlink_or_identity_denied`. Once a path has been bound for verification, later disappearance or replacement is reported with its replacement-specific path-binding blocker rather than as an initial missing path; replacing the bound root changes the retained parent namespace and returns `bundle_parent_identity_changed`.
- `git-adapt` is an experimental trusted-local adapter for one supported working-tree edit; it does not apply, stage, commit, push, or fetch.

Run `clu-governance <command> --help` for required arguments and detailed help. An allow decision means eligibility for a separate approval step, not approval or permission to apply a mutation.

## Generic agent preflight

`agent-preflight` is the agent-neutral, read-only pre-tool contract. It is intentionally a thin wrapper around the same evaluator used by `evaluate`, so it does not implement a second policy engine or enforce a particular coding agent. It does not start a daemon, service, agent process, or background task.

It is composable evidence before a caller's tool action, not agent enforcement. A caller may use an allow result to decide whether to offer a separate approval or application step. CLU neither approves nor invokes that later step.

Pass exactly one UTF-8 JSON object on stdin:

```json
{
  "schema_name": "clu_governance_agent_preflight_input.v1",
  "schema_version": "1",
  "policy_path": "/absolute/path/to/policy.json",
  "request_path": "/absolute/path/to/request.json",
  "source_root": "/absolute/path/to/controlled-source",
  "event_timestamp": "2026-06-26T00:00:00Z",
  "sequence_index": 1
}
```

All three path fields must be absolute strings. `event_timestamp` must be a nonempty string and `sequence_index` must be a positive integer. The supplied timestamp and sequence index make the adapter invocation reproducible against unchanged local inputs. The envelope must have exactly these fields: unknown, missing, duplicate, malformed, and trailing JSON input are rejected.

The command writes exactly one JSON object to stdout and writes no diagnostic text there. `--json` is accepted for CLI consistency, but the command always uses JSON output.

### Allow output

The result is the existing `clu_governance_source_mutation_policy_decision.v1` evidence object. This representative allow output shows the contract fields most relevant to a pre-tool caller; the complete object also contains the checked operations, execution binding, and `audit_event_hash`.

```json
{
  "schema_name": "clu_governance_source_mutation_policy_decision.v1",
  "decision": "allow",
  "reason_code": "eligible_for_human_approval",
  "eligible_for_human_approval": true,
  "operator_approval_required": true,
  "mutation_authorized": false,
  "mutation_applied": false,
  "policy_hash": "<sha256>",
  "canonical_request_hash": "<sha256>",
  "proposal_hash_supplied": "<sha256>",
  "proposal_hash_verified": "<sha256>",
  "source_hash_supplied": "<sha256>",
  "source_hash_verified": "<sha256>",
  "rollback_readiness_verified": true,
  "network_calls": 0,
  "provider_calls": 0
}
```

### Deny output

Policy denials retain the same evidence schema and use a precise blocker. They are completed evaluations, not malformed adapter input.

```json
{
  "schema_name": "clu_governance_source_mutation_policy_decision.v1",
  "decision": "deny",
  "reason_code": "delete_operation_denied",
  "exact_blocker": "delete_operation_denied",
  "eligible_for_human_approval": false,
  "mutation_authorized": false,
  "mutation_applied": false,
  "rollback_readiness_verified": false
}
```

### Error output and exit codes

Malformed input and bounded local failures use `clu_governance_agent_preflight_error.v1`. They do not expose caller paths in the result.

| Exit | Meaning | Stdout schema |
| --- | --- | --- |
| `0` | Evaluation completed and the request is eligible for separate approval. | `clu_governance_source_mutation_policy_decision.v1` with `decision: "allow"` |
| `2` | Evaluation completed and the policy denied the request. | `clu_governance_source_mutation_policy_decision.v1` with `decision: "deny"` |
| `1` | Strict envelope input was malformed or a bounded local evaluation failure occurred. | `clu_governance_agent_preflight_error.v1` |

For an input error, `result` is `input_rejected`; examples of stable blockers include `agent_preflight_input_duplicate_json_key`, `agent_preflight_input_required_field_missing`, and `agent_preflight_input_unknown_field`. A bounded evaluator failure reports `result: "failed"` with `agent_preflight_evaluation_failed`. Diagnostics remain off stdout.

### Shell integration shape

The caller controls any later tool. This example uses stdout as in-memory evidence and deliberately does not execute the placeholder later command when policy denies the request:

```bash
if evidence="$(clu-governance agent-preflight --json < preflight-input.json)"; then
  printf '%s\n' "$evidence"
  # The caller may now request separate approval or run its own later command.
  # CLU does not run that command.
else
  status=$?
  printf '%s\n' "$evidence"
  if [ "$status" -eq 2 ]; then
    printf '%s\n' 'Policy denied: later command was not run.' >&2
  else
    printf '%s\n' 'Preflight input or local evaluation failed.' >&2
  fi
fi
```

Redirecting stdout to a file is optional caller-selected persistence, for example `> evidence.json`. CLU creates no evidence file itself.

### State and uninstall

By default, `agent-preflight` creates no files, directories, approval artifacts, caches, databases, daemon sockets, services, hooks, keychain entries, or global configuration. It reads the caller-supplied policy/request/source paths and writes one JSON result to stdout. It has no hidden persistent state.

To remove an integration, remove the caller's shell or CI invocation, any caller-created envelope or redirected evidence file, and the CLU package or virtual environment if it is no longer needed. There is no CLU-created preflight state to remove.

### Future adapter boundary

Future thin adapters for Claude Code, Copilot CLI, OpenHands, Codex, Cursor, Aider, or another agent surface may construct this same envelope before their own tool call and consume the JSON evidence. They must remain separate packages or layers: this command is vendor-neutral and does not launch, configure, or claim to enforce any named agent.

`agent-preflight` never records approval, creates an approval artifact, or applies a mutation. A caller must keep approval and any application step separate.
