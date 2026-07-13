# CLI Contract

Distribution version: `0.1.0a1`  
Executable: `clu-governance`

`--version` prints `clu-governance 0.1.0a1`. Valid `--json` commands write one complete JSON object to stdout. Usage errors use stderr and exit `2`; governed denials and structural blocks also use exit `2`; bounded unexpected failures use exit `1`.

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

`agent-preflight` is the agent-neutral stdin/stdout bridge. It is intentionally a thin wrapper around the same evaluator used by `evaluate`, so it does not implement a second policy engine.

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

All three path fields must be absolute. The supplied timestamp and sequence index make the adapter invocation reproducible against unchanged local inputs. Unknown, missing, or duplicate input fields are rejected.

The command writes exactly one JSON object to stdout:

- On eligibility, it writes the existing `clu_governance_source_mutation_policy_decision.v1` evidence object with `decision: "allow"`, `eligible_for_human_approval: true`, `mutation_authorized: false`, and `mutation_applied: false`.
- On policy denial, it writes the same evidence schema with `decision: "deny"` and exits `2`.
- On invalid adapter input, it writes `clu_governance_agent_preflight_error.v1` and exits `2`.
- On an unexpected local evaluation failure, it writes the bounded error schema and exits `1`.

`agent-preflight` never records approval or applies a mutation. A caller must keep approval and any application step separate.
