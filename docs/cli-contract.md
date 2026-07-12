# CLI Contract

Distribution version: `0.1.0a1`  
Executable: `clu-governance`

`--version` prints `clu-governance 0.1.0a1`. Valid `--json` commands write one complete JSON object to stdout. Usage errors use stderr and exit `2`; governed denials and structural blocks also use exit `2`; bounded unexpected failures use exit `1`.

## Core commands

- `evaluate` evaluates a request against a local policy and writes a decision artifact. It does not mutate source.
- `verify` verifies a decision artifact hash.
- `demo-init`, `demo-approve`, `demo-execute`, and `demo-run-all` implement the deterministic local demonstration workflow.
- `protected-source-manifest` reports exact active package/distribution ownership without modifying files.
- `verify-bundle` checks the currently observed local adapter bundle without modifying it. An initially nonexistent requested bundle path returns `bundle_path_missing`; a symlinked ancestor remains blocked as `bundle_parent_symlink_or_identity_denied`. Once a path has been bound for verification, later disappearance or replacement is reported with its replacement-specific path-binding blocker rather than as an initial missing path; replacing the bound root changes the retained parent namespace and returns `bundle_parent_identity_changed`.
- `git-adapt` is an experimental trusted-local adapter for one supported working-tree edit; it does not apply, stage, commit, push, or fetch.

Run `clu-governance <command> --help` for required arguments and detailed help. An allow decision means eligibility for a separate approval step, not approval or permission to apply a mutation.
