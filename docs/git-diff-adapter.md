# Experimental Git Adapter

> **Warning:** `git-adapt` is experimental and intended for trusted local repositories in single-user workflows. It is not a sandbox and does not defend against a malicious Git executable, hostile local process, operating-system administrator, concurrent same-user filesystem modification, or tampering after point-in-time verification.

The adapter reads one supported tracked, unstaged UTF-8 text modification from a local Git working tree and writes a local evidence bundle outside the repository. It does not apply, stage, commit, push, fetch, or approve a source change.

## Supported boundary

The documented boundary is macOS with CPython 3.12 and a local Git executable. The repository must have an existing `HEAD`, a clean stage-zero index, no ordinary or ignored untracked paths, and exactly one supported working-tree modification. Binary, symlink, submodule, multi-file, staged, conflicted, sparse, partial/promisor, reftable, and other unsupported repository states fail closed.

On an unsupported platform, `git-adapt --help` remains available but an execution attempt returns a JSON `blocked` result with `exact_blocker` `content_sensitive_git_sandbox_unavailable`. It does not complete a bundle or apply a repository mutation. Linux CI verifies that fail-closed contract; successful adapter integration is tested on macOS only.

The generated bundle contains a selected baseline file, request, rollback snapshot, provenance, preview, policy decision, checksums, and completion record. `verify-bundle` checks the currently observed bundle before a consumer uses it.

## Example

```bash
clu-governance git-adapt \
  --repo /path/to/trusted-local-repository \
  --policy examples/example_source_mutation_policy.json \
  --declared-actor-id local_operator \
  --scope docs_only \
  --output-dir /path/outside/repository/governance-bundle \
  --json
```

An allow decision remains eligible for separate approval only. Adapter output is local technical evidence, not a signature, authenticated origin record, immutable bundle, or proof of repository ownership.
