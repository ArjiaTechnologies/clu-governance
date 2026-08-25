# Architecture Overview

CLU Governance is a local Python package with a command-line interface.

```text
request + policy + source state
            |
            v
  deny-by-default policy evaluation
            |
            v
 decision and rollback-readiness evidence
            |
            +-- allow means eligible for separate approval
            +-- deny blocks the demonstrated workflow
```

The core modules evaluate requests, bind evidence with hashes, validate strict JSON, and run the deterministic demo. The protected-source manifest identifies the active CLU package and relevant metadata. The bundle verifier checks currently observed adapter bundles. The `git-adapt` module is an optional experimental integration that reads one supported local Git working-tree change and emits a local bundle; it does not apply, commit, push, or fetch changes.

## Canonical unsigned evidence

`evidence-envelope` accepts an existing evaluator decision and wraps it in a
strict, domain-separated SHA-256 envelope. The body cross-binds the original
decision hash, policy, request, proposal, source-tree snapshot, and, for an
allowed decision, the validated rollback and execution projections.
`verify-evidence-envelope` independently checks the exact schema, canonical
digest, internal decision and execution hashes, normalized paths, and approval
separation entirely offline.

Both commands consume stdin and produce stdout without writing files, evaluating
policy again, approving, applying, authenticating, signing, witnessing a
timestamp, or starting a network call. The envelope provides local integrity
evidence only; it is neither a signature nor immutable storage.

## Agent-neutral preflight seam

`agent-preflight` is a read-only stdin/stdout seam before a caller's tool action. It validates one strict envelope and delegates to the existing source-mutation evaluator, returning the evaluator's evidence without creating an approval artifact or persistent state. Future thin adapters may translate an agent's own pre-tool event into this envelope and act on the result themselves. They are not part of the core contract: CLU does not start, configure, or enforce Claude Code, Copilot CLI, OpenHands, Codex, Cursor, Aider, or another named agent.

## Experimental Claude Code translation layer

The optional `claude-pretooluse` command is the first thin adapter above this
seam. It accepts a Claude Code `PreToolUse` `Edit` event, creates an ephemeral
generic envelope plus rollback snapshot, calls `agent-preflight`, and deletes
the temporary files before returning a Claude Code response. It has no policy
rules and does not call the evaluator directly. Policy allow maps to Claude
Code `ask`, preserving Claude's normal permission decision; policy deny maps
to Claude Code `deny`. This portable stdin/stdout integration does not inherit
the separate macOS-only `git-adapt` execution boundary.
