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

## Agent-neutral preflight seam

`agent-preflight` is a read-only stdin/stdout seam before a caller's tool action. It validates one strict envelope and delegates to the existing source-mutation evaluator, returning the evaluator's evidence without creating an approval artifact or persistent state. Future thin adapters may translate an agent's own pre-tool event into this envelope and act on the result themselves. They are not part of the core contract: CLU does not start, configure, or enforce Claude Code, Copilot CLI, OpenHands, Codex, Cursor, Aider, or another named agent.
