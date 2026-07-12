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
