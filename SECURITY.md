# Security Policy

CLU Governance `0.1.0a1` is a pre-alpha developer tool. It has not received independent security certification.

## Supported surface

- Core CLI and deterministic demo: CPython 3.12.
- Protected-source manifest: source tree, the documented standard setuptools editable install, and wheel installs.
- `git-adapt`: the documented macOS, CPython 3.12, local-Git surface only.

## Important boundary

`git-adapt` is experimental and intended for trusted local repositories in single-user workflows. It is not a sandbox and does not defend against a malicious Git executable, hostile local process, operating-system administrator, concurrent same-user filesystem modification, or tampering after point-in-time verification.

The policy gate is effective only when an integration invokes and honors it. Actor identifiers and approval inputs are caller-supplied; they do not authenticate identity or verify human presence. An allow decision means eligibility for separate approval, not authorization to mutate a repository.

## Integrity behavior

The CLI validates structured JSON, hashes policy/request/source-related evidence where implemented, checks rollback readiness before the demo mutation path, and produces exact protected-source manifests. `verify-bundle` checks the currently observed local bundle file set, checksums, and internal bindings. These are point-in-time integrity checks, not signatures, immutable storage, tamper-evident logging, or proof of bundle origin.

## Non-goals

CLU Governance does not guarantee successful rollback, full-repository governance, non-bypassable enforcement, authenticated approval, or protection from a hostile administrator or later same-user tampering. Do not use this pre-alpha release as a production security boundary.

## Reporting a vulnerability

Until a public repository has GitHub private vulnerability reporting enabled, please do not post suspected vulnerabilities in a public issue. At publication, the repository security settings should make GitHub private vulnerability reporting the preferred channel.

For this pre-public candidate, report a concern to the project maintainer through the private coordination channel available to you. Include the version, platform, reproduction steps, expected behavior, and observed behavior. Do not include secrets or sensitive repository contents.
