# Claims and Limitations

CLU Governance `0.1.0a3` may be described as a local-first policy and evidence layer for AI-proposed source changes under its documented workflow. It provides deterministic policy evaluation, structured hash validation where implemented, rollback-readiness validation, separate eligibility and approval artifacts, strict JSON handling, exact protected-source manifests, and point-in-time bundle verification.

The documented standard setuptools editable install reconciles one active editable distribution record with one generated source-adjacent companion metadata directory. The generated metadata is disposable and excluded from the protected set. The manifest does not protect all of `site-packages`.

## Explicit non-claims

- Not production-ready, market-ready, enterprise-ready, independently security-certified, or customer validated.
- Not authenticated identity, verified human approval, non-bypassable enforcement, or a general security sandbox.
- Not immutable storage, tamper-evident logging, signed provenance, or authenticated bundle origin.
- Not full-repository governance and not a guarantee of successful rollback.
- Not universal cross-platform support for the Git adapter.
- Not a competitive-performance, benchmark, provider, or autonomous-improvement claim.

An allow result is policy eligibility for a separate approval step. It does not itself authorize, apply, stage, commit, or push a source mutation.

`git-adapt` is experimental and only for trusted local, single-user repositories. It is a point-in-time local integration, not a defense against a malicious Git executable, hostile local process, operating-system administrator, concurrent same-user filesystem modification, or later tampering.
