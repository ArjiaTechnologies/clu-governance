# CLU Governance

**CLU stands for Cognitive Layer Utility.**

CLU Governance is a local-first policy and evidence layer for AI-proposed source changes. It verifies mutation requests, rollback-readiness, and local policy eligibility before a separate approval or application step.

It is for developers experimenting with a deliberate control point between a coding agent and a repository mutation. The core CLI is the primary pre-alpha product: it runs locally, has zero runtime dependencies, and provides deterministic policy, hash, approval-separation, rollback-readiness, and evidence workflows.

AI proposes a source change → CLU verifies policy, hashes, and rollback-readiness → CLU produces allow/deny evidence → A separate approval or application step may follow.

> **Pre-alpha:** `0.1.0a1` is for experimentation and integration work. It is not an enterprise security guarantee, authenticated identity system, non-bypassable enforcement layer, immutable audit store, or guarantee that a rollback will succeed outside the documented demo.

> **Experimental Git adapter:** `git-adapt` is experimental and intended for trusted local repositories in single-user workflows. It is not a sandbox and does not defend against a malicious Git executable, hostile local process, operating-system administrator, concurrent same-user filesystem modification, or tampering after point-in-time verification.

## What it can do today

- Evaluate a structured source-mutation request against a deny-by-default local policy.
- Bind requests, proposals, policies, source state, decisions, and rollback evidence with hashes.
- Keep policy eligibility separate from approval and application.
- Run a deterministic local allow/deny demonstration that applies no lasting source mutation.
- Report an exact protected-source manifest for source, standard setuptools editable, and wheel installs.
- Verify a locally generated Git-adapter bundle at the current location and time.

An `allow` result means only that a request is eligible for a separate approval decision. It does **not** authorize, apply, stage, commit, or push a mutation.

## Quick start

Clone or copy this repository locally, then install it in an environment you control:

```bash
python -m pip install .
clu-governance --version
clu-governance demo-run-all --json
clu-governance protected-source-manifest --json
```

The documented development workflow is the standard setuptools editable install:

```bash
python -m pip install -e .
clu-governance protected-source-manifest --json
```

This release candidate validates that standard command. It does not claim support for every editable backend or every `--no-build-isolation` layout.

Where those tools are available, local tool installation can also use:

```bash
pipx install .
uv tool install .
```

The project is not yet published on PyPI; the commands above intentionally install from a local checkout.

## Short end-to-end demonstration

The built-in demonstration creates its own marker-owned temporary workspace. It evaluates one documentation-only request as eligible, evaluates one delete request as denied, records a separate scripted approval artifact for the eligible request, verifies rollback readiness, applies and rolls back only within the temporary demo repository, and proves that the packaged-source fingerprint is unchanged.

```bash
clu-governance demo-run-all --json
```

The JSON result includes the allowed and denied decisions, exact policy reasons, approval mode, rollback evidence, and zero provider/advisor/Mem0/benchmark/network call counters. No mutation is automatically authorized in a user repository.

To inspect the policy and request fixtures directly, see [examples](examples/README.md). For command arguments and JSON contracts, see the [CLI contract](docs/cli-contract.md).

## Locality and limits

Under the documented workflow, source code and generated artifacts remain local. CLU Governance does not require provider credentials, Docker, a database, or a network runtime call for its core CLI or demo.

The project does not claim production readiness, market readiness, authenticated approval, verified human presence, tamper-evident storage, immutable bundles, full-repository governance, universal cross-platform Git-adapter support, independent security validation, customer validation, or competitive superiority. See [claims and limitations](docs/claims-and-limitations.md) and [security boundaries](docs/security-boundaries.md).

## Documentation

- [Quick start and supported installation modes](docs/quickstart.md)
- [CLI contract](docs/cli-contract.md)
- [Source-mutation policy gate](docs/source-mutation-policy-gate.md)
- [Experimental Git adapter](docs/git-diff-adapter.md)
- [Security boundaries](docs/security-boundaries.md)
- [Development methodology](docs/development-methodology.md)
- [Engineering decisions](docs/engineering-decisions.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
