# Changelog

## 0.1.0a2 — Agent-neutral preflight prerelease

- Add `clu-governance agent-preflight --json`, a read-only strict-JSON stdin/stdout pre-tool contract for agent-neutral integrations.
- Reuse the existing source-mutation policy evaluator and return its allow/deny evidence without recording approval, applying a mutation, launching an agent, or creating default persistent state.
- Document the explicit exit-code, state, uninstall, and future thin-adapter boundaries.

## 0.1.0a1 — Initial public pre-alpha candidate

- Local-first CLI for deny-by-default source-mutation policy evaluation and evidence artifacts.
- Hash and rollback-readiness validation with a deterministic local allow/deny demo.
- Separate policy eligibility from approval and mutation application.
- Strict JSON boundaries and exact protected-source manifests for source, documented standard editable, and wheel installs.
- Point-in-time local bundle verification.
- Experimental trusted-local, one-file Git working-tree adapter.

This is a pre-alpha developer release candidate. See [README.md](README.md), [SECURITY.md](SECURITY.md), and [docs/claims-and-limitations.md](docs/claims-and-limitations.md) for boundaries and non-goals.
