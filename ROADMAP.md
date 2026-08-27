# CLU Governance roadmap

Current public baseline: **0.1.0a3, pre-alpha**. This roadmap describes
reviewable increments, not shipped capabilities, release commitments, or
authorization to operate a hosted service.

## 0.1.x — deterministic local evidence

- Preserve one deny-by-default source-mutation evaluator and the existing
  agent-neutral preflight contract.
- Bind a policy decision, policy, request, proposal, source snapshot, rollback
  readiness, and execution projection into a canonical **unsigned** evidence
  envelope that can be verified offline.
- Reject malformed JSON, duplicate keys, swapped artifacts, altered decisions,
  unsafe paths, contradictory rollback state, and forged approval or identity
  claims.
- Keep experimental Claude Code support limited to its documented existing-file
  hook; eligibility maps to normal permission `ask`, never automatic approval.
- Maintain reproducible release-candidate checksums and Linux/macOS packaging,
  integration, and adversarial contract coverage.

## 0.2 — bounded policy and change shapes

- Expand explicitly allowed source-change shapes only after specifying their
  before/after evidence, path confinement, rollback semantics, and adversarial
  tests; unknown operations remain denied.
- Improve trusted-local Git snapshot portability and concurrent-change
  detection without claiming a sandbox or hostile-process protection.
  The core evaluator now closes its request/operation/rollback validation
  window with a second full source-tree hash and denies stale decisions;
  broader Git adapter portability and concurrency work remains open.
- Add a thin coding-agent adapter only for an officially documented supported
  pre-tool extension point; all adapters must delegate to the same evaluator.

## 0.3 — optional signed evidence, after a separate design review

- Specify canonical signing scope, algorithm agility, signer identity, key
  custody, key rotation, offline verification, and backward compatibility.
- Distinguish local timestamps from externally witnessed time, and local files
  from tamper-evident or immutable storage.
- Keep signing, network witnesses, hosted storage, identity enrollment, and
  production enforcement optional and separately authorized. None exists in
  the current unsigned evidence milestone.

## Non-negotiable boundaries

The core remains local-first with no default network runtime, no hosted
service, no provider credential, no authenticated-human claim, and no
automatic source mutation. **Policy eligibility is not approval; approval is
not application.** Experimental adapters remain trusted-local and pre-alpha.
