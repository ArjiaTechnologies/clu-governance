# Future signed evidence

CLU Governance currently produces deterministic local policy evidence,
content hashes, an `audit_event_hash`, and point-in-time artifact
verification. These mechanisms bind the bytes and fields that CLU observed
locally at evaluation time. They do not establish who signed a verdict or
make a later artifact immutable.

The following are **not implemented** by CLU Governance today:

- authenticated signer identity;
- cryptographic verdict signatures;
- externally witnessed timestamps;
- third-party proof verification; or
- tamper-evident hosted storage.

An optional future layer could place a canonical evidence body above the
agent-neutral contract, hash it, sign that hash with an explicitly managed
identity, and offer independently verifiable timestamp or witness records.
That would require a separate design sprint covering key custody, signing
scope, verification UX, offline behavior, retention, and explicit network
boundaries. It is not part of the Claude Code adapter, does not run by
default, and must not be inferred from CLU's existing local hashes.
