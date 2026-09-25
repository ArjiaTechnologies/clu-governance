# Bounded new-file proposals

The agent-neutral `evaluate` and `agent-preflight` commands can evaluate one
`create` proposal for an absent UTF-8 file. The existing evaluator remains the
only policy authority. An allow means eligibility for separate approval;
it never creates the file. This is an unreleased, trusted-local pre-alpha
increment. Existing `modify` requests and their evidence projection retain
their contract. The Claude Edit hook, Git adapter, and demo executor remain
existing-file-only; they do not apply this proposal shape.

## Explicit opt-in

The policy must include the exact `"create"` string in its `allowed_operations`
array and in a matching allow rule's `operations` array. A rule with omitted
operations cannot opt into creation. All operation lists must be arrays of
strings. The policy must also explicitly allow the target path. Deny rules and
denied-path restrictions win, using case-insensitive matching for create so a
case variant cannot bypass a deny. Allow matches remain case-sensitive.

Only one operation is accepted. Mixed create/modify batches, directory
creation, deletes, renames, binary replacement, and other operations remain
unsupported. Every parent must already exist as a regular directory.

## Request and rollback evidence

Use the existing v1 request and rollback schemas with the following exact
create operation fields:

```json
{
  "operation": "create",
  "path": "docs/new.md",
  "before_state": "absent",
  "before_sha256": null,
  "content_encoding": "utf-8",
  "after_sha256": "<sha256 of proposed_content encoded as UTF-8>",
  "parent_identities": [
    {"path": ".", "device": 1, "inode": 100},
    {"path": "docs", "device": 1, "inode": 101}
  ]
}
```

The device/inode numbers above are placeholders. Capture actual local `lstat`
identities in source-root-to-parent order, using `"."` for the root. The helper
`new_file_proposal.inspect_absent_target(source_root, relative_path)` returns
that list plus an internal ancestor observation. Do not reuse identities from
another workspace, filesystem, or recreated directory. Missing/zero identities
fail closed. Source content remains bound by the existing source-tree hash.

`proposal_body` has exactly `operation`, `path`, `content_encoding`,
`proposed_content`, and `after_sha256`. The four shared fields must agree with
the operation. Hash the exact proposed UTF-8 bytes: no newline conversion or
Unicode normalization is performed. Empty content is valid; NUL and invalid
Unicode are rejected. Absence is `null`, distinct from the hash of an empty file.

The rollback artifact and its request wrapper must each contain exactly one
matching `files[path]` entry with `path`, `before_state: "absent"`,
`before_sha256: null`, `rollback_operation: "remove_created_file"`,
`after_sha256`, and the same `parent_identities`. No original-content bytes are
claimed for an absent file. The artifact needs its usual schema/version,
`snapshot_id`, absolute external path, and exact byte SHA-256. Creation requires
this evidence even when `rollback_readiness_required` is false.

This is a **conditional rollback plan**, not a deletion instruction or proof
of successful rollback. Any future separately designed application/rollback
tool must bind the approved request and current parents, establish exclusive
creation without overwrite, and only consider removal if the target still has
the approved after-bytes and identity. No such tool is added here.

The canonical request/proposal hashes and execution binding include the full
create projection. `before_file_hashes` contains `[null]`; checked operations
must match the ordered operation. Unsigned evidence envelopes preserve and
verify these structural bindings. They still authenticate no actor or approval.

## Path and observation limits

Create paths are relative, canonical slash-separated ASCII components using
letters, digits, underscore, hyphen, and dot. Absolute/UNC/drive-relative paths,
traversal, empty or dot components, backslashes, colons/streams, trailing dots
or spaces, Windows device names, short-name `~` aliases, and non-ASCII names are
rejected. Sensitive paths remain denied. Existing case aliases, files, empty
directories, and dangling links at the target are not absence.

The supplied source root and every ancestor/parent must be free of symlinks and
Windows reparse points. Supply a canonical physical path; a path through a
symlink such as a platform's temporary-directory alias may be rejected. Parent
device/inode identities are checked against the proposal and again before allow.
The evaluator rereads bound policy/request/rollback evidence, rehashes the source,
and explicitly rechecks target absence and parent identities. The last check is
necessary because a source-tree content hash does not include empty directories.

These are point-in-time checks for a trusted local single-user workflow, not an
atomic transaction, filesystem lock, sandbox, or guarantee against hostile or
concurrent writers after observation. Future application must revalidate.

## Reproducible CLI example

From a source checkout on Python 3.12:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -B examples/new-file-proposal/demo.py
```

With the wheel installed, run the same example script using the installed
environment's Python, with `PYTHONPATH` unset. It constructs only a temporary
fictional workspace, invokes the real `agent-preflight --json` CLI three times,
and reports one allow, an overwrite denial, and a traversal denial. The CLI
leaves source unchanged in every case and records no approval or application.

Focused adversarial tests:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -B -m unittest tests.test_new_file_proposal -v
```
