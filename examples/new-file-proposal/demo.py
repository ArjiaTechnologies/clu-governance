"""Run allowed/overwrite/traversal preflight cases in a fresh temporary fixture.

The CLI only evaluates. Fixture construction and cleanup belong to this script;
no real repository is supplied and the proposed content is never applied.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from clu_governance import new_file_proposal as new_file
from clu_governance import source_mutation_policy_gate as gate


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="clu-create-example-") as temporary:
        workspace = Path(temporary).resolve()
        source = workspace / "source"
        (source / "docs").mkdir(parents=True)
        path = "docs/hello.md"
        content = "# Hello\n\nA proposed documentation file.\n"
        after = gate.sha256_bytes(content.encode("utf-8"))
        parents, _ = new_file.inspect_absent_target(source, path)
        operation = {"operation": "create", "path": path, "before_state": "absent", "before_sha256": None,
                     "content_encoding": "utf-8", "after_sha256": after, "parent_identities": parents}
        entry = {"path": path, "before_state": "absent", "before_sha256": None,
                 "rollback_operation": "remove_created_file", "after_sha256": after, "parent_identities": parents}
        policy = {"schema_name": gate.POLICY_SCHEMA_NAME, "schema_version": "1", "policy_id": "fictional-doc-create",
                  "default_decision": "deny", "maximum_file_count": 1, "allowed_declared_actor_ids": ["fictional-agent"],
                  "allowed_scopes": ["documentation"], "allowed_operations": ["create"], "allowed_path_prefixes": ["docs"],
                  "rules": [{"rule_id": "allow-doc-create", "effect": "allow", "operations": ["create"], "path_prefixes": ["docs"]}]}
        rollback = {"schema_name": gate.ROLLBACK_SCHEMA_NAME, "schema_version": "1", "snapshot_id": "fictional-absence",
                    "files": {path: entry}}
        policy_path, request_path, rollback_path = (workspace / name for name in ("policy.json", "request.json", "rollback.json"))
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        rollback_path.write_text(json.dumps(rollback), encoding="utf-8")
        proposal = {"operation": "create", "path": path, "content_encoding": "utf-8", "proposed_content": content, "after_sha256": after}
        request = {"schema_name": gate.REQUEST_SCHEMA_NAME, "schema_version": "1", "request_id": "fictional-create",
                   "declared_actor_id": "fictional-agent", "actor_identity_source": "caller_declared", "requested_scope": "documentation",
                   "proposal_id": "fictional-proposal", "proposal_body": proposal, "proposal_hash": gate.canonical_sha256(proposal),
                   "source_tree_hash": gate.source_tree_hash(source), "operations": [operation],
                   "rollback_readiness": {"schema_name": gate.ROLLBACK_SCHEMA_NAME, "schema_version": "1",
                                          "artifact_path": str(rollback_path), "artifact_sha256": gate.sha256_file(rollback_path), "files": {path: entry}}}
        envelope = {"schema_name": "clu_governance_agent_preflight_input.v1", "schema_version": "1",
                    "policy_path": str(policy_path), "request_path": str(request_path), "source_root": str(source),
                    "event_timestamp": "2026-09-25T00:00:00Z", "sequence_index": 1}
        results = []
        for variant, expected in (("allowed", "allow"), ("overwrite", "deny"), ("traversal", "deny")):
            candidate = copy.deepcopy(request)
            if variant == "overwrite":
                (source / path).write_bytes(b"Existing fixture file; must not be overwritten.\n")
            if variant == "traversal":
                (source / path).unlink()
                candidate["operations"][0]["path"] = "../outside.md"
            candidate["source_tree_hash"] = gate.source_tree_hash(source)
            request_path.write_text(json.dumps(candidate), encoding="utf-8")
            before = gate.source_tree_hash(source)
            result = subprocess.run([sys.executable, "-B", "-m", "clu_governance.cli", "agent-preflight", "--json"],
                                    input=json.dumps(envelope), text=True, capture_output=True, check=False)
            decision = json.loads(result.stdout)
            unchanged = before == gate.source_tree_hash(source)
            if decision.get("decision") != expected or result.returncode != (0 if expected == "allow" else 2) or not unchanged:
                raise RuntimeError(f"unexpected {variant} result")
            results.append({"case": variant, "exit_code": result.returncode, "decision": decision["decision"],
                            "reason_code": decision["reason_code"], "source_unchanged": unchanged,
                            "mutation_authorized": decision["mutation_authorized"], "mutation_applied": decision["mutation_applied"],
                            "rollback_executed": decision["rollback_executed"]})
        print(json.dumps({"fixture": "synthetic_temporary", "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
