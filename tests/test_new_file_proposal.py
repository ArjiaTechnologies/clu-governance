"""Adversarial contracts for read-only, single-file create proposals."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from clu_governance import agent_preflight, evidence_envelope
from clu_governance import source_mutation_policy_gate as gate
from clu_governance import source_mutation_demo_runtime as demo


class NewFileProposalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="clu-new-file-")
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.root = self.workspace / "source"
        self.root.mkdir()
        (self.root / "docs").mkdir()
        self.target = self.root / "docs" / "new.md"
        self.policy_path = self.workspace / "policy.json"
        self.request_path = self.workspace / "request.json"
        self.rollback_path = self.workspace / "rollback.json"
        self.content = "# Proposed file\nExact UTF-8 bytes: café.\n"
        after = gate.sha256_bytes(self.content.encode("utf-8"))
        parents = []
        for relative in (".", "docs"):
            info = (self.root / relative).stat()
            parents.append({"path": relative, "device": info.st_dev, "inode": info.st_ino})
        self.operation = {"operation": "create", "path": "docs/new.md", "before_state": "absent",
                          "before_sha256": None, "content_encoding": "utf-8", "after_sha256": after,
                          "parent_identities": parents}
        self.entry = {"path": "docs/new.md", "before_state": "absent", "before_sha256": None,
                      "rollback_operation": "remove_created_file", "after_sha256": after,
                      "parent_identities": parents}
        self.rollback = {"schema_name": gate.ROLLBACK_SCHEMA_NAME, "schema_version": "1",
                         "snapshot_id": "synthetic-absent-before", "files": {"docs/new.md": self.entry}}
        self.policy = {"schema_name": gate.POLICY_SCHEMA_NAME, "schema_version": "1", "policy_id": "synthetic-create",
                       "default_decision": "deny", "maximum_file_count": 1,
                       "allowed_declared_actor_ids": ["synthetic-agent"], "allowed_scopes": ["docs"],
                       "allowed_operations": ["modify", "create"], "allowed_path_prefixes": ["docs"],
                       "rules": [{"rule_id": "create-doc", "effect": "allow", "operations": ["create"], "path_prefixes": ["docs"]}]}
        self.request = {"schema_name": gate.REQUEST_SCHEMA_NAME, "schema_version": "1", "request_id": "synthetic-create",
                        "declared_actor_id": "synthetic-agent", "actor_identity_source": "caller_declared", "requested_scope": "docs",
                        "proposal_id": "synthetic-new-file", "proposal_body": {"operation": "create", "path": "docs/new.md",
                        "content_encoding": "utf-8", "proposed_content": self.content, "after_sha256": after},
                        "source_tree_hash": gate.source_tree_hash(self.root), "operations": [self.operation]}
        self.save()

    def save(self):
        self.rollback_path.write_text(json.dumps(self.rollback), encoding="utf-8")
        self.request["rollback_readiness"] = {"schema_name": gate.ROLLBACK_SCHEMA_NAME, "schema_version": "1",
                                             "artifact_path": str(self.rollback_path), "artifact_sha256": gate.sha256_file(self.rollback_path),
                                             "files": copy.deepcopy(self.rollback["files"])}
        self.request["proposal_hash"] = gate.canonical_sha256(self.request["proposal_body"])
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        self.request_path.write_text(json.dumps(self.request), encoding="utf-8")

    def evaluate(self):
        return gate.evaluate_source_mutation_request(policy_path=self.policy_path, request_path=self.request_path,
                                                    source_root=self.root, event_timestamp="2026-09-25T17:30:00Z")

    def envelope(self):
        return json.dumps({"schema_name": agent_preflight.INPUT_SCHEMA_NAME, "schema_version": "1",
                           "policy_path": str(self.policy_path), "request_path": str(self.request_path),
                           "source_root": str(self.root), "event_timestamp": "2026-09-25T17:30:00Z", "sequence_index": 1})

    def test_valid_create_is_eligible_without_writing(self):
        before = gate.source_tree_hash(self.root)
        decision = self.evaluate()
        self.assertEqual(decision["decision"], "allow", decision)
        self.assertFalse(decision["mutation_authorized"])
        self.assertFalse(decision["mutation_applied"])
        self.assertFalse(decision["rollback_executed"])
        self.assertEqual(decision["checked_paths_and_operations"], [self.operation])
        self.assertEqual(decision["execution_binding"]["ordered_operations"], [self.operation])
        self.assertFalse(self.target.exists())
        self.assertEqual(gate.source_tree_hash(self.root), before)

    def test_old_policy_and_implicit_allow_rule_do_not_opt_in(self):
        self.policy["allowed_operations"] = ["modify"]
        self.save()
        self.assertEqual(self.evaluate()["decision"], "deny")
        self.policy["allowed_operations"].append("create")
        self.policy["rules"][0].pop("operations")
        self.save()
        self.assertEqual(self.evaluate()["decision"], "deny")

    def test_existing_empty_file_and_directory_are_denied(self):
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                self.target.touch() if kind == "file" else self.target.mkdir()
                self.request["source_tree_hash"] = gate.source_tree_hash(self.root)
                self.save()
                self.assertEqual(self.evaluate()["decision"], "deny")
                self.target.unlink() if kind == "file" else self.target.rmdir()

    def test_path_aliases_and_sensitive_paths_are_denied(self):
        for path in ("../new.md", "/tmp/new.md", "C:new.md", "C:/new.md", "//server/share/new.md",
                     "docs//new.md", "docs/./new.md", "docs\\new.md", "docs/new.md:stream", "docs/NUL.txt",
                     "docs/new.md.", "docs/new.md ", "docs/NEW~1.md", "docs/é.md", "docs/.env", ".git/config"):
            with self.subTest(path=path):
                self.operation["path"] = path
                self.save()
                self.assertEqual(self.evaluate()["decision"], "deny")

    def test_absence_and_content_binding_required(self):
        original = copy.deepcopy(self.operation)
        variants = [{"before_state": "present"}, {"before_sha256": gate.sha256_bytes(b"")},
                    {"after_sha256": "0" * 64}, {"content_encoding": "base64"}, {"parent_identities": []}]
        for change in variants:
            with self.subTest(change=change):
                self.operation.clear()
                self.operation.update(original | change)
                self.save()
                self.assertEqual(self.evaluate()["decision"], "deny")

    def test_missing_before_hash_is_not_null(self):
        self.operation.pop("before_sha256")
        self.save()
        self.assertEqual(self.evaluate()["decision"], "deny")

    def test_rollback_cannot_be_disabled_or_forged(self):
        self.policy["rollback_readiness_required"] = False
        self.entry["before_state"] = "present"
        self.save()
        self.assertEqual(self.evaluate()["decision"], "deny")

    def test_case_insensitive_deny_overrides_allow(self):
        self.policy["rules"].insert(0, {"rule_id": "deny-case-alias", "effect": "deny", "operations": ["create"], "paths": ["DOCS/NEW.MD"]})
        self.save()
        self.assertEqual(self.evaluate()["reason_code"], "explicit_deny_rule_matched")

    def test_multiple_or_mixed_operations_are_denied(self):
        self.policy["maximum_file_count"] = 2
        self.request["operations"].append(copy.deepcopy(self.operation))
        self.save()
        self.assertEqual(self.evaluate()["decision"], "deny")

    def test_absent_to_empty_directory_during_final_hash_is_denied(self):
        original_hash = gate.source_tree_hash
        count = 0
        def racing_hash(root):
            nonlocal count
            count += 1
            if count == 2:
                self.target.mkdir()
            return original_hash(root)
        with mock.patch.object(gate, "source_tree_hash", side_effect=racing_hash):
            self.assertEqual(self.evaluate()["decision"], "deny")

    def test_parent_replacement_with_identical_contents_is_denied(self):
        (self.root / "docs").rename(self.root / "previous")
        (self.root / "docs").mkdir()
        self.assertEqual(gate.source_tree_hash(self.root), self.request["source_tree_hash"])
        self.assertEqual(self.evaluate()["decision"], "deny")

    def test_preflight_and_unsigned_evidence_preserve_create_binding(self):
        code, decision = agent_preflight.run(self.envelope())
        self.assertEqual(code, 0, decision)
        envelope = evidence_envelope.build_envelope(decision)
        result = evidence_envelope.verify_envelope(envelope)
        self.assertTrue(result["verified"], result)
        self.assertFalse(self.target.exists())

    def test_cli_returns_one_object_without_applying(self):
        result = subprocess.run([sys.executable, "-B", "-m", "clu_governance.cli", "agent-preflight"],
                                input=self.envelope(), text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["decision"], "allow")
        self.assertFalse(self.target.exists())

    def test_empty_content_is_distinct_from_absence(self):
        digest = gate.sha256_bytes(b"")
        self.request["proposal_body"].update(proposed_content="", after_sha256=digest)
        self.operation["after_sha256"] = self.entry["after_sha256"] = digest
        self.save()
        self.assertEqual(self.evaluate()["decision"], "allow")
        self.assertIsNone(self.operation["before_sha256"])

    def test_changed_proposed_bytes_with_unchanged_hash_are_denied(self):
        self.request["proposal_body"]["proposed_content"] += "unexpected\n"
        self.save()
        self.assertEqual(self.evaluate()["reason_code"], "create_proposed_content_hash_mismatch")

    def test_stale_source_and_absent_to_file_race_are_denied(self):
        original_hash = gate.source_tree_hash
        count = 0
        def racing_hash(root):
            nonlocal count
            count += 1
            if count == 2:
                self.target.write_bytes(b"concurrent writer")
            return original_hash(root)
        with mock.patch.object(gate, "source_tree_hash", side_effect=racing_hash):
            self.assertEqual(self.evaluate()["decision"], "deny")
        self.assertEqual(self.target.read_bytes(), b"concurrent writer")
        self.assertEqual(self.evaluate()["decision"], "deny")

    def test_parent_replaced_during_final_hash_is_denied(self):
        original_hash = gate.source_tree_hash
        count = 0
        def racing_hash(root):
            nonlocal count
            count += 1
            if count == 2:
                (self.root / "docs").rename(self.root / "old-docs")
                (self.root / "docs").mkdir()
            return original_hash(root)
        with mock.patch.object(gate, "source_tree_hash", side_effect=racing_hash):
            self.assertEqual(self.evaluate()["reason_code"], "create_parent_identity_changed")

    def test_policy_request_and_rollback_changes_during_evaluation_are_denied(self):
        original_check = gate.check_rollback_readiness
        for artifact in (self.policy_path, self.request_path, self.rollback_path):
            with self.subTest(artifact=artifact.name):
                self.save()
                def racing_check(*args, **kwargs):
                    result = original_check(*args, **kwargs)
                    artifact.write_text("{}", encoding="utf-8")
                    return result
                with mock.patch.object(gate, "check_rollback_readiness", side_effect=racing_check):
                    self.assertEqual(self.evaluate()["decision"], "deny")

    def test_source_change_during_final_rollback_reread_is_denied(self):
        original = gate.new_file.validate_rollback
        count = 0
        def racing_rollback(*args):
            nonlocal count
            result = original(*args)
            count += 1
            if count == 2:
                (self.root / "other.md").write_bytes(b"concurrent change")
            return result
        with mock.patch.object(gate.new_file, "validate_rollback", side_effect=racing_rollback):
            self.assertEqual(self.evaluate()["reason_code"], "source_hash_changed_during_evaluation")

    def test_request_numeric_type_change_is_not_canonical_equality(self):
        self.request["review_sequence"] = 1
        self.save()
        original = gate.check_rollback_readiness
        def racing_check(*args):
            result = original(*args)
            reread = json.loads(self.request_path.read_text(encoding="utf-8"))
            reread["review_sequence"] = 1.0
            self.assertEqual(reread, self.request)
            self.request_path.write_text(json.dumps(reread), encoding="utf-8")
            return result
        with mock.patch.object(gate, "check_rollback_readiness", side_effect=racing_check):
            self.assertEqual(self.evaluate()["reason_code"], "create_input_changed_during_evaluation")

    def test_policy_opt_in_requires_exact_lists(self):
        for value in ("recreate", {"create": False}, True, 1, [True]):
            for where in (self.policy, self.policy["rules"][0]):
                field = "allowed_operations" if where is self.policy else "operations"
                original = where[field]
                where[field] = value
                self.save()
                self.assertEqual(self.evaluate()["reason_code"], "create_policy_operations_invalid")
                where[field] = original

    def test_mixed_modify_and_create_are_denied(self):
        self.policy["maximum_file_count"] = 2
        self.request["operations"].append({"operation": "modify", "path": "docs/other.md", "before_sha256": "0" * 64})
        self.save()
        self.assertEqual(self.evaluate()["reason_code"], "create_requires_single_operation")

    def test_sensitive_rollback_artifact_path_remains_denied(self):
        self.rollback_path = self.workspace / "secret.key"
        self.save()
        self.assertEqual(self.evaluate()["reason_code"], "rollback_artifact_unsafe_path_denied")

    def test_rollback_numeric_types_match_exactly(self):
        self.entry["parent_identities"] = copy.deepcopy(self.operation["parent_identities"])
        self.entry["parent_identities"][0]["inode"] = float(self.entry["parent_identities"][0]["inode"])
        self.save()
        self.assertEqual(self.evaluate()["reason_code"], "create_rollback_absence_binding_mismatch")

    def test_rollback_inside_source_is_denied(self):
        self.rollback_path = self.root / "rollback.json"
        self.save()
        self.request["source_tree_hash"] = gate.source_tree_hash(self.root)
        self.save()
        self.assertEqual(self.evaluate()["reason_code"], "create_rollback_must_be_outside_source")

    def test_source_root_symlink_is_denied(self):
        alias = self.workspace / "source-alias"
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"native symlink creation unavailable: {exc.__class__.__name__}")
        self.root = alias
        self.assertEqual(self.evaluate()["reason_code"], "create_parent_link_or_identity_denied")

    def test_rollback_symlink_is_denied(self):
        alias = self.workspace / "rollback-alias.json"
        try:
            alias.symlink_to(self.rollback_path)
        except OSError as exc:
            self.skipTest(f"native symlink creation unavailable: {exc.__class__.__name__}")
        self.request["rollback_readiness"]["artifact_path"] = str(alias)
        self.request_path.write_text(json.dumps(self.request), encoding="utf-8")
        self.assertEqual(self.evaluate()["reason_code"], "create_rollback_link_or_type_denied")

    def test_nul_and_unencodable_unicode_never_allow(self):
        for content in ("nul\x00", "bad\ud800"):
            request = copy.deepcopy(self.request)
            request["proposal_body"]["proposed_content"] = content
            self.request_path.write_text(json.dumps(request), encoding="utf-8")
            code, decision = agent_preflight.run(self.envelope())
            self.assertNotEqual(code, 0)
            self.assertFalse(decision["eligible_for_human_approval"])

    def test_rollback_wrapper_unrelated_file_and_original_content_are_denied(self):
        for field, value in (("original_content", ""), ("rollback_operation", "overwrite"), ("after_sha256", "0" * 64)):
            with self.subTest(field=field):
                old = copy.deepcopy(self.entry)
                self.entry[field] = value
                self.save()
                self.assertEqual(self.evaluate()["decision"], "deny")
                self.entry.clear()
                self.entry.update(old)
        self.rollback["files"]["unrelated.md"] = copy.deepcopy(self.entry)
        self.save()
        self.assertEqual(self.evaluate()["decision"], "deny")
        del self.rollback["files"]["unrelated.md"]
        self.save()
        self.request["rollback_readiness"]["files"]["docs/new.md"]["after_sha256"] = "0" * 64
        self.request_path.write_text(json.dumps(self.request), encoding="utf-8")
        self.assertEqual(self.evaluate()["decision"], "deny")

    def test_duplicate_json_keys_are_rejected(self):
        for artifact in (self.policy_path, self.request_path, self.rollback_path):
            with self.subTest(artifact=artifact.name):
                self.save()
                data = artifact.read_text(encoding="utf-8")
                artifact.write_text('{"schema_version":"1",' + data[1:], encoding="utf-8")
                if artifact == self.rollback_path:
                    self.request["rollback_readiness"]["artifact_sha256"] = gate.sha256_file(artifact)
                    self.request_path.write_text(json.dumps(self.request), encoding="utf-8")
                self.assertEqual(self.evaluate()["decision"], "deny")

    def test_case_collision_and_missing_parent_are_denied(self):
        alias = self.root / "docs" / "NEW.MD"
        alias.touch()
        self.request["source_tree_hash"] = gate.source_tree_hash(self.root)
        self.save()
        self.assertEqual(self.evaluate()["reason_code"], "create_target_not_absent")
        alias.unlink()
        (self.root / "docs").rmdir()
        self.request["source_tree_hash"] = gate.source_tree_hash(self.root)
        self.save()
        self.assertEqual(self.evaluate()["reason_code"], "create_parent_missing_or_case_alias")

    def test_dangling_symlink_and_parent_symlink_are_denied(self):
        try:
            self.target.symlink_to(self.workspace / "absent")
        except OSError as exc:
            self.skipTest(f"native symlink creation unavailable: {exc.__class__.__name__}")
        self.assertEqual(self.evaluate()["decision"], "deny")
        self.target.unlink()
        (self.root / "docs").rmdir()
        outside = self.workspace / "outside"
        outside.mkdir()
        (self.root / "docs").symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.evaluate()["decision"], "deny")

    def test_demo_runtime_never_accepts_create_for_application(self):
        decision = self.evaluate()
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(demo._single_operation_contract_error(self.request, decision, decision),
                         "demo_runtime_operation_binding_mismatch")
        self.assertFalse(self.target.exists())

    def test_unsigned_envelope_rejects_forged_create_projection(self):
        decision = self.evaluate()
        for field, value in (("before_state", "present"), ("after_sha256", "bad"), ("parent_identities", [])):
            with self.subTest(field=field):
                forged = copy.deepcopy(decision)
                operation = forged["execution_binding"]["ordered_operations"][0]
                operation[field] = value
                forged["checked_paths_and_operations"] = [copy.deepcopy(operation)]
                binding = forged["execution_binding"]
                binding["checked_operation_digest"] = gate.canonical_sha256(forged["checked_paths_and_operations"])
                binding["execution_binding_hash"] = gate.canonical_sha256({k: v for k, v in binding.items() if k != "execution_binding_hash"})
                forged["execution_binding_hash"] = binding["execution_binding_hash"]
                forged["audit_event_hash"] = gate.canonical_sha256({k: v for k, v in forged.items() if k != "audit_event_hash"})
                with self.assertRaises(ValueError):
                    evidence_envelope.build_envelope(forged)


if __name__ == "__main__":
    unittest.main()
