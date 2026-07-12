from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

import test_bundle_verifier as verifier_test_support

from clu_governance import git_diff_adapter as adapter
from clu_governance import source_mutation_demo_runtime as runtime
from clu_governance import source_mutation_policy_gate as gate
from clu_governance.bundle_verifier import exit_code_for_result, verify_bundle


@unittest.skipUnless(
    sys.platform == "darwin",
    "requires successful macOS git-adapt execution to create a verifier fixture",
)
class BundleVerifierSemanticBindingTest(unittest.TestCase):
    """Adversarial regression coverage for cross-artifact semantic bindings."""

    def setUp(self) -> None:
        self.root = Path(
            tempfile.mkdtemp(prefix="clu-bundle-semantic-binding-test.")
        ).resolve()
        self.policy = self.root / "policy.json"
        self.policy.write_text(
            json.dumps(runtime.build_demo_policy(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        adapter.ADAPTER_TEST_HOOK = None
        adapter.WORKTREE_READ_TEST_HOOK = None
        adapter.STATUS_SNAPSHOT_TEST_HOOK = None
        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
        adapter.OUTPUT_PARENT_TEST_HOOK = None
        adapter.PROCESS_LIMIT_TEST_OBSERVER = None
        adapter.GIT_METADATA_TEST_HOOK = None
        shutil.rmtree(self.root, ignore_errors=True)

    def make_bundle(
        self,
        name: str,
        selected_path: str = "README.md",
        *,
        benign_config_worktree: bool = False,
    ) -> Path:
        repo = self.root / f"repo-{name}"
        repo.mkdir()
        verifier_test_support.git(repo, "init", "-q")
        verifier_test_support.git(repo, "config", "user.name", "CLU Synthetic Test")
        verifier_test_support.git(
            repo, "config", "user.email", "synthetic@example.invalid"
        )
        (repo / selected_path).write_text("# Demo\n\nBaseline.\n", encoding="utf-8")
        verifier_test_support.git(repo, "add", selected_path)
        verifier_test_support.git(repo, "commit", "-q", "-m", "baseline")
        if benign_config_worktree:
            (repo / ".git" / "config.worktree").write_text(
                "[user]\n\tname = CLU Benign Worktree Fixture\n",
                encoding="utf-8",
            )
        (repo / selected_path).write_text(
            "# Demo\n\nProposed local edit.\n", encoding="utf-8"
        )
        policy_path = self.policy
        if selected_path != "README.md":
            policy = runtime.build_demo_policy()
            policy["allowed_paths"] = [selected_path]
            policy["allowed_path_globs"] = []
            policy["rules"][1]["paths"] = [selected_path]
            policy_path = self.root / f"policy-{name}.json"
            policy_path.write_text(
                json.dumps(policy, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        bundle = self.root / name
        result = adapter.adapt_git_diff(
            repo_path=repo,
            policy_path=policy_path,
            declared_actor_id="demo_operator",
            requested_scope="docs_only",
            output_dir=bundle,
            event_time="2026-06-26T00:00:00Z",
        )
        self.assertEqual(result["result"], "adapted", result)
        self.assertTrue(verify_bundle(bundle)["verified"])
        return bundle

    @staticmethod
    def load_json(bundle: Path, relative: str) -> dict[str, Any]:
        payload = json.loads((bundle / relative).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise AssertionError(f"expected object in {relative}")
        return payload

    @staticmethod
    def write_json(bundle: Path, relative: str, payload: dict[str, Any]) -> None:
        (bundle / relative).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    @staticmethod
    def refresh_checksums(bundle: Path, *relatives: str) -> None:
        checksum_path = bundle / "CHECKSUMS.sha256"
        replacements = {
            relative: hashlib.sha256((bundle / relative).read_bytes()).hexdigest()
            for relative in relatives
        }
        rewritten: list[str] = []
        for line in checksum_path.read_text(encoding="utf-8").splitlines():
            digest, relative = line.split("  ", 1)
            rewritten.append(f"{replacements.get(relative, digest)}  {relative}")
        checksum_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
        completion = BundleVerifierSemanticBindingTest.load_json(
            bundle, "BUNDLE_COMPLETE.json"
        )
        completion["checksums_sha256"] = hashlib.sha256(
            checksum_path.read_bytes()
        ).hexdigest()
        BundleVerifierSemanticBindingTest.write_json(
            bundle, "BUNDLE_COMPLETE.json", completion
        )

    @staticmethod
    def repair_allow_decision(
        request: dict[str, Any], decision: dict[str, Any]
    ) -> None:
        decision["canonical_request_hash"] = gate.canonical_sha256(request)
        decision["request_id"] = request["request_id"]
        decision["proposal_id"] = request["proposal_id"]
        decision["declared_actor_id"] = request["declared_actor_id"]
        decision["requested_scope"] = request["requested_scope"]
        decision["proposal_hash_supplied"] = request["proposal_hash"]
        decision["proposal_hash_verified"] = request["proposal_hash"]
        decision["source_hash_supplied"] = request["source_tree_hash"]
        decision["source_hash_verified"] = request["source_tree_hash"]
        binding = gate.execution_binding_for(
            request=request,
            policy_hash=decision["policy_hash"],
            checked_operations=decision["checked_paths_and_operations"],
            matched_rule_id=decision["matched_rule_id"],
        )
        decision["execution_binding"] = binding
        decision["execution_binding_hash"] = binding["execution_binding_hash"]
        decision["audit_event_hash"] = gate.canonical_sha256(
            {key: value for key, value in decision.items() if key != "audit_event_hash"}
        )

    def assert_semantically_invalid(
        self, bundle: Path, expected_blocker: str
    ) -> dict[str, Any]:
        before = verifier_test_support.tree_snapshot(bundle)
        result = verify_bundle(bundle)
        self.assertEqual(result["result"], "invalid", result)
        self.assertFalse(result["verified"], result)
        self.assertEqual(result["exact_blocker"], expected_blocker, result)
        self.assertFalse(result["verification_mutation_performed"])
        self.assertFalse(result["cleanup_performed"])
        self.assertEqual(exit_code_for_result(result), 2)
        self.assertEqual(before, verifier_test_support.tree_snapshot(bundle))
        return result

    def test_coherently_rehashed_non_string_identity_fields_fail_closed(self) -> None:
        mutations: tuple[tuple[str, Any], ...] = (
            ("request_id", False),
            ("proposal_id", ["not", "an", "identifier"]),
            ("declared_actor_id", False),
            ("requested_scope", {"not": "a string"}),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                bundle = self.make_bundle(f"identity-{field}")
                request = self.load_json(bundle, "source_mutation_request.json")
                decision = self.load_json(bundle, "policy_decision.json")
                request[field] = value
                self.repair_allow_decision(request, decision)
                self.write_json(bundle, "source_mutation_request.json", request)
                self.write_json(bundle, "policy_decision.json", decision)
                self.refresh_checksums(
                    bundle, "source_mutation_request.json", "policy_decision.json"
                )
                self.assert_semantically_invalid(
                    bundle, "bundle_request_rollback_binding_invalid"
                )

    def test_stale_and_coherently_rehashed_tampered_execution_bindings_fail(self) -> None:
        stale = self.make_bundle("stale-execution-binding")
        stale_decision = self.load_json(stale, "policy_decision.json")
        stale_decision["execution_binding"]["requested_scope"] = "tampered_scope"
        stale_decision["audit_event_hash"] = gate.canonical_sha256(
            {
                key: value
                for key, value in stale_decision.items()
                if key != "audit_event_hash"
            }
        )
        self.write_json(stale, "policy_decision.json", stale_decision)
        self.refresh_checksums(stale, "policy_decision.json")
        self.assert_semantically_invalid(stale, "bundle_decision_integrity_invalid")

        coherent = self.make_bundle("rehashed-execution-binding")
        coherent_decision = self.load_json(coherent, "policy_decision.json")
        coherent_decision["execution_binding"]["requested_scope"] = "tampered_scope"
        binding_without_hash = {
            key: value
            for key, value in coherent_decision["execution_binding"].items()
            if key != "execution_binding_hash"
        }
        coherent_decision["execution_binding"]["execution_binding_hash"] = (
            gate.canonical_sha256(binding_without_hash)
        )
        coherent_decision["execution_binding_hash"] = coherent_decision[
            "execution_binding"
        ]["execution_binding_hash"]
        coherent_decision["audit_event_hash"] = gate.canonical_sha256(
            {
                key: value
                for key, value in coherent_decision.items()
                if key != "audit_event_hash"
            }
        )
        self.write_json(coherent, "policy_decision.json", coherent_decision)
        self.refresh_checksums(coherent, "policy_decision.json")
        self.assert_semantically_invalid(coherent, "bundle_decision_integrity_invalid")

    def test_nonsense_decision_rehashed_across_provenance_fails_closed(self) -> None:
        bundle = self.make_bundle("nonsense-decision")
        decision = self.load_json(bundle, "policy_decision.json")
        provenance = self.load_json(bundle, "git_provenance.json")
        decision["decision"] = "nonsense"
        decision["audit_event_hash"] = gate.canonical_sha256(
            {key: value for key, value in decision.items() if key != "audit_event_hash"}
        )
        provenance["policy_decision"] = "nonsense"
        self.write_json(bundle, "policy_decision.json", decision)
        self.write_json(bundle, "git_provenance.json", provenance)
        self.refresh_checksums(bundle, "git_provenance.json", "policy_decision.json")
        self.assert_semantically_invalid(bundle, "bundle_decision_integrity_invalid")

    def test_rechecksummed_preview_cannot_escape_provenance_binding(self) -> None:
        bundle = self.make_bundle("preview-mismatch")
        (bundle / "change_preview.diff").write_bytes(b"coherently checksummed impostor\n")
        self.refresh_checksums(bundle, "change_preview.diff")
        result = self.assert_semantically_invalid(
            bundle, "bundle_provenance_binding_invalid"
        )
        self.assertFalse(result["preview_binding_verified"])

    def test_head_and_coherently_rehashed_blob_mismatches_fail_closed(self) -> None:
        head = self.make_bundle("head-provenance-mismatch")
        provenance = self.load_json(head, "git_provenance.json")
        provenance["head_oid"] = "0" * len(provenance["head_oid"])
        self.write_json(head, "git_provenance.json", provenance)
        self.refresh_checksums(head, "git_provenance.json")
        self.assert_semantically_invalid(head, "bundle_provenance_binding_invalid")

        blob = self.make_bundle("blob-content-mismatch")
        request = self.load_json(blob, "source_mutation_request.json")
        decision = self.load_json(blob, "policy_decision.json")
        provenance = self.load_json(blob, "git_provenance.json")
        fake_blob = "0" * len(provenance["baseline_blob_oid"])
        request["proposal_body"]["baseline_blob_oid"] = fake_blob
        request["git_provenance"]["baseline_blob_oid"] = fake_blob
        request["proposal_hash"] = gate.canonical_sha256(request["proposal_body"])
        provenance["baseline_blob_oid"] = fake_blob
        self.repair_allow_decision(request, decision)
        self.write_json(blob, "source_mutation_request.json", request)
        self.write_json(blob, "git_provenance.json", provenance)
        self.write_json(blob, "policy_decision.json", decision)
        self.refresh_checksums(
            blob,
            "source_mutation_request.json",
            "git_provenance.json",
            "policy_decision.json",
        )
        result = self.assert_semantically_invalid(
            blob, "bundle_provenance_binding_invalid"
        )
        self.assertFalse(result["git_blob_oid_verified"])

    def test_fully_rehashed_unknown_nested_proposal_field_is_rejected(self) -> None:
        bundle = self.make_bundle("unknown-nested-proposal-field")
        request = self.load_json(bundle, "source_mutation_request.json")
        decision = self.load_json(bundle, "policy_decision.json")
        request["proposal_body"]["unknown_nested_field"] = {
            "adversarial": "still not part of the schema"
        }
        request["proposal_hash"] = gate.canonical_sha256(request["proposal_body"])
        self.repair_allow_decision(request, decision)
        self.write_json(bundle, "source_mutation_request.json", request)
        self.write_json(bundle, "policy_decision.json", decision)
        self.refresh_checksums(
            bundle, "source_mutation_request.json", "policy_decision.json"
        )
        self.assert_semantically_invalid(
            bundle, "bundle_request_rollback_binding_invalid"
        )

    def test_unknown_contradictory_top_level_artifact_fields_are_rejected(self) -> None:
        completion_bundle = self.make_bundle("unknown-completion-field")
        completion = self.load_json(completion_bundle, "BUNDLE_COMPLETE.json")
        completion["immutable_bundle_claim_allowed"] = True
        self.write_json(completion_bundle, "BUNDLE_COMPLETE.json", completion)
        self.assert_semantically_invalid(
            completion_bundle, "bundle_completion_inconsistent"
        )

        ownership_bundle = self.make_bundle("unknown-ownership-field")
        ownership = self.load_json(
            ownership_bundle, ".clu-git-adapter-ownership.json"
        )
        ownership["adapter_owns_unknown_external_entries"] = True
        self.write_json(
            ownership_bundle, ".clu-git-adapter-ownership.json", ownership
        )
        self.refresh_checksums(
            ownership_bundle, ".clu-git-adapter-ownership.json"
        )
        self.assert_semantically_invalid(
            ownership_bundle, "bundle_publication_binding_invalid"
        )

        provenance_bundle = self.make_bundle("unknown-provenance-field")
        provenance = self.load_json(provenance_bundle, "git_provenance.json")
        provenance["full_repository_hash_verified_override"] = True
        self.write_json(provenance_bundle, "git_provenance.json", provenance)
        self.refresh_checksums(provenance_bundle, "git_provenance.json")
        self.assert_semantically_invalid(
            provenance_bundle, "bundle_provenance_binding_invalid"
        )

    def test_git_command_like_selected_filenames_are_valid_data_paths(self) -> None:
        for selected_path in ("fetch", "push", "commit", "remote"):
            with self.subTest(selected_path=selected_path):
                bundle = self.make_bundle(
                    f"legitimate-path-{selected_path}", selected_path=selected_path
                )
                result = verify_bundle(bundle)
                self.assertEqual(result["result"], "verified", result)
                self.assertTrue(result["verified"], result)
                self.assertEqual(exit_code_for_result(result), 0)

    def test_forbidden_git_verb_at_command_position_is_rejected(self) -> None:
        bundle = self.make_bundle("forbidden-command-verb")
        provenance = self.load_json(bundle, "git_provenance.json")
        commands = provenance["git_commands"]
        command = next(entry for entry in commands if "rev-parse" in entry)
        command[command.index("rev-parse")] = "fetch"
        self.write_json(bundle, "git_provenance.json", provenance)
        self.refresh_checksums(bundle, "git_provenance.json")
        self.assert_semantically_invalid(
            bundle, "bundle_provenance_binding_invalid"
        )

    def test_empty_metadata_ref_and_config_proof_inventories_are_rejected(self) -> None:
        inventory_pairs = (
            ("metadata", "metadata_inventory_before", "metadata_inventory_after"),
            ("refs", "refs_sha256_before", "refs_sha256_after"),
            ("config", "config_sha256_before", "config_sha256_after"),
        )
        for label, before_field, after_field in inventory_pairs:
            with self.subTest(inventory=label):
                bundle = self.make_bundle(f"empty-{label}-proof")
                provenance = self.load_json(bundle, "git_provenance.json")
                provenance[before_field] = {}
                provenance[after_field] = {}
                self.write_json(bundle, "git_provenance.json", provenance)
                self.refresh_checksums(bundle, "git_provenance.json")
                self.assert_semantically_invalid(
                    bundle, "bundle_provenance_binding_invalid"
                )

    def test_benign_regular_config_worktree_is_captured_and_verifies(self) -> None:
        bundle = self.make_bundle(
            "benign-config-worktree", benign_config_worktree=True
        )
        provenance = self.load_json(bundle, "git_provenance.json")
        self.assertIn("config.worktree", provenance["metadata_inventory_before"])
        self.assertEqual(
            provenance["metadata_inventory_before"]["config.worktree"],
            provenance["metadata_inventory_after"]["config.worktree"],
        )
        self.assertIn("config.worktree", provenance["config_sha256_before"])
        self.assertEqual(
            provenance["config_sha256_before"]["config.worktree"],
            provenance["config_sha256_after"]["config.worktree"],
        )
        result = verify_bundle(bundle)
        self.assertEqual(result["result"], "verified", result)
        self.assertTrue(result["verified"], result)
        self.assertEqual(exit_code_for_result(result), 0)

    def test_sha256_object_format_bundle_recomputes_and_verifies_blob_oid(self) -> None:
        repo = self.root / "repo-sha256-object-format"
        repo.mkdir()
        git_executable = shutil.which("git") or "git"
        initialized = subprocess.run(
            [git_executable, "init", "-q", "--object-format=sha256"],
            cwd=repo,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
        )
        if initialized.returncode:
            diagnostic = initialized.stderr.decode("utf-8", errors="replace")
            unsupported_markers = (
                "unknown option",
                "unknown hash algorithm",
                "unsupported",
                "not supported",
            )
            if any(marker in diagnostic.lower() for marker in unsupported_markers):
                self.skipTest("local Git does not support SHA-256 repository initialization")
            self.fail(f"SHA-256 repository initialization failed unexpectedly: {diagnostic}")

        verifier_test_support.git(repo, "config", "user.name", "CLU Synthetic Test")
        verifier_test_support.git(
            repo, "config", "user.email", "synthetic@example.invalid"
        )
        baseline = b"# SHA-256 Demo\n\nBaseline.\n"
        (repo / "README.md").write_bytes(baseline)
        verifier_test_support.git(repo, "add", "README.md")
        verifier_test_support.git(repo, "commit", "-q", "-m", "baseline")
        (repo / "README.md").write_text(
            "# SHA-256 Demo\n\nProposed local edit.\n", encoding="utf-8"
        )
        bundle = self.root / "sha256-object-format-bundle"
        adapted = adapter.adapt_git_diff(
            repo_path=repo,
            policy_path=self.policy,
            declared_actor_id="demo_operator",
            requested_scope="docs_only",
            output_dir=bundle,
            event_time="2026-06-26T00:00:00Z",
        )
        self.assertEqual(adapted["result"], "adapted", adapted)

        provenance = self.load_json(bundle, "git_provenance.json")
        request = self.load_json(bundle, "source_mutation_request.json")
        self.assertEqual(provenance["object_format"], "sha256")
        self.assertRegex(provenance["head_oid"], r"^[0-9a-f]{64}$")
        self.assertRegex(provenance["baseline_blob_oid"], r"^[0-9a-f]{64}$")
        self.assertTrue(provenance["baseline_git_blob_oid_recomputed"])
        self.assertTrue(provenance["baseline_git_blob_oid_verified"])
        self.assertEqual(
            request["git_provenance"]["baseline_blob_oid"],
            provenance["baseline_blob_oid"],
        )
        expected_blob_oid = hashlib.sha256(
            f"blob {len(baseline)}\0".encode("ascii") + baseline
        ).hexdigest()
        self.assertEqual(provenance["baseline_blob_oid"], expected_blob_oid)

        verified = verify_bundle(bundle)
        self.assertEqual(verified["result"], "verified", verified)
        self.assertTrue(verified["verified"], verified)
        self.assertTrue(verified["git_blob_oid_verified"], verified)
        self.assertEqual(exit_code_for_result(verified), 0)


if __name__ == "__main__":
    unittest.main()
