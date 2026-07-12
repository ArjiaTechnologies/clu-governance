from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clu_governance import git_diff_adapter as adapter
from clu_governance import source_mutation_demo_runtime as runtime


MACOS_ADAPTER_INTEGRATION_REASON = (
    "requires successful macOS git-adapt execution; unsupported-platform "
    "fail-closed behavior is covered separately"
)


def macos_adapter_integration(*portable_test_names: str):
    """Apply per-test macOS skips while retaining publication primitives."""

    def decorate(test_class):
        defined_tests = {
            name
            for name, member in vars(test_class).items()
            if name.startswith("test_") and callable(member)
        }
        unknown_portable_tests = set(portable_test_names) - defined_tests
        if unknown_portable_tests:
            raise AssertionError(
                "portable test classification references unknown tests: "
                + ", ".join(sorted(unknown_portable_tests))
            )
        for name in sorted(defined_tests - set(portable_test_names)):
            setattr(
                test_class,
                name,
                unittest.skipUnless(
                    sys.platform == "darwin", MACOS_ADAPTER_INTEGRATION_REASON
                )(getattr(test_class, name)),
            )
        return test_class

    return decorate


@macos_adapter_integration(
    "test_legacy_relocate_transition_is_disabled",
    "test_metadata_descriptor_release_cannot_override_published_result",
)
class GitPublicationBindingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="clu-git-publication.")).resolve()
        self.policy = self.root / "policy.json"
        self.policy.write_text(
            json.dumps(runtime.build_demo_policy(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        adapter.ADAPTER_TEST_HOOK = None
        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
        adapter.EXACT_SEAL_TEST_HOOK = None
        shutil.rmtree(self.root, ignore_errors=True)

    @staticmethod
    def git(repo: Path, *arguments: str) -> None:
        completed = subprocess.run(
            [shutil.which("git") or "git", *arguments],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
        )
        if completed.returncode:
            raise AssertionError(completed.stderr.decode(errors="replace"))

    def make_repo(self, name: str) -> Path:
        repo = self.root / name
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.name", "CLU Synthetic Test")
        self.git(repo, "config", "user.email", "synthetic@example.invalid")
        (repo / "README.md").write_text("# Demo\n\nBaseline.\n", encoding="utf-8")
        self.git(repo, "add", "README.md")
        self.git(repo, "commit", "-q", "-m", "baseline")
        (repo / "README.md").write_text(
            "# Demo\n\nProposed local edit.\n", encoding="utf-8"
        )
        return repo

    def adapt(self, repo: Path, output: Path) -> dict[str, object]:
        return adapter.adapt_git_diff(
            repo_path=repo,
            policy_path=self.policy,
            declared_actor_id="demo_operator",
            requested_scope="docs_only",
            output_dir=output,
            event_time="2026-06-26T00:00:00Z",
        )

    def test_no_replace_rename_is_last_mutating_action_before_strict_verification(self) -> None:
        repo = self.make_repo("last-action-repo")
        output = self.root / "last-action-bundle"
        original_rename = adapter._rename_directory_no_replace_at
        published = {"value": False}
        phases: list[str] = []

        def observe_hook(phase: str, _owned: adapter.OwnedOutputTree) -> None:
            phases.append(phase)

        def observed_rename(parent_fd: int, source: str, destination: str) -> None:
            staging = output.parent / source
            self.assertTrue((staging / "BUNDLE_COMPLETE.json").is_file())
            self.assertTrue((staging / "CHECKSUMS.sha256").is_file())
            self.assertFalse((staging / adapter.INCOMPLETE_MARKER_NAME).exists())
            completion = json.loads((staging / "BUNDLE_COMPLETE.json").read_text())
            self.assertTrue(completion["completion_requires_intended_final_binding"])
            self.assertFalse(completion["hidden_staging_completion_claim_valid"])
            original_rename(parent_fd, source, destination)
            published["value"] = True

        original_barrier = adapter.OwnedOutputTree.barrier
        original_verify = adapter.OwnedOutputTree.verify_exact

        def guarded_barrier(owned: adapter.OwnedOutputTree, phase: str) -> None:
            self.assertFalse(published["value"], f"post-publication barrier: {phase}")
            return original_barrier(owned, phase)

        def guarded_verify(owned: adapter.OwnedOutputTree, expected: set[str]):
            self.assertFalse(published["value"], "post-publication bundle read")
            return original_verify(owned, expected)

        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = observe_hook
        with (
            mock.patch.object(adapter, "_rename_directory_no_replace_at", new=observed_rename),
            mock.patch.object(adapter.OwnedOutputTree, "barrier", new=guarded_barrier),
            mock.patch.object(adapter.OwnedOutputTree, "verify_exact", new=guarded_verify),
        ):
            result = self.adapt(repo, output)

        self.assertTrue(published["value"])
        self.assertEqual(result["result"], "adapted")
        self.assertTrue(result["publication_transition_succeeded"])
        self.assertEqual(
            result["publication_final_action"],
            "descriptor_relative_no_replace_directory_rename",
        )
        self.assertEqual(result["post_publication_hook_calls"], 0)
        self.assertEqual(result["post_publication_bundle_accesses"], 2)
        self.assertTrue(result["post_publication_verification_performed"])
        self.assertTrue(result["post_publication_bundle_verified"])
        self.assertFalse(result["post_publication_cleanup_performed"])
        self.assertTrue(result["bundle_consumer_verifiable"])
        self.assertFalse(result["bundle_immutable"])
        self.assertFalse(result["bundle_tamper_prevention_provided"])
        self.assertTrue(result["bundle_exact_set_verified_at_return"])
        self.assertTrue(result["bundle_verification_required_at_consumption"])
        self.assertFalse(result["bundle_immutable_after_return_claim_allowed"])
        self.assertFalse(result["concurrent_same_user_tamper_prevention_claim_allowed"])
        self.assertFalse(result["tamper_evident_storage_claim_allowed"])
        self.assertEqual(
            result["output_bundle_sealed_meaning"],
            "strict verifier passed at return; self-verifiable integrity metadata; "
            "not immutability or tamper prevention",
        )
        self.assertTrue(result["completion_record_present"])
        self.assertFalse(result["hidden_completion_record_present"])
        self.assertNotIn("after_final_rename", phases)

    def test_rename_failure_retains_hidden_completed_candidate_without_incomplete_marker(self) -> None:
        repo = self.make_repo("rename-failure-repo")
        output = self.root / "rename-failure-bundle"
        with mock.patch.object(
            adapter,
            "_rename_directory_no_replace_at",
            side_effect=adapter.GitAdapterError("forced_publication_rename_failure"),
        ):
            result = self.adapt(repo, output)
        self.assertEqual(result["exact_blocker"], "forced_publication_rename_failure")
        self.assertFalse(output.exists())
        self.assertTrue(result["publication_transition_attempted"])
        self.assertFalse(result["publication_transition_succeeded"])
        self.assertTrue(result["hidden_sealed_bundle_preserved"])
        self.assertFalse(result["completion_record_present"])
        self.assertTrue(result["hidden_completion_record_present"])
        self.assertFalse(result["requested_final_output_present_after_failed_seal"])
        hidden = Path(result["incomplete_staging_path"])
        self.assertTrue((hidden / "BUNDLE_COMPLETE.json").is_file())
        self.assertFalse((hidden / adapter.INCOMPLETE_MARKER_NAME).exists())
        self.assertTrue(result["incomplete_marker_suppressed_due_completion_record"])

    def test_destination_race_preserves_unowned_final_and_hidden_owned_bundle(self) -> None:
        repo = self.make_repo("destination-race-repo")
        output = self.root / "destination-race-bundle"
        original_rename = adapter._rename_directory_no_replace_at

        def collide(parent_fd: int, source: str, destination: str) -> None:
            output.mkdir()
            (output / "external-sentinel").write_bytes(b"external")
            original_rename(parent_fd, source, destination)

        with mock.patch.object(adapter, "_rename_directory_no_replace_at", new=collide):
            result = self.adapt(repo, output)
        self.assertEqual(result["exact_blocker"], "output_path_must_not_exist")
        self.assertEqual((output / "external-sentinel").read_bytes(), b"external")
        self.assertTrue(result["unowned_replacement_detected"])
        self.assertFalse(result["requested_final_output_is_adapter_owned"])
        # The final result reports literal caller-visible presence independently from
        # ownership; the racing unowned sentinel is present and preserved.
        self.assertTrue(result["requested_final_output_present_after_failed_seal"])
        self.assertTrue(result["requested_final_output_present_at_return"])
        self.assertFalse(result["requested_final_output_is_adapter_owned_at_return"])
        self.assertEqual(result["unowned_replacement_path"], str(output))
        self.assertFalse(result["completion_record_present"])
        self.assertTrue(result["hidden_completion_record_present"])
        hidden = Path(result["incomplete_staging_path"])
        self.assertTrue((hidden / "BUNDLE_COMPLETE.json").is_file())
        self.assertFalse((hidden / adapter.INCOMPLETE_MARKER_NAME).exists())

    def test_unknown_before_publication_never_reaches_requested_final_name(self) -> None:
        repo = self.make_repo("unknown-prepublication-repo")
        output = self.root / "unknown-prepublication-bundle"

        def inject(phase: str, owned: adapter.OwnedOutputTree) -> None:
            if phase == "before_publication_rename":
                (owned.path / "external-unknown").write_bytes(b"preserve")

        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = inject
        result = self.adapt(repo, output)
        self.assertEqual(result["exact_blocker"], "output_bundle_unknown_entry_detected")
        self.assertFalse(output.exists())
        self.assertFalse(result["publication_transition_attempted"])
        self.assertFalse(result["completion_record_present"])
        self.assertTrue(result["hidden_completion_record_present"])
        hidden = Path(result["incomplete_staging_path"])
        self.assertEqual((hidden / "external-unknown").read_bytes(), b"preserve")
        self.assertTrue((hidden / "BUNDLE_COMPLETE.json").is_file())
        self.assertFalse((hidden / adapter.INCOMPLETE_MARKER_NAME).exists())

    def test_removed_hidden_completion_is_not_reported_present(self) -> None:
        repo = self.make_repo("removed-completion-repo")
        output = self.root / "removed-completion-bundle"

        def remove_completion(phase: str, owned: adapter.OwnedOutputTree) -> None:
            if phase == "before_publication_rename":
                (owned.path / "BUNDLE_COMPLETE.json").unlink()

        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = remove_completion
        result = self.adapt(repo, output)

        self.assertEqual(result["exact_blocker"], "output_bundle_missing_entry_detected")
        self.assertFalse(result["publication_transition_attempted"])
        self.assertFalse(result["completion_record_present"])
        self.assertFalse(result["hidden_completion_record_present"])
        self.assertFalse(output.exists())

    def test_early_block_uses_complete_result_shape(self) -> None:
        non_repository = self.root / "not-a-repository"
        non_repository.mkdir()
        result = self.adapt(non_repository, self.root / "early-block-output")
        self.assertEqual(result["result"], "blocked")
        self.assertIn("incomplete_marker_written", result)
        self.assertFalse(result["incomplete_marker_written"])
        self.assertIn("hidden_completion_record_present", result)
        self.assertFalse(result["hidden_completion_record_present"])

    def test_precompletion_failure_has_no_contradictory_disk_marker(self) -> None:
        repo = self.make_repo("precompletion-failure-repo")
        output = self.root / "precompletion-failure-bundle"
        adapter.ADAPTER_TEST_HOOK = lambda root: (root / "README.md").write_text(
            "repository race\n", encoding="utf-8"
        )
        result = self.adapt(repo, output)
        self.assertEqual(result["exact_blocker"], "repository_state_changed_during_adaptation")
        self.assertFalse(output.exists())
        self.assertFalse(result["completion_record_present"])
        self.assertFalse(result["hidden_completion_record_present"])
        hidden = Path(result["incomplete_staging_path"])
        self.assertFalse((hidden / "BUNDLE_COMPLETE.json").exists())
        self.assertFalse((hidden / adapter.INCOMPLETE_MARKER_NAME).exists())
        self.assertFalse(result["incomplete_marker_suppressed_due_completion_record"])

    def test_legacy_relocate_transition_is_disabled(self) -> None:
        parent = self.root / "legacy-relocate-parent"
        parent.mkdir()
        lease = adapter.OutputParentLease.acquire(parent, "final")
        owned = adapter.OwnedOutputTree.create(lease, "staging", "README.md")
        try:
            with self.assertRaisesRegex(adapter.GitAdapterError, "legacy_relocate_disabled"):
                owned.relocate()
            self.assertTrue((parent / "staging").is_dir())
            self.assertFalse((parent / "final").exists())
        finally:
            owned.close()
            lease.close()

    def test_metadata_descriptor_release_cannot_override_published_result(self) -> None:
        lease = adapter.GitMetadataLease(
            repo=self.root,
            git_dir=self.root / ".git",
            repo_fd=101,
            git_fd=102,
            root_fds={"objects": 103, "refs": 104},
            repo_identity={},
            git_identity={},
            root_identities={},
            initial_inventory={},
        )
        with mock.patch.object(
            adapter.os, "close", side_effect=OSError("synthetic close failure")
        ):
            lease.close()
        self.assertTrue(lease.closed)
        lease.close()

if __name__ == "__main__":
    unittest.main()
