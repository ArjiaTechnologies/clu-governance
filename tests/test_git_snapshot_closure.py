from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from clu_governance import git_diff_adapter as adapter
from clu_governance import source_mutation_demo_runtime as runtime
from clu_governance import source_mutation_policy_gate as gate


MACOS_ADAPTER_INTEGRATION_REASON = (
    "requires successful macOS git-adapt execution; unsupported-platform "
    "fail-closed behavior is covered separately"
)


def macos_adapter_integration(*portable_test_names: str):
    """Apply per-test macOS skips while retaining filesystem-only coverage."""

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
    "test_barrier_closes_visible_parent_transition",
    "test_barrier_closes_transition_after_second_root_check",
    "test_registered_nested_directory_swap_receives_no_payload",
    "test_exact_seal_closes_directory_lstat_open_transition",
)
class GitSnapshotClosureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="clu-git-closure.")).resolve()

    def tearDown(self) -> None:
        adapter.EXACT_SEAL_TEST_HOOK = None
        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
        shutil.rmtree(self.root, ignore_errors=True)

    def git(self, repo: pathlib.Path, *arguments: str) -> None:
        subprocess.run(
            [shutil.which("git") or "git", *arguments],
            cwd=repo,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=True,
        )

    def fixture(self, name: str = "fixture") -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
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
        policy = self.root / f"{name}-policy.json"
        policy.write_text(json.dumps(runtime.build_demo_policy()), encoding="utf-8")
        output = self.root / f"{name}-bundle"
        return repo, policy, output

    def adapt(self, repo: pathlib.Path, policy: pathlib.Path, output: pathlib.Path) -> dict:
        return adapter.adapt_git_diff(
            repo_path=repo,
            policy_path=policy,
            declared_actor_id="demo_operator",
            requested_scope="docs_only",
            output_dir=output,
            event_time="2026-06-26T00:00:00Z",
        )

    def test_transient_private_evaluation_request_cannot_seal_other_bytes(self) -> None:
        repo, policy, output = self.fixture("request-substitution")
        original = gate.evaluate_source_mutation_request

        def substitute(**kwargs):
            request_path = pathlib.Path(kwargs["request_path"])
            genuine = request_path.read_bytes()
            request = json.loads(genuine)
            request["request_id"] = "transient-other-request"
            request["proposal_body"]["description"] = "transient replacement"
            request["proposal_hash"] = gate.canonical_sha256(request["proposal_body"])
            request_path.write_text(json.dumps(request), encoding="utf-8")
            try:
                return original(**kwargs)
            finally:
                request_path.write_bytes(genuine)

        with mock.patch.object(gate, "evaluate_source_mutation_request", side_effect=substitute):
            result = self.adapt(repo, policy, output)
        self.assertEqual(
            result["exact_blocker"],
            "generated_policy_decision_genuine_artifact_binding_failed",
        )
        self.assertFalse(result["output_bundle_sealed"])
        self.assertFalse(output.exists())
        self.assertIsNotNone(result["incomplete_staging_path"])

    def test_transient_private_evaluation_rollback_cannot_drive_decision(self) -> None:
        repo, policy, output = self.fixture("rollback-substitution")
        original = gate.evaluate_source_mutation_request

        def substitute(**kwargs):
            request = json.loads(pathlib.Path(kwargs["request_path"]).read_text(encoding="utf-8"))
            rollback_path = pathlib.Path(request["rollback_readiness"]["artifact_path"])
            genuine = rollback_path.read_bytes()
            rollback_path.write_bytes(b"{}\n")
            try:
                return original(**kwargs)
            finally:
                rollback_path.write_bytes(genuine)

        with mock.patch.object(gate, "evaluate_source_mutation_request", side_effect=substitute):
            result = self.adapt(repo, policy, output)
        self.assertEqual(
            result["exact_blocker"],
            "generated_policy_decision_genuine_artifact_binding_failed",
        )
        self.assertFalse(result["output_bundle_sealed"])
        self.assertFalse(output.exists())

    def test_barrier_closes_visible_parent_transition(self) -> None:
        parent = self.root / "parent"
        parent.mkdir()
        old_parent = self.root / "old-parent"
        lease = adapter.OutputParentLease.acquire(parent, "final")
        owned = adapter.OwnedOutputTree.create(lease, "staging", "README.md")
        owned._write_marker()
        original = owned._root_identity_valid
        changed = False

        def replace_once() -> bool:
            nonlocal changed
            if not changed:
                changed = True
                parent.rename(old_parent)
                parent.mkdir()
                (parent / "sentinel").write_bytes(b"preserve")
            return original()

        try:
            with mock.patch.object(owned, "_root_identity_valid", side_effect=replace_once):
                with self.assertRaisesRegex(adapter.GitAdapterError, "output_parent_identity_changed"):
                    owned.barrier("probe")
            self.assertEqual((parent / "sentinel").read_bytes(), b"preserve")
        finally:
            owned.close()
            lease.close()

    def test_barrier_closes_transition_after_second_root_check(self) -> None:
        parent = self.root / "parent-second"
        parent.mkdir()
        old_parent = self.root / "old-parent-second"
        lease = adapter.OutputParentLease.acquire(parent, "final")
        owned = adapter.OwnedOutputTree.create(lease, "staging", "README.md")
        owned._write_marker()
        original = owned._root_identity_valid
        calls = 0

        def replace_on_second() -> bool:
            nonlocal calls
            calls += 1
            if calls == 2:
                parent.rename(old_parent)
                parent.mkdir()
                (parent / "sentinel").write_bytes(b"preserve")
            return original()

        try:
            with mock.patch.object(owned, "_root_identity_valid", side_effect=replace_on_second):
                with self.assertRaisesRegex(adapter.GitAdapterError, "output_parent_identity_changed"):
                    owned.barrier("probe-second")
            self.assertEqual((parent / "sentinel").read_bytes(), b"preserve")
        finally:
            owned.close()
            lease.close()

    def test_failure_disposition_never_moves_unowned_source_replacement(self) -> None:
        parent = self.root / "quarantine-parent"
        parent.mkdir()
        lease = adapter.OutputParentLease.acquire(parent, "final")
        owned = adapter.OwnedOutputTree.create(lease, "staging", "README.md")
        owned._write_marker()
        owned.publish_final_action()
        genuine = self.root / "genuine-orphan"
        (parent / "final").rename(genuine)
        (parent / "final").mkdir()
        (parent / "final" / "sentinel").write_bytes(b"external")
        try:
            with mock.patch.object(
                adapter,
                "_rename_directory_no_replace_at",
                side_effect=AssertionError("failure disposition must not rename"),
            ) as rename:
                report = owned.preserve_failure("forced")
            rename.assert_not_called()
            self.assertEqual((parent / "final" / "sentinel").read_bytes(), b"external")
            self.assertTrue((genuine / adapter.OWNERSHIP_MARKER_NAME).is_file())
            self.assertTrue(report["unowned_replacement_detected"])
            self.assertFalse(report["requested_final_output_is_adapter_owned"])
            self.assertEqual(report["output_entries_deleted"], [])
        finally:
            owned.close()
            lease.close()

    def test_registered_nested_directory_swap_receives_no_payload(self) -> None:
        parent = self.root / "nested-parent"
        parent.mkdir()
        lease = adapter.OutputParentLease.acquire(parent, "final")
        owned = adapter.OwnedOutputTree.create(lease, "staging", "README.md")
        owned._write_marker()
        owned.mkdir_relative("baseline_source")
        visible = parent / "staging" / "baseline_source"
        genuine = parent / "staging" / "genuine-baseline"
        visible.rename(genuine)
        visible.mkdir()
        (visible / "sentinel").write_bytes(b"external")
        try:
            with self.assertRaisesRegex(
                adapter.GitAdapterError, "adapter_output_directory_binding_changed"
            ):
                owned.write_bytes_once("baseline_source/README.md", b"do-not-write")
            self.assertFalse((visible / "README.md").exists())
            self.assertEqual((visible / "sentinel").read_bytes(), b"external")
        finally:
            owned.close()
            lease.close()

    def test_exact_seal_closes_directory_lstat_open_transition(self) -> None:
        parent = self.root / "seal-parent"
        parent.mkdir()
        lease = adapter.OutputParentLease.acquire(parent, "final")
        owned = adapter.OwnedOutputTree.create(lease, "staging", "README.md")
        owned._write_marker()
        owned.mkdir_relative("baseline_source")
        owned.write_bytes_once("baseline_source/README.md", b"baseline")
        swapped = False

        def swap(phase: str, detail: dict) -> None:
            nonlocal swapped
            if phase != "before_entry_open" or detail["relative"] != "baseline_source" or swapped:
                return
            swapped = True
            root = parent / "staging"
            (root / "baseline_source").rename(root / "baseline_source.old")
            (root / "baseline_source").mkdir()
            (root / "baseline_source.old" / "README.md").rename(
                root / "baseline_source" / "README.md"
            )

        adapter.EXACT_SEAL_TEST_HOOK = swap
        try:
            with self.assertRaisesRegex(
                adapter.GitAdapterError,
                "output_bundle_(registered_entry_changed|unknown_entry_detected)",
            ):
                owned.verify_exact(
                    {adapter.OWNERSHIP_MARKER_NAME, "baseline_source/README.md"}
                )
        finally:
            adapter.EXACT_SEAL_TEST_HOOK = None
            owned.close()
            lease.close()

    def test_injection_during_last_checksum_read_is_caught_by_final_seal(self) -> None:
        repo, policy, output = self.fixture("late-injection")
        original = adapter._verify_artifact_checksums
        calls = 0

        def inject(owned: adapter.OwnedOutputTree) -> bool:
            nonlocal calls
            calls += 1
            verified = original(owned)
            if calls == 3:
                pathlib.Path(owned.path, "late-unknown.txt").write_bytes(b"unknown")
            return verified

        with mock.patch.object(adapter, "_verify_artifact_checksums", side_effect=inject):
            result = self.adapt(repo, policy, output)
        self.assertEqual(result["exact_blocker"], "output_bundle_unknown_entry_detected")
        self.assertFalse(result["output_bundle_sealed"])
        self.assertFalse(output.exists())
        checksum = pathlib.Path(result["incomplete_staging_path"]) / "CHECKSUMS.sha256"
        self.assertNotIn("late-unknown.txt", checksum.read_text(encoding="utf-8"))

    def test_worktree_config_extension_blocks_before_content_sensitive_status(self) -> None:
        repo, policy, output = self.fixture("worktree-config")
        self.git(repo, "config", "extensions.worktreeConfig", "true")
        commands: list[str] = []
        original = adapter.GitRunner.run

        def observe(runner, arguments, **kwargs):
            commands.append(arguments[0])
            return original(runner, arguments, **kwargs)

        with mock.patch.object(adapter.GitRunner, "run", new=observe):
            result = self.adapt(repo, policy, output)
        self.assertEqual(
            result["exact_blocker"], "repository_worktree_config_extension_unsupported"
        )
        self.assertNotIn("status", commands)
        self.assertFalse(output.exists())

    def test_transient_local_filter_config_never_executes_helper(self) -> None:
        repo, policy, output = self.fixture("transient-filter")
        # Track attributes before the one supported same-size modification.
        (repo / "README.md").write_text("# Demo\n\nBaseline.\n", encoding="utf-8")
        (repo / ".gitattributes").write_text(
            "README.md filter=tripwire\n", encoding="utf-8"
        )
        self.git(repo, "add", "README.md", ".gitattributes")
        self.git(repo, "commit", "-q", "-m", "attribute baseline")
        baseline = (repo / "README.md").read_bytes()
        proposed = baseline.replace(b"Baseline", b"Proposal")
        self.assertEqual(len(baseline), len(proposed))
        (repo / "README.md").write_bytes(proposed)
        sentinel = self.root / "filter-executed"
        helper = self.root / "filter.sh"
        helper.write_text(
            f"#!/bin/sh\nprintf executed > '{sentinel}'\ncat\n", encoding="utf-8"
        )
        helper.chmod(0o700)
        original_run = adapter.GitRunner.run
        injected = False

        def race(runner, arguments, **kwargs):
            nonlocal injected
            if arguments[0] != "status" or injected:
                return original_run(runner, arguments, **kwargs)
            injected = True
            config = repo / ".git" / "config"
            safe = config.read_bytes()
            config.write_bytes(
                safe + f'\n[filter "tripwire"]\nclean = {helper}\n'.encode("utf-8")
            )
            try:
                return original_run(runner, arguments, **kwargs)
            finally:
                config.write_bytes(safe)

        observed: list[list[str]] = []
        original_process = adapter._run_bounded_process

        def observe_process(command, **kwargs):
            observed.append(command)
            return original_process(command, **kwargs)

        with mock.patch.object(adapter.GitRunner, "run", new=race), mock.patch.object(
            adapter, "_run_bounded_process", new=observe_process
        ):
            result = self.adapt(repo, policy, output)
        self.assertNotEqual(result["result"], "adapted")
        self.assertFalse(sentinel.exists())
        # The retained metadata lease catches the transient config identity
        # change before status can launch.  This is stricter than the earlier
        # sandboxed-status fallback and leaves no repository-controlled helper
        # or content-sensitive Git child to observe.
        self.assertEqual(result["exact_blocker"], "git_metadata_identity_changed")
        self.assertFalse(any(command and command[0] == "/usr/bin/sandbox-exec" for command in observed))
        self.assertFalse(output.exists())

    def test_no_filesystem_barrier_runs_after_final_exact_inventory(self) -> None:
        repo, policy, output = self.fixture("last-seal-operation")
        original = adapter.OwnedOutputTree.barrier
        forbidden_phase_seen = False

        def observe(owned, phase):
            nonlocal forbidden_phase_seen
            if phase == "after_final_exact_seal":
                forbidden_phase_seen = True
                pathlib.Path(owned.path, "post-seal-unknown").write_bytes(b"unknown")
            return original(owned, phase)

        with mock.patch.object(adapter.OwnedOutputTree, "barrier", new=observe):
            result = self.adapt(repo, policy, output)
        self.assertFalse(forbidden_phase_seen)
        self.assertEqual(result["result"], "adapted")
        self.assertTrue(result["output_bundle_sealed"])
        self.assertFalse((output / "post-seal-unknown").exists())

    def test_sanitized_status_detects_second_mode_only_path(self) -> None:
        repo, policy, output = self.fixture("second-mode-path")
        (repo / "README.md").write_text("# Demo\n\nBaseline.\n", encoding="utf-8")
        (repo / "OTHER.md").write_text("other\n", encoding="utf-8")
        self.git(repo, "add", "README.md", "OTHER.md")
        self.git(repo, "commit", "-q", "-m", "two-file baseline")
        (repo / "README.md").write_text(
            "# Demo\n\nProposed local edit.\n", encoding="utf-8"
        )
        os.chmod(repo / "OTHER.md", 0o755)
        result = self.adapt(repo, policy, output)
        self.assertEqual(result["exact_blocker"], "exactly_one_changed_path_required")
        self.assertNotEqual(result["result"], "adapted")
        self.assertFalse(output.exists())

    def test_prepublication_injection_is_preserved_hidden_and_never_published(self) -> None:
        repo, policy, output = self.fixture("prepublication-injection")

        def inject(phase: str, owned: adapter.OwnedOutputTree) -> None:
            if phase == "before_publication_rename":
                pathlib.Path(owned.path, "prepublication-unknown").write_bytes(b"external")

        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = inject
        result = self.adapt(repo, policy, output)
        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
        self.assertEqual(result["exact_blocker"], "output_bundle_unknown_entry_detected")
        self.assertFalse(result["output_bundle_sealed"])
        self.assertFalse(result["requested_final_output_present_after_failed_seal"])
        self.assertFalse(output.exists())
        hidden = pathlib.Path(result["incomplete_staging_path"])
        self.assertEqual((hidden / "prepublication-unknown").read_bytes(), b"external")
        self.assertTrue((hidden / "BUNDLE_COMPLETE.json").is_file())
        self.assertFalse((hidden / adapter.INCOMPLETE_MARKER_NAME).exists())

    def test_transient_private_policy_substitution_cannot_create_false_allow(self) -> None:
        repo, policy, output = self.fixture("policy-substitution")
        deny_policy = runtime.build_demo_policy()
        deny_policy["allowed_paths"] = []
        deny_policy["allowed_path_globs"] = []
        deny_policy["rules"] = [
            rule for rule in deny_policy["rules"] if rule.get("effect") != "allow"
        ]
        policy.write_text(json.dumps(deny_policy), encoding="utf-8")
        allow_bytes = json.dumps(runtime.build_demo_policy()).encode("utf-8")
        original = gate.load_policy

        def substitute(path):
            target = pathlib.Path(path)
            genuine = target.read_bytes()
            target.write_bytes(allow_bytes)
            try:
                return original(target)
            finally:
                target.write_bytes(genuine)

        with mock.patch.object(gate, "load_policy", side_effect=substitute):
            result = self.adapt(repo, policy, output)
        self.assertEqual(
            result["exact_blocker"],
            "generated_policy_decision_genuine_artifact_binding_failed",
        )
        self.assertFalse(result["output_bundle_sealed"])
        self.assertFalse(output.exists())

    def test_repeated_transient_rollback_substitution_cannot_create_false_deny(self) -> None:
        repo, policy, output = self.fixture("repeated-rollback-substitution")
        original = gate.check_rollback_readiness

        def substitute(request, source_root, policy_object):
            path = pathlib.Path(request["rollback_readiness"]["artifact_path"])
            genuine = path.read_bytes()
            path.write_bytes(b"{}\n")
            try:
                return original(request, source_root, policy_object)
            finally:
                path.write_bytes(genuine)

        with mock.patch.object(gate, "check_rollback_readiness", side_effect=substitute):
            result = self.adapt(repo, policy, output)
        self.assertEqual(
            result["exact_blocker"],
            "generated_policy_decision_genuine_artifact_binding_failed",
        )
        self.assertFalse(result["output_bundle_sealed"])
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
