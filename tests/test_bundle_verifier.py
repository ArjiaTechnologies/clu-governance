from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clu_governance import git_diff_adapter as adapter
from clu_governance import source_mutation_demo_runtime as runtime
from clu_governance import source_mutation_policy_gate as gate
from clu_governance.bundle_verifier import RESULT_SCHEMA_NAME, verify_bundle


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SRC = (PACKAGE_ROOT / "src").resolve()


def git(repo: Path, *args: str) -> None:
    result = subprocess.run(
        [shutil.which("git") or "git", *args],
        cwd=repo,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))


def tree_snapshot(root: Path) -> dict[str, tuple[object, ...]]:
    """Capture content and non-atime metadata without following links."""

    snapshot: dict[str, tuple[object, ...]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        info = os.lstat(path)
        common = (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
                  info.st_mtime_ns, info.st_ctime_ns)
        if stat.S_ISREG(info.st_mode):
            snapshot[relative] = ("file", *common, hashlib.sha256(path.read_bytes()).hexdigest())
        elif stat.S_ISDIR(info.st_mode):
            snapshot[relative] = ("directory", *common)
        elif stat.S_ISLNK(info.st_mode):
            snapshot[relative] = ("symlink", *common, os.readlink(path))
        else:
            snapshot[relative] = ("nonregular", *common)
    return snapshot


@unittest.skipUnless(
    sys.platform == "darwin",
    "requires successful macOS git-adapt execution to create a verifier fixture",
)
class BundleVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="clu-bundle-verifier-test.")).resolve()
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

    def make_bundle(self, name: str = "bundle") -> Path:
        repo = self.root / f"repo-{name}"
        repo.mkdir()
        git(repo, "init", "-q")
        git(repo, "config", "user.name", "CLU Synthetic Test")
        git(repo, "config", "user.email", "synthetic@example.invalid")
        (repo / "README.md").write_text("# Demo\n\nBaseline.\n", encoding="utf-8")
        git(repo, "add", "README.md")
        git(repo, "commit", "-q", "-m", "baseline")
        (repo / "README.md").write_text(
            "# Demo\n\nProposed local edit.\n", encoding="utf-8"
        )
        bundle = self.root / name
        result = adapter.adapt_git_diff(
            repo_path=repo,
            policy_path=self.policy,
            declared_actor_id="demo_operator",
            requested_scope="docs_only",
            output_dir=bundle,
            event_time="2026-06-26T00:00:00Z",
        )
        self.assertEqual(result["result"], "adapted", result)
        self.assertTrue(result["bundle_consumer_verifiable"])
        self.assertFalse(result["bundle_immutable"])
        self.assertTrue(result["post_publication_verification_performed"])
        self.assertTrue(result["post_publication_bundle_verified"])
        self.assertFalse(result["post_publication_cleanup_performed"])
        return bundle

    def assert_invalid_without_mutation(
        self, bundle: Path, expected_blocker: str
    ) -> dict[str, object]:
        before = tree_snapshot(bundle)
        result = verify_bundle(bundle)
        after = tree_snapshot(bundle)
        self.assertFalse(result["verified"], result)
        self.assertEqual(result["result"], "invalid")
        self.assertEqual(result["exact_blocker"], expected_blocker)
        self.assertFalse(result["verification_mutation_performed"])
        self.assertFalse(result["cleanup_performed"])
        self.assertEqual(before, after)
        return result

    def rewrite_payload_checksum(self, bundle: Path, relative: str) -> None:
        checksum_path = bundle / "CHECKSUMS.sha256"
        digest = hashlib.sha256((bundle / relative).read_bytes()).hexdigest()
        lines = checksum_path.read_text(encoding="utf-8").splitlines()
        rewritten = [
            f"{digest}  {relative}" if line.endswith(f"  {relative}") else line
            for line in lines
        ]
        checksum_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
        completion_path = bundle / "BUNDLE_COMPLETE.json"
        completion = json.loads(completion_path.read_text(encoding="utf-8"))
        completion["checksums_sha256"] = hashlib.sha256(
            checksum_path.read_bytes()
        ).hexdigest()
        completion_path.write_text(
            json.dumps(completion, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def test_genuine_bundle_verifies_without_mutation_and_claims_are_honest(self) -> None:
        bundle = self.make_bundle()
        before = tree_snapshot(bundle)
        result = verify_bundle(bundle)
        self.assertEqual(result["schema_name"], RESULT_SCHEMA_NAME)
        self.assertEqual(result["result"], "verified")
        self.assertTrue(result["verified"])
        self.assertTrue(result["exact_file_set_verified"])
        self.assertTrue(result["checksums_verified"])
        self.assertTrue(result["completion_verified"])
        self.assertTrue(result["publication_binding_verified"])
        self.assertTrue(result["request_rollback_binding_verified"])
        self.assertTrue(result["decision_integrity_verified"])
        self.assertTrue(result["bundle_consumer_verifiable"])
        self.assertFalse(result["bundle_immutable"])
        self.assertFalse(result["bundle_signed"])
        self.assertFalse(result["identity_authenticated"])
        self.assertFalse(result["future_mutation_prevented"])
        self.assertTrue(result["current_observation_only"])
        self.assertTrue(result["bundle_exact_set_verified_at_return"])
        self.assertTrue(result["bundle_verification_required_at_consumption"])
        self.assertFalse(result["bundle_immutable_after_return_claim_allowed"])
        self.assertFalse(result["concurrent_same_user_tamper_prevention_claim_allowed"])
        self.assertFalse(result["tamper_evident_storage_claim_allowed"])
        self.assertEqual(result["files_created_during_verification"], [])
        self.assertEqual(result["files_removed_during_verification"], [])
        self.assertEqual(result["files_changed_during_verification"], [])
        self.assertEqual(before, tree_snapshot(bundle))

    def test_unknown_and_missing_entries_fail_closed_without_cleanup(self) -> None:
        unknown = self.make_bundle("unknown")
        (unknown / "unexpected.txt").write_bytes(b"external sentinel\n")
        result = self.assert_invalid_without_mutation(unknown, "bundle_unknown_entry_detected")
        self.assertEqual(result["unknown_entries"], ["unexpected.txt"])

        missing = self.make_bundle("missing")
        (missing / "change_preview.diff").unlink()
        result = self.assert_invalid_without_mutation(missing, "bundle_missing_entry_detected")
        self.assertEqual(result["missing_entries"], ["change_preview.diff"])

    def test_symlink_hardlink_and_nonregular_entries_fail_closed(self) -> None:
        symlink = self.make_bundle("symlink")
        external = self.root / "symlink-external"
        external.write_bytes(b"external\n")
        (symlink / "change_preview.diff").unlink()
        (symlink / "change_preview.diff").symlink_to(external)
        result = self.assert_invalid_without_mutation(symlink, "bundle_symlink_entry_detected")
        self.assertEqual(result["symlink_entries"], ["change_preview.diff"])

        hardlink = self.make_bundle("hardlink")
        target = hardlink / "change_preview.diff"
        payload = target.read_bytes()
        target.unlink()
        hardlink_external = self.root / "hardlink-external"
        hardlink_external.write_bytes(payload)
        os.link(hardlink_external, target)
        result = self.assert_invalid_without_mutation(hardlink, "bundle_hardlink_entry_detected")
        self.assertEqual(result["hardlink_entries"], ["change_preview.diff"])

        nonregular = self.make_bundle("nonregular")
        fifo = nonregular / "change_preview.diff"
        fifo.unlink()
        os.mkfifo(fifo)
        result = self.assert_invalid_without_mutation(nonregular, "bundle_nonregular_entry_detected")
        self.assertEqual(result["nonregular_entries"], ["change_preview.diff"])

    def test_checksum_duplicate_json_and_completion_inconsistency_fail_closed(self) -> None:
        checksum = self.make_bundle("checksum")
        (checksum / "change_preview.diff").write_bytes(b"tampered\n")
        self.assert_invalid_without_mutation(checksum, "bundle_checksum_invalid")

        duplicate = self.make_bundle("duplicate")
        (duplicate / "source_mutation_request.json").write_text(
            '{"schema_name":"first","schema_name":"second"}\n', encoding="utf-8"
        )
        result = self.assert_invalid_without_mutation(
            duplicate,
            "bundle_json_duplicate_key:source_mutation_request.json",
        )
        self.assertFalse(result["checksums_verified"])

        inconsistent = self.make_bundle("completion")
        completion_path = inconsistent / "BUNDLE_COMPLETE.json"
        completion = json.loads(completion_path.read_text(encoding="utf-8"))
        completion["intended_final_name"] = "not-the-published-name"
        completion_path.write_text(
            json.dumps(completion, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.assert_invalid_without_mutation(inconsistent, "bundle_completion_inconsistent")

    def test_schema_container_type_confusion_is_invalid_not_runtime_failure(self) -> None:
        invalid_operation = self.make_bundle("invalid-operation")
        request_path = invalid_operation / "source_mutation_request.json"
        request = json.loads(request_path.read_text(encoding="utf-8"))
        request["operations"] = [None]
        request_path.write_text(
            json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.rewrite_payload_checksum(invalid_operation, "source_mutation_request.json")
        self.assert_invalid_without_mutation(
            invalid_operation, "bundle_request_rollback_binding_invalid"
        )

        invalid_rollback = self.make_bundle("invalid-rollback-entry")
        rollback_path = invalid_rollback / "rollback_snapshot.json"
        rollback = json.loads(rollback_path.read_text(encoding="utf-8"))
        rollback["files"]["README.md"] = None
        rollback_path.write_text(
            json.dumps(rollback, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.rewrite_payload_checksum(invalid_rollback, "rollback_snapshot.json")
        self.assert_invalid_without_mutation(
            invalid_rollback, "bundle_request_rollback_binding_invalid"
        )

    def test_boolean_integer_type_confusion_is_rejected(self) -> None:
        for field in ("seal_version", "bundle_verification_contract_version"):
            with self.subTest(field=field):
                bundle = self.make_bundle(f"bool-{field}")
                completion_path = bundle / "BUNDLE_COMPLETE.json"
                completion = json.loads(completion_path.read_text(encoding="utf-8"))
                completion[field] = True
                completion_path.write_text(
                    json.dumps(completion, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                self.assert_invalid_without_mutation(
                    bundle, "bundle_completion_inconsistent"
                )

        decision_bool = self.make_bundle("bool-decision-counter")
        decision_path = decision_bool / "policy_decision.json"
        decision = json.loads(decision_path.read_text(encoding="utf-8"))
        decision["network_calls"] = False
        decision["audit_event_hash"] = gate.canonical_sha256(
            {key: value for key, value in decision.items() if key != "audit_event_hash"}
        )
        decision_path.write_text(
            json.dumps(decision, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.rewrite_payload_checksum(decision_bool, "policy_decision.json")
        self.assert_invalid_without_mutation(
            decision_bool, "bundle_decision_integrity_invalid"
        )

    def test_cli_and_module_emit_one_json_object_with_exact_exit_codes(self) -> None:
        bundle = self.make_bundle("cli")
        env = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(PACKAGE_SRC),
        }
        commands = (
            [sys.executable, "-B", "-m", "clu_governance.cli"],
            [sys.executable, "-B", "-m", "clu_governance.bundle_verifier"],
        )
        for prefix in commands:
            with self.subTest(prefix=prefix):
                command = prefix + (["verify-bundle"] if prefix[-1].endswith(".cli") else [])
                completed = subprocess.run(
                    command + ["--bundle", str(bundle), "--json"],
                    cwd=PACKAGE_ROOT,
                    env=env,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
                payload = json.loads(completed.stdout)
                self.assertEqual(payload["schema_name"], RESULT_SCHEMA_NAME)
                self.assertTrue(payload["verified"])
                end = json.JSONDecoder().raw_decode(completed.stdout)[1]
                self.assertEqual(completed.stdout[end:].strip(), "")
                self.assertEqual(completed.stderr, "")

        (bundle / "unexpected.txt").write_bytes(b"sentinel\n")
        invalid = subprocess.run(
            [sys.executable, "-B", "-m", "clu_governance.cli", "verify-bundle",
             "--bundle", str(bundle), "--json"],
            cwd=PACKAGE_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
        )
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(json.loads(invalid.stdout)["exact_blocker"], "bundle_unknown_entry_detected")
        self.assertEqual(invalid.stderr, "")

    def test_defensive_verifier_failure_is_distinct_and_uses_exit_one(self) -> None:
        with mock.patch(
            "clu_governance.bundle_verifier.BundleReader",
            side_effect=RuntimeError("synthetic defensive failure"),
        ):
            result = verify_bundle(self.root / "not-opened")
        self.assertEqual(result["result"], "failed")
        self.assertEqual(
            result["exact_blocker"], "bundle_verifier_runtime_failure:RuntimeError"
        )
        from clu_governance.bundle_verifier import exit_code_for_result

        self.assertEqual(exit_code_for_result(result), 1)

    def test_post_publication_verification_catches_late_pre_rename_injection(self) -> None:
        repo = self.root / "repo-late-injection"
        repo.mkdir()
        git(repo, "init", "-q")
        git(repo, "config", "user.name", "CLU Synthetic Test")
        git(repo, "config", "user.email", "synthetic@example.invalid")
        (repo / "README.md").write_text("baseline\n", encoding="utf-8")
        git(repo, "add", "README.md")
        git(repo, "commit", "-q", "-m", "baseline")
        (repo / "README.md").write_text("proposed local edit\n", encoding="utf-8")
        bundle = self.root / "late-injection-bundle"
        original_rename = adapter._rename_directory_no_replace_at

        def inject_then_rename(parent_fd: int, source: str, destination: str) -> None:
            directory_fd = os.open(
                source,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            try:
                descriptor = os.open(
                    "late-pre-rename-injection.txt",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
                try:
                    os.write(descriptor, b"external sentinel preserved\n")
                finally:
                    os.close(descriptor)
            finally:
                os.close(directory_fd)
            original_rename(parent_fd, source, destination)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            adapter, "_rename_directory_no_replace_at", side_effect=inject_then_rename
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = gate.main(
                [
                    "git-adapt", "--repo", str(repo), "--policy", str(self.policy),
                    "--declared-actor-id", "demo_operator", "--scope", "docs_only",
                    "--output-dir", str(bundle), "--event-time", "2026-06-26T00:00:00Z",
                    "--json",
                ]
            )

        self.assertEqual(exit_code, 2)
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["result"], "blocked")
        self.assertTrue(payload["post_publication_verification_performed"], payload)
        self.assertFalse(payload["post_publication_bundle_verified"])
        self.assertFalse(payload["post_publication_cleanup_performed"])
        self.assertFalse(payload["output_bundle_sealed"])
        self.assertFalse(payload["bundle_exact_set_verified_at_return"])
        self.assertTrue(payload["bundle_verification_required_at_consumption"])
        self.assertFalse(payload["bundle_immutable_after_return_claim_allowed"])
        self.assertFalse(payload["concurrent_same_user_tamper_prevention_claim_allowed"])
        self.assertFalse(payload["tamper_evident_storage_claim_allowed"])
        self.assertIsNone(payload["output_bundle_sealed_meaning"])
        self.assertEqual(
            payload["exact_blocker"],
            "post_publication_bundle_verification_failed:bundle_unknown_entry_detected",
        )
        self.assertEqual(
            payload["output_bundle_unknown_entries"],
            ["late-pre-rename-injection.txt"],
        )
        self.assertEqual(
            payload["post_publication_verification_result"]["unknown_entries"],
            ["late-pre-rename-injection.txt"],
        )
        sentinel = bundle / "late-pre-rename-injection.txt"
        self.assertEqual(sentinel.read_bytes(), b"external sentinel preserved\n")
        self.assertTrue(bundle.is_dir())
        end = json.JSONDecoder().raw_decode(stdout.getvalue())[1]
        self.assertEqual(stdout.getvalue()[end:].strip(), "")


if __name__ == "__main__":
    unittest.main()
