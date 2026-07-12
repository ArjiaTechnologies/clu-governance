from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from clu_governance import source_mutation_demo_runtime as runtime
from clu_governance import source_mutation_policy_gate as gate


FIXED_TIME = "2026-06-26T00:00:00Z"
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
STANDALONE_SRC = (PACKAGE_ROOT / "src").resolve()
EXACT_DEMO_COMMAND = "PYTHONPATH=src python -B -m clu_governance.source_mutation_policy_gate demo-run-all --json"
EXACT_TEST_COMMAND = "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -B -m unittest discover -s tests -v"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _tree_inventory(root: Path) -> dict[str, object]:
    files: dict[str, str] = {}
    directories: list[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_dir():
            directories.append(rel)
        elif path.is_file():
            files[rel] = _sha256_file(path)
        else:
            files[rel] = "<non-regular>"
    tree_payload = {"directories": directories, "files": files}
    return {
        **tree_payload,
        "tree_hash": hashlib.sha256(json.dumps(tree_payload, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def _prohibited_cache_paths(root: Path) -> list[str]:
    prohibited: list[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.name == "__pycache__" or path.name == ".pytest_cache" or path.suffix in {".pyc", ".pyo"}:
            prohibited.append(rel)
    return prohibited


def _verify_internal_checksums(root: Path) -> None:
    checksum_path = root / "CHECKSUMS.sha256"
    listed: set[str] = set()
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        expected, rel_path = line.split(maxsplit=1)
        rel_path = rel_path.removeprefix("./")
        listed.add(rel_path)
        path = root / rel_path
        if not path.exists():
            raise AssertionError(f"missing checksum path: {rel_path}")
        if _sha256_file(path) != expected:
            raise AssertionError(f"checksum mismatch: {rel_path}")
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "CHECKSUMS.sha256"
    }
    if actual != listed:
        raise AssertionError(f"unlisted or missing files: {sorted(actual ^ listed)}")


def _copy_package_for_tree_test(temp_root: Path) -> Path:
    copied_parent = temp_root / "tree-preservation-child"
    copied_package = copied_parent / "STANDALONE_GOVERNANCE_PACKAGE"
    # Git metadata and local build products are not part of the standalone
    # public package tree. Excluding them keeps this preservation probe tied
    # to the checksummed candidate files when it runs from a GitHub checkout.
    ignore = shutil.ignore_patterns(
        ".git", "__pycache__", ".pytest_cache", "build", "dist",
        "*.pyc", "*.pyo", "*.egg-info",
    )
    shutil.copytree(PACKAGE_ROOT, copied_package, ignore=ignore)
    return copied_package


def _run_demo_command(package_root: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.pop("PYTHONDONTWRITEBYTECODE", None)
    env["PYTHONPATH"] = "src"
    return subprocess.run(
        [sys.executable, "-B", "-m", "clu_governance.source_mutation_policy_gate", "demo-run-all", "--json"],
        cwd=package_root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _run_test_command(package_root: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = "src"
    return subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=package_root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def _assert_tree_unchanged(before: dict[str, object], after: dict[str, object]) -> None:
    before_files = before["files"]
    after_files = after["files"]
    before_dirs = before["directories"]
    after_dirs = after["directories"]
    assert isinstance(before_files, dict)
    assert isinstance(after_files, dict)
    assert isinstance(before_dirs, list)
    assert isinstance(after_dirs, list)
    added_files = sorted(set(after_files) - set(before_files))
    removed_files = sorted(set(before_files) - set(after_files))
    changed_files = sorted(path for path in set(before_files) & set(after_files) if before_files[path] != after_files[path])
    added_dirs = sorted(set(after_dirs) - set(before_dirs))
    removed_dirs = sorted(set(before_dirs) - set(after_dirs))
    if added_files or removed_files or changed_files or added_dirs or removed_dirs:
        raise AssertionError(
            {
                "added_files": added_files,
                "removed_files": removed_files,
                "changed_files": changed_files,
                "added_dirs": added_dirs,
                "removed_dirs": removed_dirs,
            }
        )


def _artifact_paths(init: dict[str, object]) -> dict[str, Path]:
    policy = Path(str(init["policy_path"]))
    return {
        "policy": policy,
        "request": Path(str(init["allowed_request_path"])),
        "denied_request": Path(str(init["denied_request_path"])),
        "repo": Path(str(init["demo_repo"])),
        "artifacts": policy.parent,
        "rollback": Path(str(init["rollback_snapshot_path"])),
    }


class StandaloneGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_root = Path(tempfile.mkdtemp(prefix="clu-governance-standalone-test.")).resolve()

    def tearDown(self) -> None:
        runtime.POST_APPLY_TEST_HOOK = None
        shutil.rmtree(self.temp_root, ignore_errors=True)

    def _init_paths(self) -> tuple[Path, dict[str, Path]]:
        workspace = self.temp_root / "workspace"
        init = gate.demo_init(workspace, reset=True)
        self.assertEqual(init["result"], "ready")
        return workspace, _artifact_paths(init)

    def _evaluate_to(self, output: Path, policy: Path, request: Path, repo: Path) -> dict[str, object]:
        decision = gate.evaluate_source_mutation_request(
            policy_path=policy,
            request_path=request,
            source_root=repo,
            event_timestamp=FIXED_TIME,
        )
        gate.write_decision_output(decision, output, repo)
        return decision

    def _init_approve(self) -> tuple[Path, dict[str, Path]]:
        workspace, paths = self._init_paths()
        decision_path = paths["artifacts"] / "allowed_decision.json"
        decision = self._evaluate_to(decision_path, paths["policy"], paths["request"], paths["repo"])
        self.assertEqual(decision["decision"], "allow")
        approval_path = paths["artifacts"] / "approval.json"
        approval = gate.demo_approve(
            workspace,
            decision_path=decision_path,
            approval_path=approval_path,
            decision="approved",
        )
        self.assertEqual(approval["result"], "approval_recorded")
        self.assertEqual(approval["approval_input_mode"], "cli_argument")
        self.assertFalse(approval["approval_identity_authenticated"])
        self.assertFalse(approval["human_presence_verified"])
        self.assertFalse(approval["approval_rationale_recorded"])
        paths["decision"] = decision_path
        paths["approval"] = approval_path
        return workspace, paths

    def _execute(self, workspace: Path, paths: dict[str, Path], *, retention: str = "rollback_requested") -> dict[str, object]:
        return gate.demo_execute(
            workspace=workspace,
            decision_path=paths["decision"],
            approval_path=paths["approval"],
            request_path=paths["request"],
            policy_path=paths["policy"],
            source_root=paths["repo"],
            packaged_source_root=runtime.actual_executable_source_root(),
            retention_decision=retention,
        )

    def test_denied_and_eligible_requests(self) -> None:
        _workspace, paths = self._init_paths()
        denied = gate.evaluate_source_mutation_request(
            policy_path=paths["policy"],
            request_path=paths["denied_request"],
            source_root=paths["repo"],
            event_timestamp=FIXED_TIME,
        )
        allowed = gate.evaluate_source_mutation_request(
            policy_path=paths["policy"],
            request_path=paths["request"],
            source_root=paths["repo"],
            event_timestamp=FIXED_TIME,
        )

        self.assertEqual(denied["decision"], "deny")
        self.assertEqual(denied["exact_blocker"], "delete_operation_denied")
        self.assertEqual(allowed["decision"], "allow")
        self.assertTrue(allowed["eligible_for_human_approval"])
        self.assertFalse(allowed["mutation_authorized"])
        self.assertFalse(allowed["mutation_applied"])
        self.assertEqual(allowed["provider_calls"], 0)
        self.assertEqual(allowed["advisor_calls"], 0)
        self.assertEqual(allowed["mem0_runs"], 0)
        self.assertEqual(allowed["benchmark_runs"], 0)
        self.assertEqual(allowed["network_calls"], 0)

    def test_exact_approval_binding_and_successful_rollback(self) -> None:
        workspace, paths = self._init_approve()
        result = self._execute(workspace, paths, retention="rollback_requested")

        self.assertEqual(result["result"], "passed")
        self.assertTrue(result["approval_verified"])
        self.assertTrue(result["rollback_executed"])
        self.assertTrue(result["mutation_was_applied"])
        self.assertFalse(result["mutation_present_after_execution"])
        self.assertEqual(result["approved_operation_count"], 1)
        self.assertEqual(result["executed_operation_count"], 1)
        self.assertFalse(result["packaged_source_mutated"])

    def test_request_substitution_is_blocked(self) -> None:
        workspace, paths = self._init_approve()
        request = _read_json(paths["request"])
        request["request_id"] = "substituted-request"
        _write_json(paths["request"], request)

        result = self._execute(workspace, paths, retention="keep")

        self.assertEqual(result["result"], "blocked")
        self.assertEqual(result["exact_blocker"], "execution_binding_hash_binding_mismatch")
        self.assertFalse(result["mutation_was_applied"])

    def test_policy_substitution_is_blocked(self) -> None:
        workspace, paths = self._init_approve()
        policy = _read_json(paths["policy"])
        policy["policy_id"] = "substituted-policy"
        _write_json(paths["policy"], policy)

        result = self._execute(workspace, paths, retention="keep")

        self.assertEqual(result["result"], "blocked")
        self.assertEqual(result["exact_blocker"], "execution_binding_hash_binding_mismatch")
        self.assertFalse(result["mutation_was_applied"])

    def test_hard_linked_decision_output_is_blocked(self) -> None:
        _workspace, paths = self._init_paths()
        decision = gate.evaluate_source_mutation_request(
            policy_path=paths["policy"],
            request_path=paths["request"],
            source_root=paths["repo"],
            event_timestamp=FIXED_TIME,
        )
        output = self.temp_root / "hardlinked_decision.json"
        os.link(paths["repo"] / "README.md", output)
        source_before = gate.source_tree_hash(paths["repo"])

        with self.assertRaisesRegex(gate.PolicyGateError, "decision_output_hardlink_denied"):
            gate.write_decision_output(decision, output, paths["repo"])

        self.assertEqual(gate.source_tree_hash(paths["repo"]), source_before)

    def test_multi_operation_execution_blocks_before_write(self) -> None:
        workspace, paths = self._init_paths()
        other = paths["repo"] / "OTHER.md"
        other.write_text("# Other\n\nInitial.\n", encoding="utf-8")

        policy = _read_json(paths["policy"])
        policy["maximum_file_count"] = 2
        policy["allowed_paths"] = ["README.md", "OTHER.md"]
        policy["rules"][1]["paths"] = ["README.md", "OTHER.md"]  # type: ignore[index]
        _write_json(paths["policy"], policy)

        rollback = _read_json(paths["rollback"])
        rollback["files"]["OTHER.md"] = {  # type: ignore[index]
            "path": "OTHER.md",
            "before_sha256": gate.sha256_file(other),
            "original_content": other.read_text(encoding="utf-8"),
            "content_encoding": "utf-8",
        }
        _write_json(paths["rollback"], rollback)

        request = _read_json(paths["request"])
        request["operations"].append(  # type: ignore[union-attr]
            {
                "operation": "modify",
                "path": "OTHER.md",
                "before_sha256": gate.sha256_file(other),
            }
        )
        request["rollback_readiness"]["files"]["OTHER.md"] = {"before_sha256": gate.sha256_file(other)}  # type: ignore[index]
        request["rollback_readiness"]["artifact_sha256"] = gate.sha256_file(paths["rollback"])  # type: ignore[index]
        request["source_tree_hash"] = gate.source_tree_hash(paths["repo"])
        _write_json(paths["request"], request)

        decision_path = paths["artifacts"] / "allowed_decision.json"
        decision = self._evaluate_to(decision_path, paths["policy"], paths["request"], paths["repo"])
        self.assertEqual(decision["decision"], "allow")
        approval_path = paths["artifacts"] / "approval.json"
        approval = gate.demo_approve(workspace, decision_path=decision_path, approval_path=approval_path, decision="approved")
        self.assertEqual(approval["result"], "approval_recorded")
        paths["decision"] = decision_path
        paths["approval"] = approval_path
        before = {path.name: gate.sha256_file(path) for path in [paths["repo"] / "README.md", other]}

        result = self._execute(workspace, paths, retention="keep")

        self.assertEqual(result["result"], "blocked")
        self.assertEqual(result["exact_blocker"], "demo_runtime_multiple_operations_unsupported")
        self.assertEqual(result["approved_operation_count"], 2)
        self.assertEqual(result["executed_operation_count"], 0)
        self.assertEqual(before, {path.name: gate.sha256_file(path) for path in [paths["repo"] / "README.md", other]})

    def test_keep_path_target_tamper_after_apply_compensates(self) -> None:
        workspace, paths = self._init_approve()
        pre_hash = gate.sha256_file(paths["repo"] / "README.md")

        def tamper_target(context: dict[str, object]) -> None:
            Path(str(context["target"])).write_text("tampered after apply\n", encoding="utf-8")

        runtime.POST_APPLY_TEST_HOOK = tamper_target
        result = self._execute(workspace, paths, retention="keep")

        self.assertEqual(result["result"], "blocked")
        self.assertEqual(result["exact_blocker"], "final_target_hash_mismatch")
        self.assertTrue(result["mutation_was_applied"])
        self.assertTrue(result["compensation_attempted"])
        self.assertTrue(result["compensation_succeeded"])
        self.assertFalse(result["mutation_present_after_execution"])
        self.assertEqual(result["final_target_hash"], pre_hash)

    def test_rollback_artifact_missing_path_denies(self) -> None:
        _workspace, paths = self._init_paths()
        rollback = _read_json(paths["rollback"])
        del rollback["files"]["README.md"]["path"]  # type: ignore[index]
        _write_json(paths["rollback"], rollback)
        request = _read_json(paths["request"])
        request["rollback_readiness"]["artifact_sha256"] = gate.sha256_file(paths["rollback"])  # type: ignore[index]
        _write_json(paths["request"], request)

        decision = gate.evaluate_source_mutation_request(
            policy_path=paths["policy"],
            request_path=paths["request"],
            source_root=paths["repo"],
            event_timestamp=FIXED_TIME,
        )

        self.assertEqual(decision["decision"], "deny")
        self.assertEqual(decision["exact_blocker"], "rollback_artifact_file_path_missing")

    def test_no_reset_demo_repo_symlink_preserves_external_target(self) -> None:
        workspace, paths = self._init_paths()
        external = self.temp_root / "external"
        external.mkdir()
        sentinel = external / "README.md"
        sentinel.write_text("external sentinel\n", encoding="utf-8")
        before_hash = gate.sha256_file(sentinel)
        shutil.rmtree(paths["repo"])
        paths["repo"].symlink_to(external, target_is_directory=True)

        result = gate.demo_init(workspace, reset=False)

        self.assertEqual(result["result"], "blocked")
        self.assertEqual(result["exact_blocker"], "demo_workspace_reset_symlink_blocked")
        self.assertEqual(gate.sha256_file(sentinel), before_hash)
        self.assertEqual(sorted(child.name for child in external.iterdir()), ["README.md"])

    def test_actual_package_source_root_is_local_standalone_src(self) -> None:
        actual = runtime.actual_executable_source_root()

        self.assertEqual(actual, STANDALONE_SRC)
        self.assertTrue((actual / "clu_governance" / "source_mutation_policy_gate.py").is_file())
        self.assertNotIn("SOURCE", actual.parts)
        result = gate.demo_init(actual / "clu_governance" / "workspace-inside-source", reset=False)
        self.assertEqual(result["result"], "blocked")
        self.assertEqual(result["exact_blocker"], "demo_workspace_actual_source_overlap_denied")

    def test_one_command_demo_smoke_and_no_external_calls(self) -> None:
        completed = _run_demo_command(PACKAGE_ROOT)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)

        self.assertEqual(payload["result"], "passed")
        self.assertEqual(payload["packaged_source_root"], str(STANDALONE_SRC))
        self.assertEqual(payload["approval_input_mode"], "scripted_demo")
        self.assertEqual(payload["approval"]["approval_input_mode"], "scripted_demo")
        self.assertFalse(payload["approval_identity_authenticated"])
        self.assertFalse(payload["human_presence_verified"])
        self.assertFalse(payload["approval_rationale_recorded"])
        self.assertTrue(payload["checks"]["denied_request_blocked"])
        self.assertTrue(payload["checks"]["eligible_request_allowed"])
        self.assertTrue(payload["checks"]["explicit_approval_recorded"])
        self.assertTrue(payload["checks"]["rollback_verified"])
        self.assertTrue(payload["checks"]["standalone_source_unchanged"])
        self.assertEqual(payload["provider_calls"], 0)
        self.assertEqual(payload["advisor_calls"], 0)
        self.assertEqual(payload["mem0_runs"], 0)
        self.assertEqual(payload["benchmark_runs"], 0)
        self.assertEqual(payload["network_calls"], 0)

    def test_manual_demo_approve_reports_cli_argument_mode(self) -> None:
        workspace, paths = self._init_approve()
        approval = _read_json(paths["approval"])

        self.assertEqual(approval["approval_input_mode"], "cli_argument")
        self.assertFalse(approval["actor_identity_authenticated"])
        self.assertFalse(approval["approval_identity_authenticated"])
        self.assertFalse(approval["human_presence_verified"])
        self.assertFalse(approval["approval_rationale_recorded"])
        self.assertTrue(approval["operator_input_required"])
        self.assertEqual(workspace.name, "workspace")

    def test_child_process_smoke_disables_bytecode(self) -> None:
        copied_package = _copy_package_for_tree_test(self.temp_root)
        before = _tree_inventory(copied_package)
        completed = _run_demo_command(copied_package)
        after = _tree_inventory(copied_package)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["result"], "passed")
        _assert_tree_unchanged(before, after)
        self.assertEqual(_prohibited_cache_paths(copied_package), [])

    @unittest.skipIf(
        "tree-preservation-child" in PACKAGE_ROOT.parts,
        "avoid recursive full-tree preservation probe in child copy",
    )
    def test_exact_documented_demo_command_preserves_complete_package_tree(self) -> None:
        copied_package = _copy_package_for_tree_test(self.temp_root)
        before = _tree_inventory(copied_package)
        _verify_internal_checksums(copied_package)

        completed = _run_demo_command(copied_package)
        after = _tree_inventory(copied_package)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["result"], "passed")
        _assert_tree_unchanged(before, after)
        self.assertEqual(before["tree_hash"], after["tree_hash"])
        self.assertEqual(_prohibited_cache_paths(copied_package), [])
        _verify_internal_checksums(copied_package)

    @unittest.skipIf(
        "tree-preservation-child" in PACKAGE_ROOT.parts,
        "avoid recursive full-tree preservation probe in child copy",
    )
    def test_exact_documented_test_command_preserves_complete_package_tree(self) -> None:
        copied_package = _copy_package_for_tree_test(self.temp_root)
        before = _tree_inventory(copied_package)
        _verify_internal_checksums(copied_package)

        completed = _run_test_command(copied_package)
        after = _tree_inventory(copied_package)

        self.assertEqual(completed.returncode, 0, completed.stdout)
        _assert_tree_unchanged(before, after)
        self.assertEqual(before["tree_hash"], after["tree_hash"])
        self.assertEqual(_prohibited_cache_paths(copied_package), [])
        _verify_internal_checksums(copied_package)

    def test_runtime_imports_do_not_resolve_to_parent_monolith(self) -> None:
        gate_path = Path(gate.__file__).resolve()
        runtime_path = Path(runtime.__file__).resolve()

        self.assertTrue(gate_path.is_relative_to(STANDALONE_SRC))
        self.assertTrue(runtime_path.is_relative_to(STANDALONE_SRC))
        self.assertNotIn("SOURCE", gate_path.parts)
        self.assertNotIn("SOURCE", runtime_path.parts)


if __name__ == "__main__":
    unittest.main()
