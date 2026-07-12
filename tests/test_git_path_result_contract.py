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
from unittest import mock

from clu_governance import bundle_verifier
from clu_governance import git_diff_adapter as adapter
from clu_governance import source_mutation_demo_runtime as runtime
from clu_governance.result_contract import ResultContractError, validate_adapter_result


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        [shutil.which("git") or "git", *args], cwd=repo,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, check=False,
    )
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    return result


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def tree_state(repo: Path) -> dict[str, object]:
    index = repo / ".git/index"
    return {
        "head": git(repo, "rev-parse", "HEAD").stdout.strip(),
        "status": git(repo, "status", "--porcelain=v2", "-z", "--untracked-files=all").stdout,
        "index": hashlib.sha256(index.read_bytes()).hexdigest(),
        "entries": sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*")),
    }


MACOS_ADAPTER_INTEGRATION_REASON = (
    "requires successful macOS git-adapt execution; unsupported-platform "
    "fail-closed behavior is covered separately"
)


def macos_adapter_integration(*portable_test_names: str):
    """Apply per-test macOS skips while retaining result-contract coverage."""

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


@macos_adapter_integration("test_result_contract_rejects_contradictory_final_state")
class GitPathResultContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="clu-git-path-result.")).resolve()
        self.policy = write_json(self.root / "policy.json", runtime.build_demo_policy())

    def tearDown(self) -> None:
        bundle_verifier.BUNDLE_PATH_CHAIN_TEST_HOOK = None
        adapter.POST_PUBLICATION_PATH_TEST_HOOK = None
        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
        adapter.OUTPUT_PARENT_TEST_HOOK = None
        tempfile.tempdir = None
        shutil.rmtree(self.root, ignore_errors=True)
        for sibling in self.root.parent.glob(self.root.name + ".moved*"):
            shutil.rmtree(sibling, ignore_errors=True)

    def make_repo(self, name: str) -> Path:
        repo = self.root / name
        repo.mkdir(parents=True)
        git(repo, "init", "-q")
        git(repo, "config", "user.name", "CLU Synthetic Test")
        git(repo, "config", "user.email", "synthetic@example.invalid")
        (repo / "README.md").write_text("# Demo\n\nBaseline.\n", encoding="utf-8")
        git(repo, "add", "README.md")
        git(repo, "commit", "-q", "-m", "baseline")
        (repo / "README.md").write_text("# Demo\n\nProposed local edit.\n", encoding="utf-8")
        return repo

    def adapt(self, name: str = "bundle") -> tuple[Path, Path, dict[str, object]]:
        repo = self.make_repo("repo-" + name.replace("/", "-"))
        output = self.root / name
        output.parent.mkdir(parents=True, exist_ok=True)
        result = adapter.adapt_git_diff(
            repo_path=repo,
            policy_path=self.policy,
            declared_actor_id="demo_operator",
            requested_scope="docs_only",
            output_dir=output,
            event_time="2026-07-11T00:00:00Z",
        )
        self.assertEqual(result["result"], "adapted", result)
        return repo, output, result

    def test_verifier_rejects_caller_visible_ancestor_swap(self) -> None:
        _repo, bundle, _ = self.adapt("chain/parent/bundle")
        ancestor = self.root / "chain"
        moved = self.root / "chain.moved"
        fired = False

        def swap(phase: str, _context: object) -> None:
            nonlocal fired
            if phase == "before_final_rebind" and not fired:
                fired = True
                os.rename(ancestor, moved)
                (ancestor / "parent" / "bundle").mkdir(parents=True)
                (ancestor / "parent" / "bundle" / "MALICIOUS.txt").write_text("not verified")

        bundle_verifier.BUNDLE_PATH_CHAIN_TEST_HOOK = swap
        result = bundle_verifier.verify_bundle(bundle)
        self.assertFalse(result["verified"], result)
        self.assertIn(result["exact_blocker"], {
            "bundle_ancestor_chain_changed", "bundle_parent_identity_changed",
            "bundle_root_identity_changed", "caller_visible_bundle_path_replaced",
        })
        self.assertEqual((ancestor / "parent" / "bundle" / "MALICIOUS.txt").read_text(), "not verified")

    def test_verifier_rejects_root_replacement(self) -> None:
        _repo, bundle, _ = self.adapt("root-replace")
        moved = self.root / "root-replace.moved"
        fired = False

        def swap(phase: str, _context: object) -> None:
            nonlocal fired
            if phase == "before_final_rebind" and not fired:
                fired = True
                os.rename(bundle, moved)
                bundle.mkdir()
                (bundle / "MALICIOUS.txt").write_text("replacement")

        bundle_verifier.BUNDLE_PATH_CHAIN_TEST_HOOK = swap
        result = bundle_verifier.verify_bundle(bundle)
        self.assertFalse(result["verified"], result)
        self.assertFalse(result["bundle_exact_set_verified_at_return"])
        self.assertFalse(result["caller_visible_bundle_path_bound_at_return"])

    def test_verifier_rechecks_content_after_confirmation_rebind(self) -> None:
        _repo, bundle, _ = self.adapt("confirmation-content")
        fired = False

        def mutate(phase: str, _context: object) -> None:
            nonlocal fired
            if phase == "during_confirmation_rebind" and not fired:
                fired = True
                with (bundle / "change_preview.diff").open("ab") as handle:
                    handle.write(b"late")

        bundle_verifier.BUNDLE_PATH_CHAIN_TEST_HOOK = mutate
        result = bundle_verifier.verify_bundle(bundle)
        self.assertFalse(result["verified"], result)
        self.assertFalse(result["bundle_exact_set_verified_at_return"])

    def test_publication_parent_rename_restore_is_detected(self) -> None:
        repo = self.make_repo("repo-parent-restore")
        parent = self.root / "restore-parent"
        parent.mkdir()
        output = parent / "bundle"
        moved = self.root / "restore-parent.moved"
        fired = False

        def restore(phase: str, _owned: object) -> None:
            nonlocal fired
            if phase == "before_publication_rename" and not fired:
                fired = True
                os.rename(parent, moved)
                os.rename(moved, parent)

        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = restore
        result = adapter.adapt_git_diff(
            repo_path=repo, policy_path=self.policy, declared_actor_id="demo_operator",
            requested_scope="docs_only", output_dir=output,
            event_time="2026-07-11T00:00:00Z",
        )
        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
        self.assertEqual(result["result"], "blocked", result)
        self.assertEqual(result["exact_blocker"], "output_parent_identity_changed")

    def test_internal_temp_path_redirect_blocks_before_repository_write(self) -> None:
        repo = self.make_repo("repo-temp-redirect")
        output_parent = self.root / "temp-output-parent"
        output_parent.mkdir()
        output = output_parent / "bundle"
        moved = self.root / "temp-output-parent.moved"
        before = tree_state(repo)

        def redirect(phase: str, _lease: object) -> None:
            if phase != "after_parent_acquired":
                return
            os.rename(output_parent, moved)
            output_parent.mkdir()
            internal = next(
                path.name for path in moved.iterdir()
                if path.name.startswith(".clu-git-adapt-internal-")
            )
            os.symlink(repo, output_parent / internal)

        adapter.OUTPUT_PARENT_TEST_HOOK = redirect
        result = adapter.adapt_git_diff(
            repo_path=repo, policy_path=self.policy, declared_actor_id="demo_operator",
            requested_scope="docs_only", output_dir=output,
            event_time="2026-07-11T00:00:00Z",
        )
        adapter.OUTPUT_PARENT_TEST_HOOK = None
        self.assertEqual(result["result"], "blocked", result)
        self.assertEqual(tree_state(repo), before)
        self.assertFalse(any(path.name.startswith("clu-git-") for path in repo.iterdir()))

    def test_adapter_blocks_swap_after_first_verifier(self) -> None:
        repo = self.make_repo("repo-adapter-swap")
        output = self.root / "publish" / "bundle"
        output.parent.mkdir()
        ancestor = output.parent
        moved = self.root / "publish.moved"
        fired = False

        def swap(phase: str, _context: object) -> None:
            nonlocal fired
            if phase == "after_first_verifier_before_final_result" and not fired:
                fired = True
                os.rename(ancestor, moved)
                ancestor.mkdir()
                output.mkdir()
                (output / "MALICIOUS.txt").write_text("replacement")

        adapter.POST_PUBLICATION_PATH_TEST_HOOK = swap
        result = adapter.adapt_git_diff(
            repo_path=repo, policy_path=self.policy, declared_actor_id="demo_operator",
            requested_scope="docs_only", output_dir=output,
            event_time="2026-07-11T00:00:00Z",
        )
        self.assertEqual(result["result"], "blocked", result)
        self.assertFalse(result["post_publication_bundle_verified"])
        self.assertTrue(result["requested_final_output_present_at_return"])
        self.assertFalse(result["requested_final_output_is_adapter_owned_at_return"])
        self.assertEqual((output / "MALICIOUS.txt").read_text(), "replacement")

    def test_adapter_final_verifier_rejects_late_unknown_entry(self) -> None:
        repo = self.make_repo("repo-late-unknown")
        output = self.root / "late-unknown-bundle"

        def inject(phase: str, _context: object) -> None:
            if phase == "after_first_verifier_before_final_result":
                (output / "LATE_UNKNOWN.txt").write_text("late")

        adapter.POST_PUBLICATION_PATH_TEST_HOOK = inject
        result = adapter.adapt_git_diff(
            repo_path=repo, policy_path=self.policy, declared_actor_id="demo_operator",
            requested_scope="docs_only", output_dir=output,
            event_time="2026-07-11T00:00:00Z",
        )
        self.assertEqual(result["result"], "blocked", result)
        self.assertFalse(result["output_bundle_valid_at_return"])
        self.assertIn("LATE_UNKNOWN.txt", result["output_bundle_unknown_entries_at_return"])
        self.assertTrue((output / "LATE_UNKNOWN.txt").is_file())

    def test_adapter_reports_caller_visible_symlink_replacement_present(self) -> None:
        repo = self.make_repo("repo-symlink-output")
        output = self.root / "symlink-output"
        moved = self.root / "symlink-output.moved"
        target = self.root / "symlink-malicious"
        target.mkdir()

        def replace(phase: str, _context: object) -> None:
            if phase == "after_first_verifier_before_final_result":
                os.rename(output, moved)
                os.symlink(target, output)

        adapter.POST_PUBLICATION_PATH_TEST_HOOK = replace
        result = adapter.adapt_git_diff(
            repo_path=repo, policy_path=self.policy, declared_actor_id="demo_operator",
            requested_scope="docs_only", output_dir=output,
            event_time="2026-07-11T00:00:00Z",
        )
        self.assertEqual(result["result"], "blocked", result)
        self.assertTrue(result["requested_final_output_presence_known_at_return"])
        self.assertTrue(result["requested_final_output_present_at_return"])
        self.assertFalse(result["requested_final_output_is_adapter_owned_at_return"])
        self.assertTrue(output.is_symlink())

    def test_ambient_temp_environment_never_places_adapter_scratch_in_repository(self) -> None:
        for index, target_name in enumerate((
            "repo", ".git", "selected-parent", "output-parent",
            "candidate-source", "symlink", "missing", "conflicting",
        )):
            with self.subTest(target_name=target_name):
                repo = self.make_repo(f"temp-repo-{index}")
                symlink_target = self.root / f"temp-env-link-{index}"
                if target_name == "symlink":
                    os.symlink(repo, symlink_target)
                target = {
                    "repo": repo,
                    ".git": repo / ".git",
                    "selected-parent": repo,
                    "output-parent": self.root,
                    "candidate-source": Path(adapter.__file__).resolve().parents[1],
                    "symlink": symlink_target,
                    "missing": repo / "does-not-exist",
                    "conflicting": repo,
                }[target_name]
                before = tree_state(repo)
                root_before = os.stat(repo)
                tempfile.tempdir = str(repo)
                environment = (
                    {"TMPDIR": str(repo), "TMP": str(repo / ".git"),
                     "TEMP": str(Path(adapter.__file__).resolve().parents[1])}
                    if target_name == "conflicting"
                    else {"TMPDIR": str(target), "TMP": str(target), "TEMP": str(target)}
                )
                with mock.patch.dict(
                    os.environ,
                    environment,
                    clear=False,
                ):
                    result = adapter.adapt_git_diff(
                        repo_path=repo, policy_path=self.policy,
                        declared_actor_id="demo_operator", requested_scope="docs_only",
                        output_dir=self.root / f"temp-bundle-{index}",
                        event_time="2026-07-11T00:00:00Z",
                    )
                tempfile.tempdir = None
                self.assertEqual(result["result"], "adapted", result)
                self.assertFalse(result["internal_temp_root_environment_derived"])
                self.assertEqual(result["repository_temp_entries_created"], [])
                self.assertEqual(tree_state(repo), before)
                root_after = os.stat(repo)
                self.assertEqual(
                    (root_before.st_dev, root_before.st_ino, root_before.st_mtime_ns, root_before.st_ctime_ns),
                    (root_after.st_dev, root_after.st_ino, root_after.st_mtime_ns, root_after.st_ctime_ns),
                )

    def test_result_contract_rejects_contradictory_final_state(self) -> None:
        contradictory = {
            "result": "adapted",
            "publication_operation_completed": True,
            "published_bundle_exact_set_verified": True,
            "published_bundle_checksum_coverage_exact": True,
            "post_publication_bundle_verified": True,
            "caller_visible_bundle_path_bound_at_return": True,
            "requested_final_output_present_at_return": True,
            "requested_final_output_is_adapter_owned_at_return": True,
            "output_bundle_valid_at_return": True,
            "output_bundle_unknown_entries_at_return": ["late.txt"],
        }
        with self.assertRaises(ResultContractError):
            validate_adapter_result(contradictory)
        adapted_without_verifier = dict(contradictory)
        adapted_without_verifier["output_bundle_unknown_entries_at_return"] = []
        adapted_without_verifier["post_publication_bundle_verified"] = False
        with self.assertRaises(ResultContractError):
            validate_adapter_result(adapted_without_verifier)
        blocked_with_success = dict(contradictory)
        blocked_with_success["result"] = "blocked"
        blocked_with_success["eligible_for_separate_approval"] = False
        blocked_with_success["output_bundle_unknown_entries_at_return"] = []
        with self.assertRaises(ResultContractError):
            validate_adapter_result(blocked_with_success)
        ownership_without_binding = dict(contradictory)
        ownership_without_binding["output_bundle_unknown_entries_at_return"] = []
        ownership_without_binding["caller_visible_bundle_path_bound_at_return"] = False
        ownership_without_binding["requested_final_output_ownership_verified_at_return"] = True
        with self.assertRaises(ResultContractError):
            validate_adapter_result(ownership_without_binding)


if __name__ == "__main__":
    unittest.main()
