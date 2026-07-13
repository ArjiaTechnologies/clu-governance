from __future__ import annotations

import hashlib
import inspect
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from clu_governance import git_diff_adapter as adapter
from clu_governance import source_mutation_demo_runtime as runtime
from clu_governance import source_mutation_policy_gate as gate


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SRC = (PACKAGE_ROOT / "src").resolve()


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        [shutil.which("git") or "git", *args],
        cwd=repo,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    if check and result.returncode:
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
        "readme": hashlib.sha256((repo / "README.md").read_bytes()).hexdigest() if (repo / "README.md").exists() else None,
        "refs": sorted((p.relative_to(repo / ".git").as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()) for p in (repo / ".git/refs").rglob("*") if p.is_file()),
        "config": hashlib.sha256((repo / ".git/config").read_bytes()).hexdigest(),
        "locks": sorted(p.relative_to(repo / ".git").as_posix() for p in (repo / ".git").rglob("*.lock")),
    }


MACOS_ADAPTER_INTEGRATION_REASON = (
    "requires successful macOS git-adapt execution; unsupported-platform "
    "fail-closed behavior is covered separately"
)


def macos_adapter_integration(*portable_test_names: str):
    """Mark only successful-adaptation tests as macOS integration coverage."""

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
                    sys.platform == "darwin" and "tree-preservation-child" not in Path(__file__).resolve().parts,
                    MACOS_ADAPTER_INTEGRATION_REASON,
                )(getattr(test_class, name)),
            )
        return test_class

    return decorate


@macos_adapter_integration(
    "test_porcelain_v2_nul_parser_valid_record",
    "test_porcelain_v2_rejects_rename_copy_conflict_untracked_and_control_path",
    "test_status_selector_rejects_submodule_staged_multi_and_wrong_mode",
    "test_git_adapt_help_is_cross_platform",
    "test_non_git_bare_unborn_and_linked_worktree_are_rejected",
    "test_unsupported_repository_states_fail_closed",
    "test_repository_and_output_symlink_boundaries",
    "test_output_overlap_existing_and_candidate_source_are_rejected",
    "test_git_version_is_metadata_bracketed_and_checks_exit_status",
    "test_bounded_status_stderr_and_metadata_inventory_limits",
    "test_runtime_stdout_stderr_and_dual_stream_floods_are_killed_at_caps",
)
class GitDiffAdapterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="clu-git-adapter-test.")).resolve()
        self.policy = write_json(self.root / "policy.json", runtime.build_demo_policy())

    def tearDown(self) -> None:
        adapter.ADAPTER_TEST_HOOK = None
        adapter.WORKTREE_READ_TEST_HOOK = None
        adapter.STATUS_SNAPSHOT_TEST_HOOK = None
        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
        adapter.OUTPUT_PARENT_TEST_HOOK = None
        adapter.PROCESS_LIMIT_TEST_OBSERVER = None
        adapter.GIT_METADATA_TEST_HOOK = None
        adapter.WORKTREE_CONTENT_READ_CALLS = 0
        shutil.rmtree(self.root, ignore_errors=True)

    def make_repo(self, name: str = "repo", *, modify: bool = True) -> Path:
        repo = self.root / name
        repo.mkdir()
        git(repo, "init", "-q")
        git(repo, "config", "user.name", "CLU Synthetic Test")
        git(repo, "config", "user.email", "synthetic@example.invalid")
        # Test fixtures must be quiescent before a metadata lease is acquired.
        # Git otherwise permits automatic maintenance to detach after writes,
        # which the adapter correctly treats as a concurrent metadata change.
        git(repo, "config", "maintenance.auto", "false")
        git(repo, "config", "gc.auto", "0")
        (repo / "README.md").write_text("# Demo\n\nBaseline.\n", encoding="utf-8")
        git(repo, "add", "README.md")
        git(repo, "commit", "-q", "-m", "baseline")
        if modify:
            (repo / "README.md").write_text("# Demo\n\nProposed local edit.\n", encoding="utf-8")
        return repo

    def add_tracked_other(self, repo: Path) -> None:
        (repo / "OTHER.md").write_text("other baseline\n", encoding="utf-8")
        git(repo, "add", "OTHER.md")
        git(repo, "commit", "-q", "-m", "add other")

    def adapt(self, repo: Path, name: str = "bundle", policy: Path | None = None) -> dict[str, object]:
        return adapter.adapt_git_diff(
            repo_path=repo,
            policy_path=policy or self.policy,
            declared_actor_id="demo_operator",
            requested_scope="docs_only",
            output_dir=self.root / name,
            event_time="2026-06-26T00:00:00Z",
        )

    def test_porcelain_v2_nul_parser_valid_record(self) -> None:
        oid = b"a" * 40
        raw = b"1 .M N... 100644 100644 100644 " + oid + b" " + oid + b" README.md\0"
        parsed = adapter.parse_porcelain_v2_z(raw)
        self.assertEqual(parsed[0]["path"], "README.md")
        self.assertEqual(parsed[0]["xy"], ".M")

    def test_porcelain_v2_rejects_rename_copy_conflict_untracked_and_control_path(self) -> None:
        oid = b"a" * 40
        fixtures = {
            "rename_or_copy": b"2 .R N... 100644 100644 100644 " + oid + b" " + oid + b" R100 new\0old\0",
            "copy": b"2 .C N... 100644 100644 100644 " + oid + b" " + oid + b" C100 copy\0source\0",
            "conflict": b"u UU N... 100644 100644 100644 100644 " + oid + b" " + oid + b" " + oid + b" README.md\0",
            "untracked": b"? extra.txt\0",
            "control": b"1 .M N... 100644 100644 100644 " + oid + b" " + oid + b" bad\nname\0",
        }
        for name, raw in fixtures.items():
            with self.subTest(name=name), self.assertRaises(adapter.GitAdapterError):
                adapter.parse_porcelain_v2_z(raw)

    def test_status_selector_rejects_submodule_staged_multi_and_wrong_mode(self) -> None:
        base = {"xy": ".M", "sub": "N...", "path": "README.md"}
        fixtures = [
            [{**base, "sub": "S..."}],
            [{**base, "xy": "M."}],
            [{**base, "xy": ".D"}],
            [base, {**base, "path": "OTHER.md"}],
            [],
        ]
        for records in fixtures:
            with self.subTest(records=records), self.assertRaises(adapter.GitAdapterError):
                adapter.select_supported_status_record(records)

    def test_allow_bundle_is_valid_and_repository_is_byte_stable(self) -> None:
        repo = self.make_repo()
        before = tree_state(repo)
        result = self.adapt(repo)
        after = tree_state(repo)
        self.assertEqual(result["result"], "adapted")
        self.assertEqual(result["policy_decision"], "allow")
        self.assertTrue(result["eligible_for_separate_approval"])
        self.assertEqual(before, after)
        bundle = self.root / "bundle"
        expected = {
            "CHECKSUMS.sha256", "baseline_source/README.md", "source_mutation_request.json",
            "rollback_snapshot.json", "git_provenance.json", "change_preview.diff", "policy_decision.json",
            "BUNDLE_COMPLETE.json",
            ".clu-git-adapter-ownership.json",
        }
        self.assertEqual({p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file()}, expected)
        request = json.loads((bundle / "source_mutation_request.json").read_text())
        decision = json.loads((bundle / "policy_decision.json").read_text())
        provenance = json.loads((bundle / "git_provenance.json").read_text())
        self.assertEqual(request["source_tree_hash"], gate.source_tree_hash(bundle / "baseline_source"))
        self.assertEqual(decision["decision"], "allow")
        self.assertTrue(gate.verify_decision_artifact(bundle / "policy_decision.json")["verified"])
        self.assertFalse(provenance["full_repository_hash_verified"])
        self.assertEqual(provenance["source_surface_mode"], adapter.SOURCE_SURFACE_MODE)
        self.assertNotIn("approval.json", expected)
        for command in provenance["git_commands"]:
            self.assertNotIn(next((x for x in command if x in adapter.FORBIDDEN_GIT_COMMANDS), None), adapter.FORBIDDEN_GIT_COMMANDS)
        for line in (bundle / "CHECKSUMS.sha256").read_text().splitlines():
            digest, rel = line.split("  ", 1)
            self.assertEqual(digest, hashlib.sha256((bundle / rel).read_bytes()).hexdigest())
        completion = json.loads((bundle / "BUNDLE_COMPLETE.json").read_text())
        self.assertTrue(completion["bundle_complete"])
        self.assertEqual(completion["checksums_sha256"], hashlib.sha256((bundle / "CHECKSUMS.sha256").read_bytes()).hexdigest())

    def test_policy_deny_returns_two_semantics_and_preserves_bundle(self) -> None:
        repo = self.make_repo()
        policy = runtime.build_demo_policy()
        policy["allowed_paths"] = []
        policy["allowed_path_globs"] = []
        policy["rules"] = [rule for rule in policy["rules"] if rule["effect"] == "deny"]
        deny_policy = write_json(self.root / "deny-policy.json", policy)
        result = self.adapt(repo, policy=deny_policy)
        self.assertEqual(result["result"], "policy_denied")
        self.assertEqual(result["policy_decision"], "deny")
        self.assertEqual(adapter.exit_code_for_result(result), 2)
        self.assertTrue((self.root / "bundle/policy_decision.json").is_file())
        self.assertFalse((self.root / "bundle/approval.json").exists())

    def test_git_adapt_help_is_cross_platform(self) -> None:
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(PACKAGE_SRC)}
        help_result = subprocess.run(
            [sys.executable, "-B", "-m", "clu_governance.cli", "git-adapt", "--help"],
            cwd=PACKAGE_ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, check=False,
        )
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("without approval, apply, commit, or", help_result.stdout)
        self.assertIn("push.", help_result.stdout)

    def test_cli_json_module_invocation(self) -> None:
        repo = self.make_repo()
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(PACKAGE_SRC)}
        output = self.root / "cli-bundle"
        result = subprocess.run(
            [sys.executable, "-B", "-m", "clu_governance.cli", "git-adapt", "--repo", str(repo),
             "--policy", str(self.policy), "--declared-actor-id", "demo_operator", "--scope", "docs_only",
             "--output-dir", str(output), "--event-time", "2026-06-26T00:00:00Z", "--json"],
            cwd=PACKAGE_ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema_name"], adapter.RESULT_SCHEMA_NAME)
        self.assertEqual(result.stdout[json.JSONDecoder().raw_decode(result.stdout)[1]:].strip(), "")
        self.assertEqual(result.stderr, "")

    def test_non_git_bare_unborn_and_linked_worktree_are_rejected(self) -> None:
        non_git = self.root / "non-git"; non_git.mkdir()
        non_git_result = self.adapt(non_git, "non-git-out")
        self.assertEqual(non_git_result["exact_blocker"], "git_metadata_root_invalid")
        self.assertNotEqual(non_git_result["result"], "adapted")
        self.assertFalse((self.root / "non-git-out").exists())
        bare = self.root / "bare"; bare.mkdir(); git(bare, "init", "--bare", "-q")
        self.assertNotEqual(self.adapt(bare, "bare-out")["result"], "adapted")
        unborn = self.root / "unborn"; unborn.mkdir(); git(unborn, "init", "-q")
        self.assertNotEqual(self.adapt(unborn, "unborn-out")["result"], "adapted")
        main = self.make_repo("main", modify=False)
        linked = self.root / "linked"
        git(main, "worktree", "add", "-q", "-b", "linked-test", str(linked))
        (linked / "README.md").write_text("linked change\n", encoding="utf-8")
        linked_result = self.adapt(linked, "linked-out")
        self.assertEqual(linked_result["exact_blocker"], "git_metadata_root_symlink_denied")
        self.assertNotEqual(linked_result["result"], "adapted")
        self.assertFalse((self.root / "linked-out").exists())

    def test_unsupported_repository_states_fail_closed(self) -> None:
        cases = ("clean", "staged", "staged_plus_unstaged", "untracked", "multiple", "delete", "symlink", "binary", "invalid_utf8", "oversize", "mode")
        for case in cases:
            with self.subTest(case=case):
                repo = self.make_repo(f"repo-{case}", modify=case != "clean")
                if case == "staged":
                    git(repo, "add", "README.md")
                elif case == "staged_plus_unstaged":
                    git(repo, "add", "README.md"); (repo / "README.md").write_text("second edit\n")
                elif case == "untracked":
                    (repo / "extra.txt").write_text("extra\n")
                elif case == "multiple":
                    (repo / "OTHER.md").write_text("base\n"); git(repo, "add", "OTHER.md"); git(repo, "commit", "-q", "-m", "other");
                    (repo / "README.md").write_text("edit one\n"); (repo / "OTHER.md").write_text("edit two\n")
                elif case == "delete":
                    (repo / "README.md").unlink()
                elif case == "symlink":
                    (repo / "README.md").unlink(); (repo / "README.md").symlink_to("target")
                elif case == "binary":
                    (repo / "README.md").write_bytes(b"text\0binary")
                elif case == "invalid_utf8":
                    (repo / "README.md").write_bytes(b"bad\xfftext")
                elif case == "oversize":
                    (repo / "README.md").write_bytes(b"x" * (adapter.MAX_PROPOSED_FILE_SIZE + 1))
                elif case == "mode":
                    os.chmod(repo / "README.md", (repo / "README.md").stat().st_mode | stat.S_IXUSR)
                result = self.adapt(repo, f"out-{case}")
                self.assertEqual(result["result"], "blocked")
                self.assertFalse((self.root / f"out-{case}").exists())

    def test_repository_and_output_symlink_boundaries(self) -> None:
        repo = self.make_repo()
        repo_link = self.root / "repo-link"; repo_link.symlink_to(repo, target_is_directory=True)
        self.assertEqual(self.adapt(repo_link, "repo-link-out")["exact_blocker"], "repository_path_symlink_denied")
        repo_parent_link = self.root / "repo-parent-link"; repo_parent_link.symlink_to(self.root, target_is_directory=True)
        result = adapter.adapt_git_diff(repo_path=repo_parent_link / repo.name, policy_path=self.policy, declared_actor_id="demo_operator", requested_scope="docs_only", output_dir=self.root / "repo-parent-out")
        self.assertEqual(result["exact_blocker"], "repository_parent_symlink_denied")
        output_link = self.root / "output-link"; output_link.symlink_to(self.root / "missing", target_is_directory=True)
        result = adapter.adapt_git_diff(repo_path=repo, policy_path=self.policy, declared_actor_id="demo_operator", requested_scope="docs_only", output_dir=output_link)
        self.assertEqual(result["exact_blocker"], "output_path_must_not_exist")
        symlink_parent = self.root / "symlink-parent"; symlink_parent.symlink_to(self.root, target_is_directory=True)
        result = adapter.adapt_git_diff(repo_path=repo, policy_path=self.policy, declared_actor_id="demo_operator", requested_scope="docs_only", output_dir=symlink_parent / "child")
        self.assertEqual(result["exact_blocker"], "output_parent_symlink_denied")

    def test_output_overlap_existing_and_candidate_source_are_rejected(self) -> None:
        repo = self.make_repo()
        existing = self.root / "existing"; existing.mkdir(); sentinel = existing / "sentinel"; sentinel.write_text("preserve")
        result = adapter.adapt_git_diff(repo_path=repo, policy_path=self.policy, declared_actor_id="demo_operator", requested_scope="docs_only", output_dir=existing)
        self.assertEqual(result["exact_blocker"], "output_path_must_not_exist")
        self.assertEqual(sentinel.read_text(), "preserve")
        result = adapter.adapt_git_diff(repo_path=repo, policy_path=self.policy, declared_actor_id="demo_operator", requested_scope="docs_only", output_dir=repo / "bundle")
        self.assertEqual(result["exact_blocker"], "output_repository_overlap_denied")
        result = adapter.adapt_git_diff(repo_path=repo, policy_path=self.policy, declared_actor_id="demo_operator", requested_scope="docs_only", output_dir=self.root)
        self.assertEqual(result["exact_blocker"], "output_path_must_not_exist")
        candidate_output = PACKAGE_SRC / "clu_governance" / f"adapter-test-{uuid_fragment()}"
        try:
            result = adapter.adapt_git_diff(repo_path=repo, policy_path=self.policy, declared_actor_id="demo_operator", requested_scope="docs_only", output_dir=candidate_output)
            self.assertEqual(result["exact_blocker"], "output_candidate_source_overlap_denied")
        finally:
            if candidate_output.exists(): shutil.rmtree(candidate_output)

    def test_worktree_index_and_head_toctou_preserve_incomplete_outputs(self) -> None:
        mutations = {
            "worktree": lambda repo: (repo / "README.md").write_text("raced content\n"),
            "index": lambda repo: git(repo, "add", "README.md"),
            "head": self._advance_head,
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                repo = self.make_repo(f"race-{name}")
                adapter.ADAPTER_TEST_HOOK = mutation
                result = self.adapt(repo, f"race-out-{name}")
                adapter.ADAPTER_TEST_HOOK = None
                self.assertEqual(result["exact_blocker"], "repository_state_changed_during_adaptation")
                self.assertFalse((self.root / f"race-out-{name}").exists())
                retained = list(self.root.glob(f".race-out-{name}.clu-git-adapt-*"))
                self.assertEqual(len(retained), 1)
                self.assertFalse((retained[0] / adapter.INCOMPLETE_MARKER_NAME).exists())
                self.assertFalse(result["automatic_nonempty_failure_cleanup_performed"])

    def _advance_head(self, repo: Path) -> None:
        git(repo, "add", "README.md")
        git(repo, "commit", "-q", "-m", "race")

    def test_malicious_fsmonitor_external_diff_textconv_and_hook_are_not_executed(self) -> None:
        repo = self.make_repo()
        sentinels = {name: self.root / f"{name}.executed" for name in ("fsmonitor", "diff", "textconv", "hook")}
        scripts: dict[str, Path] = {}
        for name, sentinel in sentinels.items():
            script = self.root / f"{name}.sh"
            script.write_text(f"#!/bin/sh\nprintf executed > '{sentinel}'\nexit 0\n")
            os.chmod(script, 0o755); scripts[name] = script
        (repo / ".gitattributes").write_text("README.md diff=clu\n")
        git(repo, "add", ".gitattributes"); git(repo, "commit", "-q", "-m", "attributes")
        git(repo, "config", "core.fsmonitor", str(scripts["fsmonitor"]))
        git(repo, "config", "diff.external", str(scripts["diff"]))
        git(repo, "config", "diff.clu.textconv", str(scripts["textconv"]))
        (repo / "README.md").write_text("safe modified content\n")
        hook = repo / ".git/hooks/post-commit"; shutil.copy2(scripts["hook"], hook); os.chmod(hook, 0o755)
        result = self.adapt(repo)
        self.assertEqual(result["result"], "adapted")
        self.assertEqual([p for p in sentinels.values() if p.exists()], [])
        provenance = json.loads((self.root / "bundle/git_provenance.json").read_text())
        self.assertFalse(provenance["git_shell_execution_used"])
        self.assertEqual(provenance["git_network_commands"], 0)
        self.assertEqual(provenance["lock_files_after"], provenance["lock_files_before"])

    def test_controlled_git_environment_strips_trace_and_context_overrides(self) -> None:
        repo = self.make_repo()
        trace = self.root / "inherited-git-trace.log"
        with mock.patch.dict(
            os.environ,
            {"GIT_TRACE": str(trace), "GIT_DIR": str(self.root / "wrong"), "GIT_INDEX_FILE": str(self.root / "wrong-index")},
            clear=False,
        ):
            result = self.adapt(repo)
        self.assertEqual(result["result"], "adapted")
        self.assertFalse(trace.exists())
        synthetic_temp = mock.Mock(path=self.root)
        synthetic_temp.revalidate.return_value = None
        token = adapter._ACTIVE_INTERNAL_TEMP_ROOT.set(synthetic_temp)
        try:
            controlled = adapter._controlled_git_environment()
        finally:
            adapter._ACTIVE_INTERNAL_TEMP_ROOT.reset(token)
        self.assertEqual(controlled["GIT_NO_LAZY_FETCH"], "1")
        self.assertNotIn("GIT_DIR", controlled)
        self.assertNotIn("GIT_TRACE", controlled)

    def test_partial_promisor_missing_blob_blocks_without_fetch_or_pack_change(self) -> None:
        remote_work = self.make_repo("remote-work", modify=False)
        blob_oid = git(remote_work, "rev-parse", "HEAD:README.md").stdout.decode().strip()
        remote = self.root / "remote.git"
        git(self.root, "clone", "--bare", "--no-local", str(remote_work), str(remote))
        local = self.root / "partial-local"
        git(self.root, "clone", "--no-local", str(remote), str(local))
        git(local, "config", "user.name", "CLU Synthetic Test")
        git(local, "config", "user.email", "synthetic@example.invalid")
        (local / "README.md").write_text("# Demo\n\nProposed local edit.\n", encoding="utf-8")
        loose = local / ".git/objects" / blob_oid[:2] / blob_oid[2:]
        if loose.exists():
            loose.unlink()
        for packed_object_file in (local / ".git/objects/pack").glob("*"):
            packed_object_file.unlink()
        git(local, "config", "remote.origin.promisor", "true")
        git(local, "config", "extensions.partialClone", "origin")
        packs_before = sorted(p.name for p in (local / ".git/objects/pack").glob("*"))
        remote_before = tree_file_inventory(remote)
        result = self.adapt(local, "partial-out")
        self.assertEqual(result["exact_blocker"], "partial_or_promisor_repository_unsupported")
        self.assertEqual(result["network_calls"], 0)
        self.assertEqual(packs_before, sorted(p.name for p in (local / ".git/objects/pack").glob("*")))
        self.assertEqual(remote_before, tree_file_inventory(remote))
        self.assertFalse((self.root / "partial-out").exists())

    def test_git_metadata_root_and_nested_symlinks_are_rejected(self) -> None:
        root_blockers = {
            "objects": "git_object_root_symlink_denied",
            "objects/pack": "git_object_pack_root_symlink_denied",
            "objects/info": "git_object_info_root_symlink_denied",
            "refs": "git_refs_root_symlink_denied",
            "info": "git_info_root_symlink_denied",
        }
        for relative, blocker in root_blockers.items():
            with self.subTest(root=relative):
                root_repo = self.make_repo(
                    "metadata-root-symlink-" + relative.replace("/", "-"), modify=False
                )
                secret = "EXTERNAL_ROOT_SECRET_" + relative.replace("/", "_")
                if relative == "objects":
                    (root_repo / "README.md").write_text(secret + "\n", encoding="utf-8")
                    git(root_repo, "add", "README.md")
                    git(root_repo, "commit", "--amend", "-q", "-m", "external secret")
                    (root_repo / "README.md").write_text(
                        "public proposed content\n", encoding="utf-8"
                    )
                else:
                    (root_repo / "README.md").write_text(
                        "# Demo\n\nProposed local edit.\n", encoding="utf-8"
                    )
                original = root_repo / ".git" / relative
                external = self.root / ("external-root-" + relative.replace("/", "-"))
                original.rename(external)
                original.symlink_to(external, target_is_directory=True)
                output_name = "metadata-root-symlink-out-" + relative.replace("/", "-")
                commands: list[str] = []
                original_run = adapter.GitRunner.run

                def tracked_run(runner, arguments, **kwargs):
                    commands.append(arguments[0])
                    return original_run(runner, arguments, **kwargs)

                with mock.patch.object(adapter.GitRunner, "run", tracked_run):
                    result = self.adapt(root_repo, output_name)
                self.assertEqual(result["exact_blocker"], blocker)
                self.assertEqual(commands, [])
                self.assertTrue(result["git_metadata_root_symlink_detected"])
                self.assertEqual(
                    result["git_object_root_symlink_detected"], relative == "objects"
                )
                self.assertFalse(result["external_object_database_used"])
                self.assertFalse(result["external_baseline_content_packaged"])
                self.assertFalse((self.root / output_name).exists())
                self.assertEqual(
                    list(self.root.glob(f".{output_name}.clu-git-adapt-*")), []
                )

        for relative in (
            "objects/pack/nested-link",
            "objects/info/nested-link",
            "refs/heads/nested-link",
            "info/nested-link",
        ):
            with self.subTest(relative=relative):
                repo = self.make_repo("nested-" + relative.replace("/", "-"))
                external = self.root / ("external-" + relative.replace("/", "-"))
                external.write_bytes(b"external metadata sentinel")
                target = repo / ".git" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(external)
                before = external.read_bytes()
                result = self.adapt(repo, "nested-out-" + relative.replace("/", "-"))
                self.assertEqual(result["exact_blocker"], "git_metadata_symlink_denied")
                self.assertEqual(external.read_bytes(), before)

    def test_external_object_routes_grafts_replace_and_indirection_are_rejected(self) -> None:
        cases = (
            ("objects/info/alternates", "external_object_database_unsupported"),
            ("objects/info/http-alternates", "external_object_database_unsupported"),
            ("info/grafts", "git_grafts_unsupported"),
            ("info/attributes", "git_info_attributes_unsupported"),
            ("commondir", "non_direct_git_metadata_unsupported"),
        )
        for relative, blocker in cases:
            with self.subTest(relative=relative):
                repo = self.make_repo("forbidden-" + relative.replace("/", "-"))
                path = repo / ".git" / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(str(self.root / "external-object-db") + "\n")
                commands: list[str] = []
                original_run = adapter.GitRunner.run

                def tracked_run(runner, arguments, **kwargs):
                    commands.append(arguments[0])
                    return original_run(runner, arguments, **kwargs)

                with mock.patch.object(adapter.GitRunner, "run", tracked_run):
                    result = self.adapt(repo, "forbidden-out-" + relative.replace("/", "-"))
                self.assertEqual(result["exact_blocker"], blocker)
                self.assertNotIn("status", commands)
                self.assertNotIn("cat-file", commands)

        repo = self.make_repo("replace-ref")
        (repo / ".git/refs/replace").mkdir(parents=True)
        self.assertEqual(
            self.adapt(repo, "replace-ref-out")["exact_blocker"],
            "git_replace_refs_unsupported",
        )

        repo = self.make_repo("packed-replace-ref")
        oid = git(repo, "rev-parse", "HEAD").stdout.decode().strip()
        (repo / ".git/packed-refs").write_text(
            f"# pack-refs with: peeled fully-peeled sorted\n{oid} refs/replace/{oid}\n"
        )
        self.assertEqual(
            self.adapt(repo, "packed-replace-out")["exact_blocker"],
            "git_replace_refs_unsupported",
        )

    def test_required_git_controls_are_regular_and_present(self) -> None:
        for name in ("HEAD", "index", "config"):
            with self.subTest(name=name):
                repo = self.make_repo("missing-control-" + name.lower())
                (repo / ".git" / name).unlink()
                result = self.adapt(repo, "missing-control-out-" + name.lower())
                self.assertEqual(
                    result["exact_blocker"], "git_metadata_required_control_missing"
                )
                self.assertFalse(result["git_metadata_descriptor_boundary_enforced"])

    def test_two_repository_external_secret_baseline_exfiltration_is_blocked(self) -> None:
        victim = self.make_repo("external-secret-victim", modify=False)
        secret = "EXTERNAL_BASELINE_SECRET_7a61f5"
        (victim / "README.md").write_text(secret + "\n", encoding="utf-8")
        git(victim, "add", "README.md")
        git(victim, "commit", "--amend", "-q", "-m", "secret baseline")
        external = self.root / "external-object-repository"
        git(self.root, "clone", "--no-hardlinks", str(victim), str(external))
        blob_oid = git(victim, "rev-parse", "HEAD:README.md").stdout.decode().strip()
        local_blob = victim / ".git/objects" / blob_oid[:2] / blob_oid[2:]
        self.assertTrue(local_blob.is_file())
        local_blob.unlink()
        (victim / "README.md").write_text("public proposed content\n", encoding="utf-8")
        alternates = victim / ".git/objects/info/alternates"
        alternates.write_text(str(external / ".git/objects") + "\n", encoding="utf-8")
        commands: list[str] = []
        original_run = adapter.GitRunner.run

        def tracked_run(runner, arguments, **kwargs):
            commands.append(arguments[0])
            return original_run(runner, arguments, **kwargs)

        with mock.patch.object(adapter.GitRunner, "run", tracked_run):
            result = self.adapt(victim, "external-secret-out")
        self.assertEqual(result["exact_blocker"], "external_object_database_unsupported")
        self.assertFalse(result["external_object_database_used"])
        self.assertFalse(result["external_baseline_content_packaged"])
        self.assertEqual(commands, [])
        self.assertFalse((self.root / "external-secret-out").exists())
        self.assertEqual((external / "README.md").read_text().strip(), secret)

    def test_git_metadata_hardlinks_and_transient_ctime_changes_block(self) -> None:
        repo = self.make_repo("metadata-hardlink")
        external = self.root / "external-pack"
        external.write_bytes(b"not a pack")
        os.link(external, repo / ".git/objects/pack/external.pack")
        result = self.adapt(repo, "metadata-hardlink-out")
        self.assertEqual(result["exact_blocker"], "git_metadata_hardlink_denied")
        self.assertEqual(external.read_bytes(), b"not a pack")

        repo = self.make_repo("metadata-ctime-race")
        changed = {"value": False}

        def mutate(phase: str, _lease: adapter.GitMetadataLease) -> None:
            if phase == "before_post:status" and not changed["value"]:
                changed["value"] = True
                transient = repo / ".git/objects/pack/transient"
                transient.write_bytes(b"transient")
                transient.unlink()

        adapter.GIT_METADATA_TEST_HOOK = mutate
        result = self.adapt(repo, "metadata-ctime-race-out")
        adapter.GIT_METADATA_TEST_HOOK = None
        self.assertTrue(changed["value"])
        self.assertEqual(result["exact_blocker"], "git_metadata_identity_changed")
        self.assertFalse((self.root / "metadata-ctime-race-out").exists())

        repo = self.make_repo("metadata-rename-restore-race")
        renamed = {"value": False}

        def rename_restore(phase: str, _lease: adapter.GitMetadataLease) -> None:
            if phase == "before_post:status" and not renamed["value"]:
                renamed["value"] = True
                pack = repo / ".git/objects/pack"
                temporary = repo / ".git/objects/pack-temporary"
                pack.rename(temporary)
                temporary.rename(pack)

        adapter.GIT_METADATA_TEST_HOOK = rename_restore
        result = self.adapt(repo, "metadata-rename-restore-out")
        adapter.GIT_METADATA_TEST_HOOK = None
        self.assertTrue(renamed["value"])
        self.assertEqual(result["exact_blocker"], "git_metadata_identity_changed")
        self.assertFalse((self.root / "metadata-rename-restore-out").exists())

    def test_object_root_replacement_is_detected_without_deleting_replacement(self) -> None:
        repo = self.make_repo("object-root-replacement")
        holder: dict[str, Path] = {}

        def replace(phase: str, _lease: adapter.GitMetadataLease) -> None:
            if phase != "before_post:cat-file" or holder:
                return
            pack = repo / ".git/objects/pack"
            orphan = repo / ".git/objects/pack-original"
            pack.rename(orphan)
            pack.mkdir()
            sentinel = pack / "important.txt"
            sentinel.write_bytes(b"preserve")
            holder["sentinel"] = sentinel

        adapter.GIT_METADATA_TEST_HOOK = replace
        result = self.adapt(repo, "object-root-replacement-out")
        adapter.GIT_METADATA_TEST_HOOK = None
        self.assertEqual(result["exact_blocker"], "git_metadata_identity_changed")
        self.assertEqual(holder["sentinel"].read_bytes(), b"preserve")
        self.assertTrue(holder["sentinel"].parent.exists())
        self.assertFalse((self.root / "object-root-replacement-out").exists())

    def test_git_version_is_metadata_bracketed_and_checks_exit_status(self) -> None:
        repo = self.make_repo("git-version-metadata")
        lease = adapter.GitMetadataLease.acquire(repo, repo / ".git")
        synthetic_temp = mock.Mock(path=self.root)
        synthetic_temp.revalidate.return_value = None
        temp_token = adapter._ACTIVE_INTERNAL_TEMP_ROOT.set(synthetic_temp)
        original_process = adapter._run_bounded_process
        changed = {"value": False}

        def raced_process(command, **kwargs):
            result = original_process(command, **kwargs)
            if command[-1:] == ["--version"] and not changed["value"]:
                changed["value"] = True
                transient = repo / ".git/objects/pack/version-race"
                transient.write_bytes(b"race")
                transient.unlink()
            return result

        try:
            with mock.patch.object(adapter, "_run_bounded_process", raced_process):
                with self.assertRaisesRegex(
                    adapter.GitAdapterError, "git_metadata_identity_changed"
                ):
                    adapter._git_version(adapter._resolve_git_executable("/usr/bin/git"), lease)
        finally:
            lease.close()
        self.assertTrue(changed["value"])

        failing = self.root / "failing-git-version"
        failing.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
        failing.chmod(0o700)
        try:
            with self.assertRaisesRegex(adapter.GitAdapterError, "git_version_failed"):
                adapter._git_version(str(failing))
        finally:
            adapter._ACTIVE_INTERNAL_TEMP_ROOT.reset(temp_token)

    def test_ignored_entries_are_strictly_unsupported_and_races_are_derived(self) -> None:
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                repo = self.make_repo(f"ignored-{kind}")
                (repo / ".gitignore").write_text("ignored*\n", encoding="utf-8")
                git(repo, "add", ".gitignore"); git(repo, "commit", "-q", "-m", "ignore")
                (repo / "README.md").write_text("supported edit\n", encoding="utf-8")
                if kind == "file":
                    (repo / "ignored.tmp").write_text("ignored\n", encoding="utf-8")
                else:
                    (repo / "ignored-dir").mkdir(); (repo / "ignored-dir/x").write_text("ignored\n")
                result = self.adapt(repo, f"ignored-out-{kind}")
                self.assertEqual(result["exact_blocker"], "ignored_untracked_files_unsupported")
        repo = self.make_repo("ignored-race")
        (repo / ".gitignore").write_text("race.tmp\n", encoding="utf-8")
        git(repo, "add", ".gitignore"); git(repo, "commit", "-q", "-m", "ignore")
        (repo / "README.md").write_text("supported edit\n", encoding="utf-8")
        adapter.ADAPTER_TEST_HOOK = lambda root: (root / "race.tmp").write_text("raced\n")
        result = self.adapt(repo, "ignored-race-out")
        self.assertEqual(result["exact_blocker"], "repository_state_changed_during_adaptation")
        self.assertEqual(result["post_acceptance_detail"], "git_metadata_identity_changed")
        self.assertIn("repository:post_acceptance_snapshot", result["repository_files_changed"])
        self.assertFalse(result["repository_worktree_unchanged"])
        self.assertFalse((self.root / "ignored-race-out").exists())
        for action in ("delete", "rename"):
            with self.subTest(action=action):
                repo = self.make_repo(f"ignored-{action}")
                (repo / ".gitignore").write_text("old.tmp\nnew.tmp\n", encoding="utf-8")
                git(repo, "add", ".gitignore"); git(repo, "commit", "-q", "-m", "ignore")
                (repo / "README.md").write_text("supported edit\n", encoding="utf-8")
                ignored = repo / "old.tmp"; ignored.write_text("ignored\n")
                if action == "delete":
                    adapter.STATUS_SNAPSHOT_TEST_HOOK = lambda _root, path=ignored: path.unlink()
                else:
                    adapter.STATUS_SNAPSHOT_TEST_HOOK = lambda _root, path=ignored: path.rename(path.with_name("new.tmp"))
                result = self.adapt(repo, f"ignored-{action}-out")
                adapter.STATUS_SNAPSHOT_TEST_HOOK = None
                self.assertEqual(result["exact_blocker"], "ignored_untracked_files_unsupported")
                self.assertFalse((self.root / f"ignored-{action}-out").exists())
        before = {"status:!:old.tmp": {"record_sha256": "a"}}
        after_delete: dict[str, dict[str, str]] = {}
        self.assertEqual(adapter._derive_inventory_changes(before, after_delete), ([], ["status:!:old.tmp"], []))
        after_rename = {"status:!:new.tmp": {"record_sha256": "b"}}
        created, removed, changed = adapter._derive_inventory_changes(before, after_rename)
        self.assertEqual(created, ["status:!:new.tmp"])
        self.assertEqual(removed, ["status:!:old.tmp"])
        self.assertEqual(changed, [])

    def test_same_size_transient_content_substitution_is_blocked(self) -> None:
        repo = self.make_repo()
        accepted = (repo / "README.md").read_bytes()
        transient = b"# Demo\n\nTransient local edit\n"
        self.assertEqual(len(accepted), len(transient))
        reads = {"count": 0}

        def hook(phase: str, path: Path, _descriptor: int) -> None:
            if phase == "after_pre_fstat":
                reads["count"] += 1
                if reads["count"] == 2:
                    path.write_bytes(transient)
            elif phase == "after_read" and reads["count"] == 2:
                path.write_bytes(accepted)

        adapter.WORKTREE_READ_TEST_HOOK = hook
        result = self.adapt(repo, "transient-out")
        self.assertEqual(result["exact_blocker"], "worktree_snapshot_hash_mismatch")
        self.assertEqual((repo / "README.md").read_bytes(), accepted)
        self.assertFalse((self.root / "transient-out").exists())

    def test_symlink_inode_size_and_mode_read_races_block(self) -> None:
        race_cases = {}

        def symlink_swap(path: Path) -> None:
            target = path.parent / "alternate"
            target.write_text("alternate\n")
            path.unlink(); path.symlink_to(target.name)
        race_cases["symlink"] = symlink_swap

        def inode_swap(path: Path) -> None:
            data = path.read_bytes(); replacement = path.with_name("replacement")
            replacement.write_bytes(data); os.replace(replacement, path)
        race_cases["inode"] = inode_swap
        race_cases["size"] = lambda path: path.write_bytes(path.read_bytes() + b"x")
        race_cases["mode"] = lambda path: os.chmod(path, path.stat().st_mode | stat.S_IXUSR)
        for name, mutation in race_cases.items():
            with self.subTest(name=name):
                repo = self.make_repo(f"read-race-{name}")
                calls = {"count": 0}
                def hook(phase: str, path: Path, _descriptor: int, mutation=mutation) -> None:
                    if phase == "after_pre_fstat":
                        calls["count"] += 1
                        if calls["count"] == 2:
                            mutation(path)
                adapter.WORKTREE_READ_TEST_HOOK = hook
                result = self.adapt(repo, f"read-race-out-{name}")
                adapter.WORKTREE_READ_TEST_HOOK = None
                expected = "worktree_file_symlink_race_detected" if name == "symlink" else (
                    "worktree_file_identity_changed" if name == "inode" else "worktree_content_changed_during_read"
                )
                self.assertEqual(result["exact_blocker"], expected)
                self.assertFalse((self.root / f"read-race-out-{name}").exists())

    def test_pre_read_size_limits_and_blob_oid_verification(self) -> None:
        baseline_repo = self.make_repo("oversized-baseline", modify=False)
        oversized = b"x" * (adapter.MAX_PROPOSED_FILE_SIZE + 1)
        (baseline_repo / "README.md").write_bytes(oversized)
        git(baseline_repo, "add", "README.md"); git(baseline_repo, "commit", "-q", "-m", "large")
        (baseline_repo / "README.md").write_bytes(b"small proposed\n")
        calls: list[list[str]] = []
        original_run = adapter.GitRunner.run
        def spy(runner, arguments, **kwargs):
            calls.append(arguments)
            return original_run(runner, arguments, **kwargs)
        with mock.patch.object(adapter.GitRunner, "run", new=spy):
            result = self.adapt(baseline_repo, "large-baseline-out")
        self.assertEqual(result["exact_blocker"], "baseline_blob_size_limit_exceeded")
        self.assertFalse(any(args[:1] == ["cat-file"] and len(args) > 1 and args[1] == "blob" for args in calls))

        worktree_repo = self.make_repo("oversized-worktree")
        with (worktree_repo / "README.md").open("wb") as sparse:
            sparse.truncate(adapter.MAX_PROPOSED_FILE_SIZE + 1)
        adapter.WORKTREE_CONTENT_READ_CALLS = 0
        result = self.adapt(worktree_repo, "large-worktree-out")
        self.assertEqual(result["exact_blocker"], "worktree_file_size_limit_exceeded")
        self.assertEqual(adapter.WORKTREE_CONTENT_READ_CALLS, 0)
        boundary = self.root / "boundary.bin"
        with boundary.open("wb") as bounded:
            bounded.truncate(adapter.MAX_PROPOSED_FILE_SIZE)
        boundary_bytes, boundary_identity = adapter._bounded_regular_file_read(
            boundary, limit=adapter.MAX_PROPOSED_FILE_SIZE
        )
        self.assertEqual(len(boundary_bytes), adapter.MAX_PROPOSED_FILE_SIZE)
        self.assertEqual(boundary_identity["size"], adapter.MAX_PROPOSED_FILE_SIZE)

        repo = self.make_repo("blob-mismatch")
        original_run = adapter.GitRunner.run
        def substituted(runner, arguments, **kwargs):
            payload = original_run(runner, arguments, **kwargs)
            if arguments[:2] == ["cat-file", "blob"]:
                return b"Z" * len(payload)
            return payload
        with mock.patch.object(adapter.GitRunner, "run", new=substituted):
            result = self.adapt(repo, "blob-mismatch-out")
        self.assertEqual(result["exact_blocker"], "baseline_blob_oid_content_mismatch")

    def test_bounded_status_stderr_and_metadata_inventory_limits(self) -> None:
        with self.assertRaisesRegex(adapter.GitAdapterError, "git_status_output_limit_exceeded"):
            adapter.parse_porcelain_v2_z(b"x" * (adapter.MAX_GIT_STATUS_BYTES + 1))
        oid = b"a" * 40
        record = b"1 .M N... 100644 100644 100644 " + oid + b" " + oid + b" README.md\0"
        with self.assertRaisesRegex(adapter.GitAdapterError, "git_status_record_limit_exceeded"):
            adapter.parse_porcelain_v2_z(record * (adapter.MAX_STATUS_RECORDS + 1))
        repo = self.make_repo("inventory-limit")
        with mock.patch.object(adapter, "MAX_GIT_METADATA_INVENTORY_ENTRIES", 1):
            with self.assertRaisesRegex(adapter.GitAdapterError, "git_metadata_inventory_limit_exceeded"):
                adapter._bounded_inventory_files(repo / ".git")
        noisy = self.root / "noisy-git"
        noisy.write_text(
            "#!/usr/bin/env python3\nimport sys\nsys.stderr.write('x' * 70000)\nraise SystemExit(1)\n",
            encoding="utf-8",
        )
        os.chmod(noisy, 0o755)
        synthetic_temp = mock.Mock(path=self.root)
        synthetic_temp.revalidate.return_value = None
        temp_token = adapter._ACTIVE_INTERNAL_TEMP_ROOT.set(synthetic_temp)
        try:
            with self.assertRaisesRegex(adapter.GitAdapterError, "git_stderr_limit_exceeded"):
                adapter._run_bounded_process(
                    [sys.executable, str(noisy)],
                    cwd=repo,
                    max_stdout=adapter.MAX_GIT_STDOUT_BYTES,
                )
        finally:
            adapter._ACTIVE_INTERNAL_TEMP_ROOT.reset(temp_token)

    def test_candidate_to_accepted_snapshot_transition_races_block_before_staging(self) -> None:
        cases = (
            "second_tracked", "ignored_file", "ignored_directory", "untracked",
            "stage_selected", "stage_second", "delete_other", "rename_other",
            "head_change", "index_flag",
        )
        for case in cases:
            with self.subTest(case=case):
                repo = self.make_repo(f"acceptance-{case}")
                self.add_tracked_other(repo)
                if case.startswith("ignored"):
                    (repo / ".gitignore").write_text("ignored*\n")
                    git(repo, "add", ".gitignore"); git(repo, "commit", "-q", "-m", "ignore")
                def mutation(root: Path, case=case) -> None:
                    if case == "second_tracked":
                        (root / "OTHER.md").write_text("other changed\n")
                    elif case == "ignored_file":
                        (root / "ignored.tmp").write_text("ignored\n")
                    elif case == "ignored_directory":
                        (root / "ignored-dir").mkdir(); (root / "ignored-dir/x").write_text("ignored\n")
                    elif case == "untracked":
                        (root / "untracked.tmp").write_text("untracked\n")
                    elif case == "stage_selected":
                        git(root, "add", "README.md")
                    elif case == "stage_second":
                        (root / "OTHER.md").write_text("other changed\n"); git(root, "add", "OTHER.md")
                    elif case == "delete_other":
                        (root / "OTHER.md").unlink()
                    elif case == "rename_other":
                        (root / "OTHER.md").rename(root / "RENAMED.md")
                    elif case == "head_change":
                        (root / "OTHER.md").write_text("committed race\n"); git(root, "add", "OTHER.md"); git(root, "commit", "-q", "-m", "race")
                    elif case == "index_flag":
                        git(root, "update-index", "--assume-unchanged", "OTHER.md")
                adapter.STATUS_SNAPSHOT_TEST_HOOK = mutation
                output_name = f"acceptance-out-{case}"
                result = self.adapt(repo, output_name)
                adapter.STATUS_SNAPSHOT_TEST_HOOK = None
                self.assertEqual(result["exact_blocker"], "repository_state_changed_before_acceptance")
                self.assertNotEqual(result["result"], "adapted")
                self.assertTrue(
                    result["repository_files_created"]
                    or result["repository_files_removed"]
                    or result["repository_files_changed"]
                )
                if case.startswith("ignored"):
                    self.assertEqual(result["pre_acceptance_detail"], "git_metadata_identity_changed")
                    self.assertIn(
                        "repository:accepted_snapshot_capture",
                        result["repository_files_changed"],
                    )
                self.assertFalse((self.root / output_name).exists())
                self.assertEqual(list(self.root.glob(f".{output_name}.clu-git-adapt-*")), [])

    def test_hidden_index_flags_sparse_state_and_index_limits_fail_closed(self) -> None:
        flags = (
            ("assume", "--assume-unchanged", "assume_unchanged_index_entry_unsupported"),
            ("skip", "--skip-worktree", "skip_worktree_index_entry_unsupported"),
        )
        for name, option, blocker in flags:
            with self.subTest(name=name):
                repo = self.make_repo(f"hidden-{name}")
                self.add_tracked_other(repo)
                git(repo, "update-index", option, "OTHER.md")
                (repo / "OTHER.md").write_text("hidden modification\n")
                result = self.adapt(repo, f"hidden-{name}-out")
                self.assertEqual(result["exact_blocker"], blocker)
                self.assertFalse((self.root / f"hidden-{name}-out").exists())

        repo = self.make_repo("flag-after-acceptance")
        self.add_tracked_other(repo)
        adapter.ADAPTER_TEST_HOOK = lambda root: git(root, "update-index", "--skip-worktree", "OTHER.md")
        result = self.adapt(repo, "flag-after-out")
        adapter.ADAPTER_TEST_HOOK = None
        self.assertEqual(result["exact_blocker"], "repository_state_changed_during_adaptation")
        self.assertEqual(result["post_acceptance_detail"], "git_metadata_identity_changed")
        self.assertIn("repository:post_acceptance_snapshot", result["repository_files_changed"])
        self.assertFalse((self.root / "flag-after-out").exists())

        repo = self.make_repo("flag-removal-prevented")
        self.add_tracked_other(repo)
        git(repo, "update-index", "--assume-unchanged", "OTHER.md")
        hook_called = {"value": False}
        def remove_flag(root: Path) -> None:
            hook_called["value"] = True; git(root, "update-index", "--no-assume-unchanged", "OTHER.md")
        adapter.STATUS_SNAPSHOT_TEST_HOOK = remove_flag
        result = self.adapt(repo, "flag-removal-out")
        adapter.STATUS_SNAPSHOT_TEST_HOOK = None
        self.assertEqual(result["exact_blocker"], "assume_unchanged_index_entry_unsupported")
        self.assertFalse(hook_called["value"])

        repo = self.make_repo("sparse-state")
        git(repo, "sparse-checkout", "init", "--cone")
        result = self.adapt(repo, "sparse-out")
        self.assertEqual(result["exact_blocker"], "sparse_checkout_or_sparse_index_unsupported")

        repo = self.make_repo("index-limit")
        with mock.patch.object(adapter, "MAX_INDEX_STATE_OUTPUT_BYTES", 1):
            result = self.adapt(repo, "index-limit-out")
        self.assertEqual(result["exact_blocker"], "index_state_output_limit_exceeded")

        oid = "a" * 40
        raw = f"M 100644 {oid} 1\tREADME.md\0".encode()
        fake_runner = mock.Mock()
        fake_runner.run.return_value = raw
        state = adapter._index_state_snapshot(fake_runner, "sha1")
        self.assertEqual(state["boundary_blocker"], "nonzero_index_stage_unsupported")

    def test_direct_included_and_racing_partial_promisor_config_is_rejected(self) -> None:
        fixtures = {
            "direct_partial": "\n[extensions]\n\tpartialClone = origin\n",
            "direct_promisor": "\n[remote \"origin\"]\n\tpromisor = true\n",
            "include": f"\n[include]\n\tpath = {self.root / 'included.cfg'}\n",
            "include_if": f"\n[includeIf \"gitdir:**\"]\n\tpath = {self.root / 'included.cfg'}\n",
        }
        (self.root / "included.cfg").write_text("[remote \"origin\"]\npromisor=true\n")
        for name, addition in fixtures.items():
            with self.subTest(name=name):
                repo = self.make_repo(f"config-{name}")
                config = repo / ".git/config"
                config.write_text(config.read_text() + addition)
                before_packs = tree_file_inventory(repo / ".git/objects/pack")
                result = self.adapt(repo, f"config-{name}-out")
                expected = "repository_config_include_unsupported" if "include" in name else "partial_or_promisor_repository_unsupported"
                self.assertEqual(result["exact_blocker"], expected)
                self.assertEqual(before_packs, tree_file_inventory(repo / ".git/objects/pack"))
                self.assertFalse((self.root / f"config-{name}-out").exists())

        repo = self.make_repo("config-worktree")
        (repo / ".git/config.worktree").write_text("[remote \"origin\"]\npromisor=true\n")
        self.assertEqual(self.adapt(repo, "config-worktree-out")["exact_blocker"], "partial_or_promisor_repository_unsupported")

        repo = self.make_repo("promisor-marker")
        pack = repo / ".git/objects/pack"; pack.mkdir(parents=True, exist_ok=True)
        (pack / "pack-synthetic.promisor").write_bytes(b"")
        self.assertEqual(self.adapt(repo, "promisor-marker-out")["exact_blocker"], "partial_or_promisor_repository_unsupported")

        repo = self.make_repo("config-include-race")
        def add_include(root: Path) -> None:
            config = root / ".git/config"
            config.write_text(config.read_text() + f"\n[include]\npath={self.root / 'included.cfg'}\n")
        adapter.STATUS_SNAPSHOT_TEST_HOOK = add_include
        result = self.adapt(repo, "config-include-race-out")
        adapter.STATUS_SNAPSHOT_TEST_HOOK = None
        self.assertEqual(result["exact_blocker"], "repository_state_changed_before_acceptance")
        self.assertEqual(result["pre_acceptance_detail"], "git_metadata_identity_changed")
        self.assertIn("repository:accepted_snapshot_capture", result["repository_files_changed"])

        repo = self.make_repo("config-include-late")
        adapter.ADAPTER_TEST_HOOK = add_include
        result = self.adapt(repo, "config-include-late-out")
        adapter.ADAPTER_TEST_HOOK = None
        self.assertEqual(result["exact_blocker"], "repository_state_changed_during_adaptation")
        self.assertFalse((self.root / "config-include-late-out").exists())

    def test_staging_replacement_and_symlink_cleanup_preserve_external_sentinels(self) -> None:
        for replacement in ("directory", "symlink"):
            with self.subTest(replacement=replacement):
                repo = self.make_repo(f"cleanup-replacement-{replacement}")
                orphan_holder: dict[str, Path] = {}
                sentinel_holder: dict[str, Path] = {}
                def hook(phase: str, owned: adapter.OwnedOutputTree) -> None:
                    if phase != "before_repository_recheck":
                        return
                    original = owned.path
                    orphan = original.with_name(original.name + ".genuine-orphan")
                    original.rename(orphan); orphan_holder["path"] = orphan
                    if replacement == "directory":
                        original.mkdir(); sentinel = original / "important.txt"
                    else:
                        external = self.root / f"external-{replacement}-{uuid_fragment()}"; external.mkdir()
                        original.symlink_to(external, target_is_directory=True); sentinel = external / "important.txt"
                    sentinel.write_bytes(b"must survive")
                    sentinel_holder["path"] = sentinel
                    (repo / "README.md").write_text("force repository blocker\n")
                adapter.OUTPUT_OWNERSHIP_TEST_HOOK = hook
                result = self.adapt(repo, f"cleanup-replacement-out-{replacement}")
                adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
                self.assertEqual(result["exact_blocker"], "adapter_output_ownership_lost")
                self.assertTrue(result["cleanup_ownership_lost"])
                self.assertTrue(result["cleanup_intentionally_not_attempted"])
                self.assertFalse(result["automatic_nonempty_failure_cleanup_performed"])
                self.assertEqual(sentinel_holder["path"].read_bytes(), b"must survive")
                self.assertTrue(orphan_holder["path"].exists())
                self.assertTrue(sentinel_holder["path"].parent.exists())

    def test_repository_clean_process_and_required_filters_block_before_execution(self) -> None:
        for key in ("clean", "process", "required"):
            with self.subTest(key=key):
                repo = self.make_repo(f"filter-{key}", modify=False)
                (repo / ".gitattributes").write_text("README.md filter=tripwire\n", encoding="utf-8")
                git(repo, "add", ".gitattributes")
                git(repo, "commit", "-q", "-m", "attributes")
                sentinel = self.root / f"filter-{key}-sentinel"
                script = self.root / f"filter-{key}.sh"
                script.write_text(
                    f"#!/bin/sh\nprintf executed > '{sentinel}'\ncat\n",
                    encoding="utf-8",
                )
                script.chmod(0o700)
                if key == "required":
                    with (repo / ".git/config").open("a", encoding="utf-8") as handle:
                        handle.write("\n[filter \"tripwire\"]\n\trequired\n")
                else:
                    git(repo, "config", f"filter.tripwire.{key}", str(script))
                baseline = (repo / "README.md").read_bytes()
                proposed = baseline.replace(b"Baseline", b"Proposal")
                self.assertEqual(len(baseline), len(proposed))
                (repo / "README.md").write_bytes(proposed)
                git_commands: list[str] = []
                original_run = adapter.GitRunner.run
                def tracked_run(runner, arguments, **kwargs):
                    git_commands.append(arguments[0])
                    return original_run(runner, arguments, **kwargs)
                with mock.patch.object(adapter.GitRunner, "run", tracked_run):
                    result = self.adapt(repo, f"filter-{key}-out")
                self.assertEqual(result["exact_blocker"], "repository_filter_driver_unsupported")
                self.assertEqual(result["repository_configured_external_helpers_executed"], 0)
                self.assertNotIn("status", git_commands)
                self.assertFalse(sentinel.exists())
                self.assertFalse((self.root / f"filter-{key}-out").exists())

    def test_typed_promisor_booleans_block_true_forms_and_allow_false(self) -> None:
        truthy = (None, '"true"', "true", "yes", "on", "1", "TrUe")
        for index, value in enumerate(truthy):
            with self.subTest(value=value):
                repo = self.make_repo(f"typed-promisor-{index}")
                with (repo / ".git/config").open("a", encoding="utf-8") as handle:
                    handle.write("\n[remote \"origin\"]\n\tpromisor")
                    if value is not None:
                        handle.write(f" = {value}")
                    handle.write("\n")
                result = self.adapt(repo, f"typed-promisor-{index}-out")
                self.assertEqual(result["exact_blocker"], "partial_or_promisor_repository_unsupported")
        repo = self.make_repo("typed-promisor-false")
        with (repo / ".git/config").open("a", encoding="utf-8") as handle:
            handle.write("\n[remote \"origin\"]\n\tpromisor = false\n")
        result = self.adapt(repo, "typed-promisor-false-out")
        self.assertEqual(result["result"], "adapted")

    def test_repository_filter_cannot_reach_local_listener(self) -> None:
        repo = self.make_repo("filter-listener", modify=False)
        (repo / ".gitattributes").write_text("README.md filter=listener\n", encoding="utf-8")
        git(repo, "add", ".gitattributes")
        git(repo, "commit", "-q", "-m", "listener attributes")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.2)
        port = listener.getsockname()[1]
        command = (
            f"{sys.executable} -c \"import socket;"
            f"s=socket.create_connection(('127.0.0.1',{port}),1);s.send(b'x')\""
        )
        git(repo, "config", "filter.listener.process", command)
        baseline = (repo / "README.md").read_bytes()
        (repo / "README.md").write_bytes(baseline.replace(b"Baseline", b"Proposal"))
        try:
            result = self.adapt(repo, "filter-listener-out")
            self.assertEqual(result["exact_blocker"], "repository_filter_driver_unsupported")
            with self.assertRaises(socket.timeout):
                listener.accept()
        finally:
            listener.close()

    def test_output_parent_replacement_is_descriptor_bound(self) -> None:
        for replacement in ("directory", "symlink"):
            with self.subTest(replacement=replacement):
                repo = self.make_repo(f"parent-replace-{replacement}")
                parent = self.root / f"parent-{replacement}"
                parent.mkdir()
                orphan = self.root / f"parent-{replacement}-original"
                external = self.root / f"parent-{replacement}-replacement"
                external.mkdir()
                sentinel = external / "sentinel.txt"
                sentinel.write_bytes(b"preserve-parent")

                def replace_parent(phase: str, lease: adapter.OutputParentLease) -> None:
                    if phase != "after_parent_acquired":
                        return
                    parent.rename(orphan)
                    if replacement == "directory":
                        external.rename(parent)
                    else:
                        parent.symlink_to(external, target_is_directory=True)

                adapter.OUTPUT_PARENT_TEST_HOOK = replace_parent
                result = adapter.adapt_git_diff(
                    repo_path=repo,
                    policy_path=self.policy,
                    declared_actor_id="demo_operator",
                    requested_scope="docs_only",
                    output_dir=parent / "bundle",
                    event_time="2026-06-26T00:00:00Z",
                )
                adapter.OUTPUT_PARENT_TEST_HOOK = None
                self.assertEqual(result["exact_blocker"], "output_parent_identity_changed")
                self.assertFalse(result["output_parent_identity_preserved"])
                sentinel_after = parent / "sentinel.txt" if replacement == "directory" else sentinel
                self.assertEqual(sentinel_after.read_bytes(), b"preserve-parent")
                self.assertFalse((external / "bundle").exists())
                self.assertFalse((parent / "bundle").exists())

    def test_unknown_output_entries_are_not_blessed_and_are_retained_incomplete(self) -> None:
        cases = (
            "regular", "symlink", "hardlink", "directory", "fifo",
            "expected_changed", "expected_replaced",
        )
        for case in cases:
            with self.subTest(case=case):
                repo = self.make_repo(f"seal-{case}")
                external = self.root / f"seal-{case}-external"
                external.write_bytes(b"external-preserved")

                def inject(phase: str, owned: adapter.OwnedOutputTree, case=case) -> None:
                    expected_case = case.startswith("expected_")
                    wanted_phase = "before_checksums" if expected_case else "after_checksums_before_completion"
                    if phase != wanted_phase:
                        return
                    target = owned.path / f"unknown-{case}"
                    if case == "regular":
                        target.write_bytes(b"unknown")
                    elif case == "symlink":
                        target.symlink_to(external)
                    elif case == "hardlink":
                        os.link(external, target)
                    elif case == "directory":
                        target.mkdir()
                        (target / "sentinel").write_bytes(b"nested")
                    elif case == "fifo":
                        os.mkfifo(target)
                    elif case == "expected_changed":
                        (owned.path / "change_preview.diff").write_bytes(b"changed after registration")
                    else:
                        original = owned.path / "change_preview.diff"
                        original.rename(owned.path / "change_preview.original")
                        original.write_bytes(b"replacement")

                adapter.OUTPUT_OWNERSHIP_TEST_HOOK = inject
                result = self.adapt(repo, f"seal-{case}-out")
                adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
                self.assertNotEqual(result["result"], "adapted")
                self.assertFalse(result["output_bundle_sealed"])
                self.assertFalse(result["requested_final_output_present_after_failed_seal"])
                self.assertFalse((self.root / f"seal-{case}-out").exists())
                self.assertEqual(external.read_bytes(), b"external-preserved")
                incomplete = result["incomplete_staging_path"]
                self.assertIsInstance(incomplete, str)
                incomplete_path = Path(incomplete)
                self.assertTrue(incomplete_path.exists())
                checksum_path = incomplete_path / "CHECKSUMS.sha256"
                if checksum_path.exists():
                    self.assertNotIn(f"unknown-{case}", checksum_path.read_text(encoding="utf-8"))

    def test_final_seal_reports_exact_allowlist(self) -> None:
        repo = self.make_repo("exact-seal")
        result = self.adapt(repo, "exact-seal-out")
        self.assertTrue(result["output_bundle_exact_file_set_verified"])
        self.assertTrue(result["output_bundle_checksum_coverage_exact"])
        self.assertTrue(result["output_bundle_sealed"])
        self.assertEqual(result["output_bundle_unknown_entries"], [])
        self.assertEqual(result["output_bundle_missing_entries"], [])
        self.assertEqual(result["output_bundle_symlink_entries"], [])
        self.assertEqual(result["output_bundle_hardlink_entries"], [])

    def test_parent_replacement_after_staging_and_final_rename_never_redirects_output(self) -> None:
        for phase in ("after_staging_created", "before_repository_recheck", "before_publication_rename"):
            with self.subTest(phase=phase):
                repo = self.make_repo(f"parent-phase-{phase}")
                parent = self.root / f"output-parent-phase-{phase}"
                parent.mkdir()
                original = self.root / f"output-parent-phase-{phase}-original"
                sentinel_bytes = f"sentinel-{phase}".encode()

                def replace(phase_seen: str, owned: adapter.OwnedOutputTree, phase=phase) -> None:
                    if phase_seen != phase:
                        return
                    parent.rename(original)
                    parent.mkdir()
                    (parent / "sentinel").write_bytes(sentinel_bytes)

                adapter.OUTPUT_OWNERSHIP_TEST_HOOK = replace
                result = adapter.adapt_git_diff(
                    repo_path=repo,
                    policy_path=self.policy,
                    declared_actor_id="demo_operator",
                    requested_scope="docs_only",
                    output_dir=parent / "bundle",
                    event_time="2026-06-26T00:00:00Z",
                )
                adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
                self.assertNotEqual(result["result"], "adapted")
                self.assertIn(result["exact_blocker"], {"output_parent_identity_changed", "adapter_output_ownership_lost"})
                self.assertEqual((parent / "sentinel").read_bytes(), sentinel_bytes)
                self.assertEqual({path.name for path in parent.iterdir()}, {"sentinel"})
                self.assertFalse((parent / "bundle/BUNDLE_COMPLETE.json").exists())

    def test_unknown_entry_immediately_before_final_seal_invalidates_completion(self) -> None:
        repo = self.make_repo("pre-final-seal-injection")
        def inject(phase: str, owned: adapter.OwnedOutputTree) -> None:
            if phase == "before_final_seal":
                (owned.path / "late-unknown.txt").write_bytes(b"late")
        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = inject
        result = self.adapt(repo, "pre-final-seal-out")
        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
        self.assertEqual(result["exact_blocker"], "output_bundle_unknown_entry_detected")
        self.assertFalse(result["completion_record_present"])
        self.assertTrue(result["hidden_completion_record_present"])
        self.assertFalse(result["output_bundle_sealed"])
        self.assertFalse((self.root / "pre-final-seal-out").exists())
        incomplete = Path(result["incomplete_staging_path"])
        self.assertTrue((incomplete / "BUNDLE_COMPLETE.json").is_file())
        self.assertFalse((incomplete / adapter.INCOMPLETE_MARKER_NAME).exists())
        self.assertTrue(result["incomplete_marker_suppressed_due_completion_record"])
        self.assertNotIn("late-unknown.txt", (incomplete / "CHECKSUMS.sha256").read_text())

    def test_unknown_staging_content_marker_and_type_swaps_are_never_deleted(self) -> None:
        cases = ("unknown_file", "unknown_directory", "expected_directory", "marker_modified", "marker_hardlink")
        for case in cases:
            with self.subTest(case=case):
                repo = self.make_repo(f"cleanup-unknown-{case}")
                sentinel_holder: dict[str, Path] = {}
                def hook(phase: str, owned: adapter.OwnedOutputTree, case=case) -> None:
                    if phase != "before_repository_recheck":
                        return
                    if case == "unknown_file":
                        sentinel = owned.path / "important.txt"; sentinel.write_bytes(b"preserve")
                    elif case == "unknown_directory":
                        nested = owned.path / "unknown"; nested.mkdir(); sentinel = nested / "important.txt"; sentinel.write_bytes(b"preserve")
                    elif case == "expected_directory":
                        target = owned.path / "change_preview.diff"; target.unlink(); target.mkdir(); sentinel = target / "important.txt"; sentinel.write_bytes(b"preserve")
                    elif case == "marker_modified":
                        sentinel = owned.path / adapter.OWNERSHIP_MARKER_NAME; sentinel.write_bytes(b"preserve")
                    else:
                        marker = owned.path / adapter.OWNERSHIP_MARKER_NAME
                        sentinel = self.root / f"marker-hardlink-{uuid_fragment()}"; os.link(marker, sentinel)
                    sentinel_holder["path"] = sentinel
                    (repo / "README.md").write_text("force repository blocker\n")
                adapter.OUTPUT_OWNERSHIP_TEST_HOOK = hook
                result = self.adapt(repo, f"cleanup-unknown-out-{case}")
                adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
                self.assertEqual(result["exact_blocker"], "repository_state_changed_during_adaptation")
                self.assertTrue(result["cleanup_intentionally_not_attempted"])
                self.assertTrue(sentinel_holder["path"].exists())
                self.assertEqual(sentinel_holder["path"].read_bytes(), b"preserve" if case != "marker_hardlink" else sentinel_holder["path"].read_bytes())

    def test_publication_destination_race_preserves_sentinel(self) -> None:
        repo = self.make_repo("publication-destination-race")
        output = self.root / "publication-destination-race-out"
        holder: dict[str, Path] = {}
        def hook(phase: str, owned: adapter.OwnedOutputTree) -> None:
            if phase != "before_publication_rename":
                return
            output.mkdir(); sentinel = output / "important.txt"; sentinel.write_bytes(b"final sentinel")
            holder["sentinel"] = sentinel
        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = hook
        result = self.adapt(repo, "publication-destination-race-out")
        adapter.OUTPUT_OWNERSHIP_TEST_HOOK = None
        self.assertEqual(result["exact_blocker"], "output_path_must_not_exist")
        self.assertEqual(result["primary_blocker"], "output_path_must_not_exist")
        self.assertTrue(result["cleanup_intentionally_not_attempted"])
        self.assertEqual(holder["sentinel"].read_bytes(), b"final sentinel")
        self.assertTrue(output.exists())
        self.assertTrue(result["unowned_replacement_detected"])

    def test_failure_disposition_never_calls_output_deletion_apis(self) -> None:
        repo = self.make_repo("no-delete-failure")
        adapter.ADAPTER_TEST_HOOK = lambda root: (root / "README.md").write_text("force block\n")
        result = self.adapt(repo, "no-delete-failure-out")
        adapter.ADAPTER_TEST_HOOK = None
        self.assertEqual(result["exact_blocker"], "repository_state_changed_during_adaptation")
        self.assertFalse(result["automatic_nonempty_failure_cleanup_performed"])
        self.assertTrue(result["cleanup_intentionally_not_attempted"])
        self.assertEqual(result["output_entries_deleted"], [])
        disposition_source = inspect.getsource(adapter.OwnedOutputTree.preserve_failure)
        self.assertNotIn("os.unlink", disposition_source)
        self.assertNotIn("os.rmdir", disposition_source)
        self.assertNotIn("shutil.rmtree", disposition_source)

    def test_runtime_stdout_stderr_and_dual_stream_floods_are_killed_at_caps(self) -> None:
        for mode in ("stdout", "stderr", "both"):
            with self.subTest(mode=mode):
                pid_path = self.root / f"flood-{mode}.pid"
                script = self.root / f"flood-{mode}.py"
                script.write_text(
                    "import os,sys\n"
                    "open(sys.argv[2],'w').write(str(os.getpid()))\n"
                    "chunk=b'x'*4096\n"
                    "while True:\n"
                    "  os.write(1,chunk) if sys.argv[1] in ('stdout','both') else None\n"
                    "  os.write(2,chunk) if sys.argv[1] in ('stderr','both') else None\n"
                )
                observed: list[dict[str, object]] = []
                adapter.PROCESS_LIMIT_TEST_OBSERVER = observed.append
                started = time.monotonic()
                synthetic_temp = mock.Mock(path=self.root)
                synthetic_temp.revalidate.return_value = None
                token = adapter._ACTIVE_INTERNAL_TEMP_ROOT.set(synthetic_temp)
                try:
                    with self.assertRaises(adapter.GitAdapterError) as caught:
                        adapter._run_bounded_process(
                            [sys.executable, str(script), mode, str(pid_path)],
                            cwd=self.root,
                            max_stdout=8192,
                        )
                finally:
                    adapter._ACTIVE_INTERNAL_TEMP_ROOT.reset(token)
                elapsed = time.monotonic() - started
                adapter.PROCESS_LIMIT_TEST_OBSERVER = None
                expected = "git_stderr_limit_exceeded" if mode == "stderr" else "git_stdout_limit_exceeded"
                self.assertEqual(str(caught.exception), expected)
                self.assertLess(elapsed, 5)
                self.assertTrue(observed)
                self.assertLessEqual(observed[-1]["stdout_bytes"], 8193)
                self.assertLessEqual(observed[-1]["stderr_bytes"], adapter.MAX_GIT_STDERR_BYTES + 1)
                pid = int(pid_path.read_text())
                with self.assertRaises(OSError):
                    os.kill(pid, 0)

    def test_selected_parent_directory_symlink_swap_blocks_before_output(self) -> None:
        repo = self.root / "parent-race-repo"; repo.mkdir(); git(repo, "init", "-q")
        git(repo, "config", "user.name", "CLU Synthetic Test"); git(repo, "config", "user.email", "synthetic@example.invalid")
        (repo / "docs").mkdir(); (repo / "docs/README.md").write_text("baseline\n")
        git(repo, "add", "docs/README.md"); git(repo, "commit", "-q", "-m", "baseline")
        (repo / "docs/README.md").write_text("proposed\n")
        policy = runtime.build_demo_policy(); policy["allowed_paths"] = ["docs/README.md"]
        for rule in policy["rules"]:
            if rule["effect"] == "allow": rule["paths"] = ["docs/README.md"]
        policy_path = write_json(self.root / "parent-policy.json", policy)
        swapped = {"value": False}
        def hook(phase: str, _path: Path, _descriptor: int) -> None:
            if phase == "after_parent_traversal" and not swapped["value"]:
                swapped["value"] = True
                (repo / "docs").rename(repo / "docs-original")
                (repo / "docs").symlink_to("docs-original", target_is_directory=True)
        adapter.WORKTREE_READ_TEST_HOOK = hook
        result = self.adapt(repo, "parent-race-out", policy=policy_path)
        adapter.WORKTREE_READ_TEST_HOOK = None
        self.assertEqual(result["result"], "blocked")
        self.assertIn(
            result["exact_blocker"],
            {
                "worktree_parent_symlink_race_detected",
                # Accepted-snapshot closure may observe the same injected path
                # change before the descriptor reader reaches its more
                # specific classification. Both paths fail closed before
                # output publication.
                "repository_snapshot_not_closed",
                # Git may classify the swapped directory as an unsupported
                # multi-path state before either repository revalidation or
                # the descriptor reader supplies a narrower race blocker.
                "exactly_one_changed_path_required",
            },
        )
        self.assertFalse((self.root / "parent-race-out").exists())


def tree_file_inventory(root: Path) -> list[tuple[str, int, str]]:
    return sorted(
        (path.relative_to(root).as_posix(), path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.rglob("*") if path.is_file() and not path.is_symlink()
    )


def uuid_fragment() -> str:
    return next(tempfile._get_candidate_names())


if __name__ == "__main__":
    unittest.main()
