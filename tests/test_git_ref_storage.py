from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clu_governance import git_diff_adapter as adapter
from clu_governance import source_mutation_demo_runtime as runtime


def git(repo: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        [shutil.which("git") or "git", *arguments],
        cwd=repo,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    if check and completed.returncode:
        raise AssertionError(completed.stderr.decode(errors="replace"))
    return completed


MACOS_ADAPTER_INTEGRATION_REASON = (
    "requires successful macOS git-adapt execution; unsupported-platform "
    "fail-closed behavior is covered separately"
)


def macos_adapter_integration(*portable_test_names: str):
    """Apply per-test macOS skips while retaining ref-format parsing."""

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
    "test_ref_format_probe_fails_closed_and_exact_old_git_fallback_is_bounded"
)
class GitRefStorageBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="clu-git-ref-storage.")).resolve()
        self.policy = self.root / "policy.json"
        self.policy.write_text(
            json.dumps(runtime.build_demo_policy(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        adapter.ADAPTER_TEST_HOOK = None
        adapter.STATUS_SNAPSHOT_TEST_HOOK = None
        adapter.GIT_METADATA_TEST_HOOK = None
        shutil.rmtree(self.root, ignore_errors=True)

    def make_repo(self, name: str, *, ref_format: str | None = None) -> Path:
        repo = self.root / name
        repo.mkdir()
        init = ["init", "-q"]
        if ref_format is not None:
            init.append(f"--ref-format={ref_format}")
        git(repo, *init)
        git(repo, "config", "user.name", "CLU Synthetic Test")
        git(repo, "config", "user.email", "synthetic@example.invalid")
        (repo / "README.md").write_text("# Demo\n\nBaseline.\n", encoding="utf-8")
        git(repo, "add", "README.md")
        git(repo, "commit", "-q", "-m", "baseline")
        (repo / "README.md").write_text(
            "# Demo\n\nProposed local edit.\n", encoding="utf-8"
        )
        return repo

    def adapt(self, repo: Path, output_name: str) -> dict[str, object]:
        return adapter.adapt_git_diff(
            repo_path=repo,
            policy_path=self.policy,
            declared_actor_id="demo_operator",
            requested_scope="docs_only",
            output_dir=self.root / output_name,
            event_time="2026-07-11T00:00:00Z",
        )

    @staticmethod
    def append_config(repo: Path, text: str) -> None:
        with (repo / ".git/config").open("a", encoding="utf-8") as handle:
            handle.write(text)

    def test_files_backend_is_explicitly_proven(self) -> None:
        repo = self.make_repo("files")
        result = self.adapt(repo, "files-bundle")
        self.assertEqual(result["result"], "adapted")
        self.assertEqual(result["supported_git_ref_storage_backend"], "files")
        self.assertEqual(result["git_ref_storage_backend"], "files")
        self.assertTrue(result["git_ref_storage_backend_verified"])
        self.assertIn(
            result["git_ref_storage_backend_evidence_source"],
            {"git_rev_parse_show_ref_format", "captured_config_and_absent_reftable_fallback"},
        )
        provenance = json.loads(
            (self.root / "files-bundle/git_provenance.json").read_text(encoding="utf-8")
        )
        self.assertEqual(provenance["git_ref_storage_backend"], "files")
        self.assertTrue(provenance["git_ref_storage_backend_verified"])
        self.assertTrue(
            any("--show-ref-format" in command for command in provenance["git_commands"])
        )

    def test_real_reftable_repository_is_rejected_before_git_runner(self) -> None:
        probe = self.root / "probe"
        probe.mkdir()
        supported = git(probe, "init", "-q", "--ref-format=reftable", check=False)
        if supported.returncode:
            self.skipTest("executed Git does not support reftable fixtures")
        shutil.rmtree(probe)
        repo = self.make_repo("reftable-repo", ref_format="reftable")
        commands: list[list[str]] = []
        original = adapter.GitRunner.run

        def observed(runner, arguments, **kwargs):
            commands.append(list(arguments))
            return original(runner, arguments, **kwargs)

        with mock.patch.object(adapter.GitRunner, "run", new=observed):
            result = self.adapt(repo, "reftable-out")
        self.assertEqual(result["exact_blocker"], "git_ref_storage_backend_unsupported")
        self.assertEqual(commands, [])
        self.assertFalse((self.root / "reftable-out").exists())
        self.assertFalse(result["external_reftable_storage_used"])
        self.assertFalse(result["external_ref_storage_content_packaged"])

    def test_external_reftable_symlink_cannot_exfiltrate_secret(self) -> None:
        victim = self.make_repo("reftable-victim", ref_format="reftable")
        secret = "EXTERNAL_REFTABLE_BASELINE_SECRET_29d752"
        (victim / "README.md").write_text(secret + "\n", encoding="utf-8")
        git(victim, "add", "README.md")
        git(victim, "commit", "--amend", "-q", "-m", "secret baseline")

        attacker = self.make_repo("reftable-attacker")
        external_reftable = victim / ".git/reftable"
        (attacker / ".git/reftable").symlink_to(
            external_reftable, target_is_directory=True
        )
        result = self.adapt(attacker, "external-reftable-out")
        self.assertEqual(result["exact_blocker"], "git_ref_storage_backend_unsupported")
        output = self.root / "external-reftable-out"
        self.assertFalse(output.exists())
        self.assertFalse(result["external_reftable_storage_used"])
        self.assertFalse(result["external_ref_storage_content_packaged"])
        self.assertNotIn(secret.encode(), b"".join(
            path.read_bytes() for path in self.root.rglob("*")
            if path.is_file() and output in path.parents
        ))

    def test_every_reftable_path_object_type_is_rejected(self) -> None:
        for kind in ("directory", "file", "symlink", "hardlink"):
            with self.subTest(kind=kind):
                repo = self.make_repo("reftable-type-" + kind)
                target = repo / ".git/reftable"
                external = self.root / ("external-reftable-" + kind)
                if kind == "directory":
                    target.mkdir()
                elif kind == "file":
                    target.write_bytes(b"unsupported")
                elif kind == "symlink":
                    external.mkdir()
                    target.symlink_to(external, target_is_directory=True)
                else:
                    external.write_bytes(b"unsupported")
                    os.link(external, target)
                result = self.adapt(repo, "reftable-type-out-" + kind)
                self.assertEqual(
                    result["exact_blocker"], "git_ref_storage_backend_unsupported"
                )
                self.assertFalse((self.root / ("reftable-type-out-" + kind)).exists())

    def test_refstorage_case_quoted_and_unknown_extensions_fail_closed(self) -> None:
        cases = {
            "refstorage-lower": (
                "\n[extensions]\n\trefStorage = reftable\n",
                "git_ref_storage_backend_unsupported",
            ),
            "refstorage-case-quoted": (
                "\n[ExTeNsIoNs]\n\tReFsToRaGe = \"ReFtAbLe\"\n",
                "git_ref_storage_backend_unsupported",
            ),
            "refstorage-files": (
                "\n[extensions]\n\trefStorage = files\n",
                "git_ref_storage_backend_unsupported",
            ),
            "compat-object": (
                "\n[extensions]\n\tcompatObjectFormat = sha256\n",
                "repository_extension_unsupported",
            ),
            "unknown-future": (
                "\n[extensions]\n\tfutureRefBackend = surprising\n",
                "repository_extension_unsupported",
            ),
        }
        for name, (config_text, blocker) in cases.items():
            with self.subTest(name=name):
                repo = self.make_repo(name)
                self.append_config(repo, config_text)
                result = self.adapt(repo, name + "-out")
                self.assertEqual(result["exact_blocker"], blocker)
                self.assertFalse((self.root / (name + "-out")).exists())

    def test_reftable_path_introduced_before_acceptance_is_blocked(self) -> None:
        for variant in ("real-directory", "symlink", "restored-absent"):
            with self.subTest(variant=variant):
                repo = self.make_repo("preaccept-reftable-" + variant)
                external = self.root / ("preaccept-external-" + variant)
                external.mkdir()
                (external / "tables.list").write_text("external\n", encoding="utf-8")

                def introduce(_repo: Path) -> None:
                    target = _repo / ".git/reftable"
                    if variant == "real-directory":
                        external.rename(target)
                    elif variant == "symlink":
                        target.symlink_to(external, target_is_directory=True)
                    else:
                        target.mkdir()
                        target.rmdir()

                adapter.STATUS_SNAPSHOT_TEST_HOOK = introduce
                output = "preaccept-reftable-out-" + variant
                result = self.adapt(repo, output)
                self.assertEqual(
                    result["exact_blocker"], "repository_state_changed_before_acceptance"
                )
                self.assertIn(
                    result["pre_acceptance_detail"],
                    {
                        "git_ref_storage_backend_unsupported",
                        "git_metadata_identity_changed",
                    },
                )
                self.assertFalse((self.root / output).exists())
                adapter.STATUS_SNAPSHOT_TEST_HOOK = None

    def test_transient_reftable_and_config_restoration_are_detected(self) -> None:
        for surface in ("reftable", "config"):
            with self.subTest(surface=surface):
                repo = self.make_repo("transient-" + surface)
                config = repo / ".git/config"
                original_config = config.read_bytes()
                state = {"armed": True}

                def race(phase: str, _lease: adapter.GitMetadataLease) -> None:
                    if not state["armed"]:
                        return
                    if phase == "after_pre:rev-parse":
                        if surface == "reftable":
                            (repo / ".git/reftable").mkdir()
                        else:
                            config.write_bytes(
                                original_config
                                + b"\n[extensions]\nrefStorage = reftable\n"
                            )
                    elif phase == "before_post:rev-parse":
                        if surface == "reftable":
                            (repo / ".git/reftable").rmdir()
                        else:
                            config.write_bytes(original_config)
                        state["armed"] = False

                adapter.GIT_METADATA_TEST_HOOK = race
                result = self.adapt(repo, "transient-" + surface + "-out")
                self.assertNotEqual(result["result"], "adapted")
                self.assertIn(
                    result["exact_blocker"],
                    {"git_metadata_identity_changed", "git_ref_storage_backend_unsupported"},
                )
                self.assertFalse((self.root / ("transient-" + surface + "-out")).exists())
                adapter.GIT_METADATA_TEST_HOOK = None

    def test_ref_format_probe_fails_closed_and_exact_old_git_fallback_is_bounded(self) -> None:
        class FakeRunner:
            def __init__(self, output: bytes) -> None:
                self.output = output
                self.calls: list[list[str]] = []

            def run(self, arguments, **_kwargs):
                self.calls.append(list(arguments))
                return self.output

        config = {"ref_storage_extension_absent": True}
        files = FakeRunner(b"files\n")
        proof = adapter._git_ref_storage_backend_snapshot(files, config)
        self.assertEqual(proof["backend"], "files")
        self.assertTrue(proof["probe_supported"])

        old = FakeRunner(b"--show-ref-format\n")
        fallback = adapter._git_ref_storage_backend_snapshot(old, config)
        self.assertEqual(fallback["backend"], "files")
        self.assertFalse(fallback["probe_supported"])

        for unsupported in (b"reftable\n", b"future-backend\n"):
            with self.subTest(unsupported=unsupported), self.assertRaisesRegex(
                adapter.GitAdapterError, "git_ref_storage_backend_unsupported"
            ):
                adapter._git_ref_storage_backend_snapshot(
                    FakeRunner(unsupported), config
                )


if __name__ == "__main__":
    unittest.main()
