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

from clu_governance import source_mutation_demo_runtime as runtime


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SRC = (PACKAGE_ROOT / "src").resolve()
UNSUPPORTED_PLATFORM_BLOCKER = "content_sensitive_git_sandbox_unavailable"


def git(repo: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        [shutil.which("git") or "git", *arguments],
        cwd=repo,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    if completed.returncode:
        raise AssertionError(completed.stderr.decode("utf-8", errors="replace"))
    return completed


def parse_single_json(stdout: str) -> dict[str, object]:
    decoder = json.JSONDecoder()
    payload, end = decoder.raw_decode(stdout)
    if stdout[end:].strip() or not isinstance(payload, dict):
        raise AssertionError("expected exactly one JSON object on stdout")
    return payload


@unittest.skipIf(
    sys.platform == "darwin",
    "unsupported-platform git-adapt contract is exercised on non-macOS platforms",
)
class UnsupportedPlatformGitAdapterContractTest(unittest.TestCase):
    """Ensure unsupported platforms fail closed instead of emulating macOS success."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="clu-git-adapter-platform.")).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "CLU Synthetic Test")
        git(self.repo, "config", "user.email", "synthetic@example.invalid")
        (self.repo / "README.md").write_text("# Demo\n\nBaseline.\n", encoding="utf-8")
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-q", "-m", "baseline")
        (self.repo / "README.md").write_text(
            "# Demo\n\nProposed local edit.\n", encoding="utf-8"
        )
        self.policy = self.root / "policy.json"
        self.policy.write_text(
            json.dumps(runtime.build_demo_policy(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_help_and_attempted_execution_fail_closed_without_mutating_repository(self) -> None:
        environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(PACKAGE_SRC),
        }
        help_result = subprocess.run(
            [sys.executable, "-B", "-m", "clu_governance.cli", "git-adapt", "--help"],
            cwd=PACKAGE_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("EXPERIMENTAL TRUSTED-LOCAL BOUNDARY", help_result.stdout)
        self.assertEqual(help_result.stderr, "")

        before = {
            "head": git(self.repo, "rev-parse", "HEAD").stdout,
            "status": git(
                self.repo, "status", "--porcelain=v2", "-z", "--untracked-files=all"
            ).stdout,
            "index_sha256": hashlib.sha256((self.repo / ".git" / "index").read_bytes()).hexdigest(),
            "readme_sha256": hashlib.sha256((self.repo / "README.md").read_bytes()).hexdigest(),
        }
        output = self.root / "bundle"
        execution = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "clu_governance.cli",
                "git-adapt",
                "--repo",
                str(self.repo),
                "--policy",
                str(self.policy),
                "--declared-actor-id",
                "demo_operator",
                "--scope",
                "docs_only",
                "--output-dir",
                str(output),
                "--event-time",
                "2026-07-11T00:00:00Z",
                "--json",
            ],
            cwd=PACKAGE_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
        )
        self.assertEqual(execution.returncode, 2, execution.stderr or execution.stdout)
        self.assertEqual(execution.stderr, "")
        payload = parse_single_json(execution.stdout)
        self.assertEqual(payload["result"], "blocked")
        self.assertEqual(payload["exact_blocker"], UNSUPPORTED_PLATFORM_BLOCKER)
        self.assertFalse(payload["output_bundle_sealed"])
        self.assertFalse(payload["mutation_applied"])
        self.assertFalse(payload["publication_operation_completed"])
        self.assertEqual(payload["provider_calls"], 0)
        self.assertEqual(payload["advisor_calls"], 0)
        self.assertEqual(payload["mem0_runs"], 0)
        self.assertEqual(payload["benchmark_runs"], 0)
        self.assertEqual(payload["network_calls"], 0)
        self.assertFalse((output / "BUNDLE_COMPLETE.json").exists())

        after = {
            "head": git(self.repo, "rev-parse", "HEAD").stdout,
            "status": git(
                self.repo, "status", "--porcelain=v2", "-z", "--untracked-files=all"
            ).stdout,
            "index_sha256": hashlib.sha256((self.repo / ".git" / "index").read_bytes()).hexdigest(),
            "readme_sha256": hashlib.sha256((self.repo / "README.md").read_bytes()).hexdigest(),
        }
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
