from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clu_governance import cli


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SRC = (PACKAGE_ROOT / "src").resolve()
COMMANDS = (
    "evaluate",
    "verify",
    "verify-bundle",
    "protected-source-manifest",
    "demo-init",
    "demo-approve",
    "demo-execute",
    "demo-run-all",
    "git-adapt",
)


def run_module(*args: str, module: str = "clu_governance.cli") -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(PACKAGE_SRC)
    return subprocess.run(
        [sys.executable, "-B", "-m", module, *args],
        cwd=PACKAGE_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def parse_single_json(stdout: str) -> dict[str, object]:
    decoder = json.JSONDecoder()
    value, end = decoder.raw_decode(stdout)
    if stdout[end:].strip():
        raise AssertionError("stdout contains data after the JSON object")
    if not isinstance(value, dict):
        raise AssertionError("stdout JSON is not an object")
    return value


class PublicCliContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_root = Path(tempfile.mkdtemp(prefix="clu-governance-public-cli-test.")).resolve()
        self.workspace_index = 0

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_root, ignore_errors=True)

    def init_workspace(self) -> tuple[Path, dict[str, object]]:
        self.workspace_index += 1
        workspace = self.temp_root / f"workspace-{self.workspace_index}"
        result = run_module("demo-init", "--workspace", str(workspace), "--json")
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(result.stderr, "")
        payload = parse_single_json(result.stdout)
        self.assertEqual(payload["result"], "ready")
        return workspace, payload

    def allowed_decision(self) -> tuple[Path, dict[str, object], Path]:
        workspace, init = self.init_workspace()
        output = Path(str(init["policy_path"])).parent / "allowed_decision.json"
        result = run_module(
            "evaluate",
            "--policy",
            str(init["policy_path"]),
            "--request",
            str(init["allowed_request_path"]),
            "--source-root",
            str(init["demo_repo"]),
            "--output",
            str(output),
            "--event-time",
            "2026-06-26T00:00:00Z",
            "--json",
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        payload = parse_single_json(result.stdout)
        self.assertEqual(payload["decision"], "allow")
        return workspace, init, output

    def test_version_is_exact_and_uses_package_surface(self) -> None:
        result = run_module("--version")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "clu-governance 0.1.0a1\n")
        self.assertEqual(result.stderr, "")

    def test_top_level_and_all_subcommand_help(self) -> None:
        top = run_module("--help")
        self.assertEqual(top.returncode, 0)
        self.assertIn("local-first", top.stdout)
        self.assertIn("eligible for a separate approval", top.stdout)
        self.assertIn("caller-declared and unauthenticated", top.stdout)
        self.assertIn("--version", top.stdout)
        self.assertNotIn("/" + "Users/", top.stdout)
        for command in COMMANDS:
            result = run_module(command, "--help")
            self.assertEqual(result.returncode, 0, command)
            self.assertIn("local-first", result.stdout.lower(), command)
            self.assertIn("unauthenticated", result.stdout, command)
            self.assertEqual(result.stderr, "", command)

        git_help = run_module("git-adapt", "--help")
        self.assertIn("EXPERIMENTAL TRUSTED-LOCAL BOUNDARY", git_help.stdout)
        self.assertIn("not a sandbox", git_help.stdout)

    def test_demo_json_is_one_object_and_zero_call(self) -> None:
        result = run_module("demo-run-all", "--json")
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(result.stderr, "")
        payload = parse_single_json(result.stdout)
        self.assertEqual(payload["schema_name"], "clu_governance_standalone_demo_run_all.v1")
        self.assertEqual(payload["result"], "passed")
        for key in ("provider_calls", "advisor_calls", "mem0_runs", "benchmark_runs", "network_calls"):
            self.assertEqual(payload[key], 0)

    def test_usage_error_is_stderr_exit_two(self) -> None:
        result = run_module("evaluate")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("usage:", result.stderr)
        self.assertIn("error:", result.stderr)

    def test_denied_evaluate_and_verify_exit_codes(self) -> None:
        _workspace, init = self.init_workspace()
        artifacts = Path(str(init["policy_path"])).parent
        denied_output = artifacts / "denied_decision.json"
        denied = run_module(
            "evaluate",
            "--policy",
            str(init["policy_path"]),
            "--request",
            str(init["denied_request_path"]),
            "--source-root",
            str(init["demo_repo"]),
            "--output",
            str(denied_output),
            "--json",
        )
        self.assertEqual(denied.returncode, 2)
        self.assertEqual(parse_single_json(denied.stdout)["decision"], "deny")
        self.assertEqual(denied.stderr, "")

        _workspace, _init, allowed_output = self.allowed_decision()
        valid = run_module("verify", "--decision", str(allowed_output), "--json")
        self.assertEqual(valid.returncode, 0)
        self.assertIs(parse_single_json(valid.stdout)["verified"], True)

        artifact = json.loads(allowed_output.read_text(encoding="utf-8"))
        artifact["reason_text"] = "tampered"
        allowed_output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        invalid = run_module("verify", "--decision", str(allowed_output), "--json")
        self.assertEqual(invalid.returncode, 2)
        self.assertIs(parse_single_json(invalid.stdout)["verified"], False)

    def test_rejected_approval_records_then_blocks_execution(self) -> None:
        workspace, init, decision = self.allowed_decision()
        approval = Path(str(init["policy_path"])).parent / "rejected_approval.json"
        recorded = run_module(
            "demo-approve",
            "--workspace",
            str(workspace),
            "--decision-artifact",
            str(decision),
            "--approval-output",
            str(approval),
            "--decision",
            "rejected",
            "--json",
        )
        self.assertEqual(recorded.returncode, 0)
        recorded_payload = parse_single_json(recorded.stdout)
        self.assertEqual(recorded_payload["result"], "approval_recorded")
        self.assertEqual(recorded_payload["decision"], "rejected")
        self.assertIs(recorded_payload["approval_identity_authenticated"], False)
        self.assertIs(recorded_payload["human_presence_verified"], False)

        execution = run_module(
            "demo-execute",
            "--workspace",
            str(workspace),
            "--policy",
            str(init["policy_path"]),
            "--request",
            str(init["allowed_request_path"]),
            "--decision-artifact",
            str(decision),
            "--approval",
            str(approval),
            "--source-root",
            str(init["demo_repo"]),
            "--packaged-source-root",
            str(PACKAGE_SRC),
            "--retention-decision",
            "rollback_requested",
            "--json",
        )
        self.assertEqual(execution.returncode, 2)
        execution_payload = parse_single_json(execution.stdout)
        self.assertEqual(execution_payload["result"], "blocked")
        self.assertFalse(execution_payload.get("mutation_was_applied", False))

    def test_historical_module_invocation_remains_compatible(self) -> None:
        result = run_module("demo-run-all", "--json", module="clu_governance.source_mutation_policy_gate")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(parse_single_json(result.stdout)["result"], "passed")

    def test_human_output_is_one_concise_line(self) -> None:
        _workspace, init = self.init_workspace()
        output = Path(str(init["policy_path"])).parent / "human_denied_decision.json"
        result = run_module(
            "evaluate",
            "--policy",
            str(init["policy_path"]),
            "--request",
            str(init["denied_request_path"]),
            "--source-root",
            str(init["demo_repo"]),
            "--output",
            str(output),
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(result.stdout.rstrip("\n").splitlines()), 1)
        self.assertTrue(result.stdout.startswith("decision=deny reason="))

    def test_wrapper_is_thin_delegate(self) -> None:
        with mock.patch.object(cli, "policy_gate_main", return_value=7) as delegated:
            self.assertEqual(cli.main(["verify", "--decision", "x"]), 7)
        delegated.assert_called_once_with(["verify", "--decision", "x"])

    def test_bounded_error_redacts_home_archive_and_token(self) -> None:
        archive_name = "private-release-review.zip"
        token = "gh" + "p_" + "abcdefghijklmnopqrstuv"
        message = f"{Path.home()}/private/{archive_name} {token}"
        bounded = __import__(
            "clu_governance.source_mutation_policy_gate", fromlist=["bounded_cli_error"]
        ).bounded_cli_error(RuntimeError(message))
        self.assertNotIn(str(Path.home()), bounded)
        self.assertNotIn(archive_name, bounded)
        self.assertNotIn("gh" + "p_", bounded)


if __name__ == "__main__":
    unittest.main()
