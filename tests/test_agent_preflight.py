from __future__ import annotations

import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clu_governance import agent_preflight
from clu_governance.source_mutation_policy_gate import demo_init, source_tree_hash


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SRC = ROOT / "src"


def parse_single_json(text: str) -> dict[str, object]:
    decoder = json.JSONDecoder()
    value, end = decoder.raw_decode(text)
    if text[end:].strip():
        raise AssertionError("stdout contains data after the JSON object")
    if not isinstance(value, dict):
        raise AssertionError("stdout JSON is not an object")
    return value


class AgentPreflightContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_root = Path(tempfile.mkdtemp(prefix="clu-governance-agent-preflight-test.")).resolve()
        self.workspace = self.temp_root / "workspace"
        self.init = demo_init(self.workspace, reset=True)
        self.assertEqual(self.init["result"], "ready")
        self.policy_path = Path(str(self.init["policy_path"]))
        self.artifacts = self.policy_path.parent
        self.demo_repo = Path(str(self.init["demo_repo"]))

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_root, ignore_errors=True)

    def envelope(self, *, request_key: str = "allowed_request_path") -> dict[str, object]:
        return {
            "schema_name": agent_preflight.INPUT_SCHEMA_NAME,
            "schema_version": agent_preflight.SCHEMA_VERSION,
            "policy_path": str(self.policy_path),
            "request_path": str(self.init[request_key]),
            "source_root": str(self.demo_repo),
            "event_timestamp": "2026-07-12T00:00:00Z",
            "sequence_index": 11,
        }

    def invoke_cli(self, document: str, *args: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(PACKAGE_SRC)
        return subprocess.run(
            [sys.executable, "-B", "-m", "clu_governance.cli", "agent-preflight", *args],
            cwd=ROOT,
            env=environment,
            input=document,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_allowed_direct_evaluation_is_read_only_and_has_existing_evidence(self) -> None:
        before_tree_hash = source_tree_hash(self.demo_repo)
        before_workspace = sorted(path.relative_to(self.temp_root).as_posix() for path in self.temp_root.rglob("*"))

        with (
            mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess forbidden")),
            mock.patch("socket.create_connection", side_effect=AssertionError("network forbidden")),
        ):
            exit_code, payload = agent_preflight.run(json.dumps(self.envelope(), sort_keys=True))

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["schema_name"], "clu_governance_source_mutation_policy_decision.v1")
        self.assertEqual(payload["decision"], "allow")
        self.assertEqual(payload["reason_code"], "eligible_for_human_approval")
        self.assertIs(payload["eligible_for_human_approval"], True)
        self.assertIs(payload["operator_approval_required"], True)
        self.assertIs(payload["mutation_authorized"], False)
        self.assertIs(payload["mutation_applied"], False)
        self.assertIs(payload["rollback_readiness_verified"], True)
        self.assertTrue(payload["policy_hash"])
        self.assertTrue(payload["canonical_request_hash"])
        self.assertTrue(payload["proposal_hash_verified"])
        self.assertTrue(payload["source_hash_verified"])
        self.assertEqual(payload["network_calls"], 0)
        self.assertEqual(payload["provider_calls"], 0)
        self.assertEqual(payload["advisor_calls"], 0)
        self.assertEqual(payload["mem0_runs"], 0)
        self.assertEqual(payload["benchmark_runs"], 0)
        self.assertEqual(before_tree_hash, source_tree_hash(self.demo_repo))
        self.assertEqual(
            before_workspace,
            sorted(path.relative_to(self.temp_root).as_posix() for path in self.temp_root.rglob("*")),
        )

    def test_cli_stdout_is_one_json_object_and_allow_remains_separate_from_approval(self) -> None:
        result = self.invoke_cli(json.dumps(self.envelope()), "--json")

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(result.stderr, "")
        payload = parse_single_json(result.stdout)
        self.assertEqual(payload["decision"], "allow")
        self.assertIs(payload["eligible_for_human_approval"], True)
        self.assertIs(payload["operator_approval_required"], True)
        self.assertIs(payload["mutation_authorized"], False)
        self.assertIs(payload["mutation_applied"], False)
        self.assertFalse((self.artifacts / "approval.json").exists())

    def test_denied_envelope_returns_policy_evidence_and_exit_two(self) -> None:
        result = self.invoke_cli(json.dumps(self.envelope(request_key="denied_request_path")))

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "")
        payload = parse_single_json(result.stdout)
        self.assertEqual(payload["decision"], "deny")
        self.assertEqual(payload["exact_blocker"], "delete_operation_denied")
        self.assertIs(payload["eligible_for_human_approval"], False)
        self.assertIs(payload["mutation_authorized"], False)
        self.assertIs(payload["mutation_applied"], False)

    def test_malformed_and_contract_invalid_input_exit_one_with_bounded_error(self) -> None:
        valid = self.envelope()
        malformed_cases = {
            "malformed_json": ("{", "agent_preflight_input_malformed_json"),
            "duplicate_key": (
                '{"schema_name":"clu_governance_agent_preflight_input.v1",'
                '"schema_name":"clu_governance_agent_preflight_input.v1"}',
                "agent_preflight_input_duplicate_json_key",
            ),
            "trailing_input": (json.dumps(valid) + "\n{}", "agent_preflight_input_malformed_json"),
            "missing_field": (
                json.dumps({key: value for key, value in valid.items() if key != "request_path"}),
                "agent_preflight_input_required_field_missing",
            ),
            "unknown_field": (json.dumps({**valid, "unexpected": True}), "agent_preflight_input_unknown_field"),
            "wrong_field_type": (json.dumps({**valid, "sequence_index": "11"}), "agent_preflight_input_sequence_index_invalid"),
        }
        for case, (document, blocker) in malformed_cases.items():
            with self.subTest(case=case):
                result = self.invoke_cli(document)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, "")
                payload = parse_single_json(result.stdout)
                self.assertEqual(payload["schema_name"], agent_preflight.ERROR_SCHEMA_NAME)
                self.assertEqual(payload["result"], "input_rejected")
                self.assertEqual(payload["exact_blocker"], blocker)
                self.assertIs(payload["mutation_authorized"], False)
                self.assertIs(payload["mutation_applied"], False)
                self.assertIs(payload["agent_subprocess_started"], False)
                self.assertEqual(payload["network_calls"], 0)

    def test_bounded_local_evaluation_failure_is_distinct_from_policy_denial(self) -> None:
        result = self.invoke_cli(json.dumps({**self.envelope(), "source_root": str(self.temp_root / "missing")}))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        payload = parse_single_json(result.stdout)
        self.assertEqual(payload["schema_name"], agent_preflight.ERROR_SCHEMA_NAME)
        self.assertEqual(payload["result"], "failed")
        self.assertEqual(payload["exact_blocker"], "agent_preflight_evaluation_failed")
        self.assertIs(payload["mutation_authorized"], False)
        self.assertIs(payload["mutation_applied"], False)

    def test_shell_pattern_blocks_a_later_command_on_deny_without_clu_running_it(self) -> None:
        denied_input = self.temp_root / "denied-envelope.json"
        denied_input.write_text(json.dumps(self.envelope(request_key="denied_request_path")), encoding="utf-8")
        later_command_marker = self.temp_root / "later-command-ran"
        command = (
            f"if {shlex.quote(sys.executable)} -B -m clu_governance.cli agent-preflight --json "
            f"< {shlex.quote(str(denied_input))}; then "
            f"printf later-command-ran > {shlex.quote(str(later_command_marker))}; fi; "
            f"test ! -e {shlex.quote(str(later_command_marker))}"
        )
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(PACKAGE_SRC)

        result = subprocess.run(
            ["/bin/sh", "-c", command],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertFalse(later_command_marker.exists())


if __name__ == "__main__":
    unittest.main()
