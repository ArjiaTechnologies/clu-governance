from __future__ import annotations

import io
import inspect
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clu_governance import agent_preflight, claude_code_pretooluse
from clu_governance.source_mutation_demo_runtime import build_demo_policy
from clu_governance.source_mutation_policy_gate import source_tree_hash


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SRC = ROOT / "src"


def parse_single_json(text: str) -> dict[str, object]:
    decoder = json.JSONDecoder()
    payload, end = decoder.raw_decode(text)
    if text[end:].strip():
        raise AssertionError("stdout contains data after the JSON object")
    if not isinstance(payload, dict):
        raise AssertionError("stdout did not contain a JSON object")
    return payload


class ClaudeCodePreToolUseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_root = Path(tempfile.mkdtemp(prefix="clu-governance-claude-pretooluse-test.")).resolve()
        self.project = self.temp_root / "project"
        self.project.mkdir()
        self.target = self.project / "README.md"
        self.target.write_text("# Example\n\nOriginal line.\n", encoding="utf-8")
        policy = build_demo_policy()
        policy["allowed_declared_actor_ids"] = [claude_code_pretooluse.DECLARED_ACTOR_ID]
        policy["allowed_scopes"] = [claude_code_pretooluse.REQUESTED_SCOPE]
        self.policy_path = self.temp_root / "policy.json"
        self.policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_root, ignore_errors=True)

    def hook_input(
        self,
        *,
        tool_name: str = "Edit",
        file_path: Path | None = None,
        old_string: str = "Original line.",
        new_string: str = "Updated line.",
        replace_all: bool = False,
    ) -> dict[str, object]:
        return {
            "session_id": "fixture-session",
            "transcript_path": "/tmp/fixture-transcript.jsonl",
            "cwd": str(self.project),
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_use_id": "toolu_fixture",
            "tool_input": {
                "file_path": str(file_path or self.target),
                "old_string": old_string,
                "new_string": new_string,
                "replace_all": replace_all,
            },
        }

    def invoke_cli(self, document: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(PACKAGE_SRC)
        return subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "clu_governance.cli",
                "claude-pretooluse",
                "--policy",
                str(self.policy_path),
            ],
            cwd=ROOT,
            env=environment,
            input=document,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def assert_hook_decision(self, payload: dict[str, object], decision: str) -> str:
        hook = payload.get("hookSpecificOutput")
        self.assertIsInstance(hook, dict)
        assert isinstance(hook, dict)
        self.assertEqual(hook.get("hookEventName"), "PreToolUse")
        self.assertEqual(hook.get("permissionDecision"), decision)
        reason = hook.get("permissionDecisionReason")
        self.assertIsInstance(reason, str)
        return str(reason)

    def test_supported_edit_allow_maps_to_ask_and_leaves_no_residual_state(self) -> None:
        before_source = source_tree_hash(self.project)
        before_entries = sorted(path.relative_to(self.temp_root).as_posix() for path in self.temp_root.rglob("*"))
        with (
            mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess forbidden")),
            mock.patch("socket.create_connection", side_effect=AssertionError("network forbidden")),
        ):
            exit_code, payload = claude_code_pretooluse.run(
                json.dumps(self.hook_input(), sort_keys=True),
                policy_path=self.policy_path,
                temporary_parent=self.temp_root,
            )

        self.assertEqual(exit_code, 0)
        reason = self.assert_hook_decision(payload, "ask")
        self.assertIn("eligible for separate approval", reason)
        self.assertIn("not an automatic permission approval", reason)
        self.assertNotIn("permissionDecision\": \"allow", json.dumps(payload))
        self.assertEqual(before_source, source_tree_hash(self.project))
        self.assertEqual(before_entries, sorted(path.relative_to(self.temp_root).as_posix() for path in self.temp_root.rglob("*")))
        self.assertEqual(list(self.temp_root.glob("clu-governance-claude-pretooluse-*")), [])

    def test_cli_writes_one_json_object_and_no_stderr(self) -> None:
        result = self.invoke_cli(json.dumps(self.hook_input()))

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(result.stderr, "")
        self.assert_hook_decision(parse_single_json(result.stdout), "ask")

    def test_policy_denial_returns_documented_hook_deny_shape(self) -> None:
        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        policy["allowed_paths"] = []
        policy["allowed_path_globs"] = []
        self.policy_path.write_text(json.dumps(policy), encoding="utf-8")

        exit_code, payload = claude_code_pretooluse.run(
            json.dumps(self.hook_input()), policy_path=self.policy_path, temporary_parent=self.temp_root
        )

        self.assertEqual(exit_code, 0)
        reason = self.assert_hook_decision(payload, "deny")
        self.assertIn("blocker: path_not_explicitly_allowed", reason)
        self.assertIn("Next step:", reason)

    def test_malformed_duplicate_and_missing_hook_input_fail_closed(self) -> None:
        missing_cwd = self.hook_input()
        missing_cwd.pop("cwd")
        cases = {
            "malformed": ("{", "claude_pretooluse_input_malformed_json"),
            "duplicate": (
                '{"hook_event_name":"PreToolUse","hook_event_name":"PreToolUse"}',
                "claude_pretooluse_input_duplicate_json_key",
            ),
            "missing": (json.dumps(missing_cwd), "claude_pretooluse_cwd_missing_or_invalid"),
        }
        for name, (document, blocker) in cases.items():
            with self.subTest(name=name):
                result = self.invoke_cli(document)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stderr, "")
                reason = self.assert_hook_decision(parse_single_json(result.stdout), "deny")
                self.assertIn(f"blocker: {blocker}", reason)

    def test_unsupported_tool_is_explicitly_not_governed_by_the_edit_matcher(self) -> None:
        result = self.invoke_cli(json.dumps(self.hook_input(tool_name="Bash")))

        self.assertEqual(result.returncode, 0)
        reason = self.assert_hook_decision(parse_single_json(result.stdout), "ask")
        self.assertIn("supports Edit only", reason)
        self.assertIn("normal permission flow", reason)

    def test_missing_policy_and_source_state_mismatch_fail_closed(self) -> None:
        missing_policy = self.temp_root / "missing-policy.json"
        exit_code, payload = claude_code_pretooluse.run(
            json.dumps(self.hook_input()), policy_path=missing_policy, temporary_parent=self.temp_root
        )
        self.assertEqual(exit_code, 0)
        self.assertIn("blocker: policy_missing", self.assert_hook_decision(payload, "deny"))

        exit_code, payload = claude_code_pretooluse.run(
            json.dumps(self.hook_input(old_string="does not match the current source")),
            policy_path=self.policy_path,
            temporary_parent=self.temp_root,
        )
        self.assertEqual(exit_code, 0)
        self.assertIn("blocker: claude_edit_old_string_not_found", self.assert_hook_decision(payload, "deny"))

    def test_rollback_readiness_denial_from_generic_contract_remains_a_deny(self) -> None:
        generic_denial = {
            "decision": "deny",
            "exact_blocker": "rollback_artifact_hash_mismatch",
            "mutation_applied": False,
        }
        with mock.patch.object(agent_preflight, "run", return_value=(2, generic_denial)) as delegated:
            exit_code, payload = claude_code_pretooluse.run(
                json.dumps(self.hook_input()), policy_path=self.policy_path, temporary_parent=self.temp_root
            )

        self.assertEqual(exit_code, 0)
        self.assertIn("blocker: rollback_artifact_hash_mismatch", self.assert_hook_decision(payload, "deny"))
        delegated.assert_called_once()

    def test_adapter_delegates_to_generic_contract_and_contains_no_policy_engine(self) -> None:
        source = inspect.getsource(claude_code_pretooluse)
        self.assertIn("agent_preflight.run(", source)
        self.assertNotIn("evaluate_source_mutation_request", source)
        self.assertNotIn("validate_policy(", source)
        self.assertNotIn("first_matching_rule(", source)

        with mock.patch.object(
            agent_preflight,
            "run",
            return_value=(0, {"decision": "allow", "exact_blocker": None}),
        ) as delegated:
            exit_code, payload = claude_code_pretooluse.run(
                json.dumps(self.hook_input()), policy_path=self.policy_path, temporary_parent=self.temp_root
            )

        self.assertEqual(exit_code, 0)
        self.assert_hook_decision(payload, "ask")
        envelope = json.loads(delegated.call_args.args[0])
        self.assertEqual(envelope["schema_name"], agent_preflight.INPUT_SCHEMA_NAME)
        self.assertEqual(envelope["policy_path"], str(self.policy_path))
        self.assertEqual(envelope["source_root"], str(self.project))
        self.assertTrue(Path(str(envelope["request_path"])).is_absolute())

    def test_replace_all_and_symlinked_target_are_rejected_without_mutation(self) -> None:
        linked_target = self._make_symlink_target()
        before = source_tree_hash(self.project)
        for name, document, blocker in (
            ("replace_all", self.hook_input(replace_all=True), "claude_edit_replace_all_unsupported"),
            ("symlink", self.hook_input(file_path=linked_target), "claude_edit_target_symlink_denied"),
        ):
            with self.subTest(name=name):
                exit_code, payload = claude_code_pretooluse.run(
                    json.dumps(document), policy_path=self.policy_path, temporary_parent=self.temp_root
                )
                self.assertEqual(exit_code, 0)
                self.assertIn(f"blocker: {blocker}", self.assert_hook_decision(payload, "deny"))
        self.assertEqual(before, source_tree_hash(self.project))

    def _make_symlink_target(self) -> Path:
        link = self.project / "linked-readme.md"
        if not link.exists() and not link.is_symlink():
            link.symlink_to(self.target)
        return link

    def test_documented_setup_disable_uninstall_and_linux_contract_are_present(self) -> None:
        documentation = (ROOT / "docs/claude-code-pretooluse.md").read_text(encoding="utf-8")
        settings = ROOT / "examples/claude-code-pretooluse/.claude/settings.local.json"
        for marker in (
            "Ubuntu Linux",
            "x86_64",
            "Python 3.12",
            "disable",
            "uninstall",
            "no daemon",
            "no global cache",
            "zero residual",
            "permissionDecision: \"ask\"",
        ):
            self.assertIn(marker, documentation)
        self.assertTrue(settings.is_file())
        self.assertEqual(json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]["matcher"], "Edit")

    def test_committed_project_local_exec_hook_runs_and_uninstalls_cleanly(self) -> None:
        example_root = ROOT / "examples/claude-code-pretooluse/.claude"
        settings_document = json.loads((example_root / "settings.local.json").read_text(encoding="utf-8"))
        expected_settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Edit",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "${CLAUDE_PROJECT_DIR}/.claude/clu-governance-venv/bin/clu-governance",
                                "args": [
                                    "claude-pretooluse",
                                    "--policy",
                                    "${CLAUDE_PROJECT_DIR}/.claude/clu-governance-policy.json",
                                ],
                                "timeout": 30,
                            }
                        ],
                    }
                ]
            }
        }
        self.assertEqual(settings_document, expected_settings)
        handler = settings_document["hooks"]["PreToolUse"][0]["hooks"][0]
        assert isinstance(handler, dict)
        command = handler["command"]
        arguments = handler["args"]
        self.assertIsInstance(command, str)
        self.assertIsInstance(arguments, list)
        self.assertNotIn(" ", command)
        for value in [command, *arguments]:
            self.assertIsInstance(value, str)
            self.assertNotRegex(str(value), r"[|;&><`]")

        claude_directory = self.project / ".claude"
        claude_directory.mkdir()
        shutil.copyfile(example_root / "settings.local.json", claude_directory / "settings.local.json")
        shutil.copyfile(example_root / "clu-governance-policy.json", claude_directory / "clu-governance-policy.json")
        environment = dict(os.environ)
        environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
        environment["PIP_NO_INPUT"] = "1"
        environment["PIP_NO_CACHE_DIR"] = "1"
        virtual_environment = claude_directory / "clu-governance-venv"
        candidate_copy = self.temp_root / "candidate"
        shutil.copytree(
            ROOT,
            candidate_copy,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "*.egg-info", "build", "dist"),
        )
        subprocess.run([sys.executable, "-m", "venv", str(virtual_environment)], check=True, capture_output=True, text=True)
        virtual_python = virtual_environment / "bin/python"
        installation = subprocess.run(
            [str(virtual_python), "-m", "pip", "install", "--no-deps", "--no-cache-dir", str(candidate_copy)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(installation.returncode, 0, installation.stderr or installation.stdout)

        expanded_command = str(command).replace("${CLAUDE_PROJECT_DIR}", str(self.project))
        expanded_arguments = [str(value).replace("${CLAUDE_PROJECT_DIR}", str(self.project)) for value in arguments]
        allowed = subprocess.run(
            [expanded_command, *expanded_arguments],
            cwd=self.project,
            input=json.dumps(self.hook_input()),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(allowed.returncode, 0, allowed.stderr or allowed.stdout)
        self.assertEqual(allowed.stderr, "")
        self.assert_hook_decision(parse_single_json(allowed.stdout), "ask")

        (self.project / "notes.txt").write_text("Not governed by the sample policy.\n", encoding="utf-8")
        denied = self.hook_input(
            file_path=self.project / "notes.txt",
            old_string="Not governed by the sample policy.",
            new_string="Still not governed by the sample policy.",
        )
        denied_result = subprocess.run(
            [expanded_command, *expanded_arguments],
            cwd=self.project,
            input=json.dumps(denied),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(denied_result.returncode, 0, denied_result.stderr or denied_result.stdout)
        self.assertEqual(denied_result.stderr, "")
        self.assertIn("blocker: path_not_explicitly_allowed", self.assert_hook_decision(parse_single_json(denied_result.stdout), "deny"))

        shutil.rmtree(virtual_environment)
        (claude_directory / "settings.local.json").unlink()
        (claude_directory / "clu-governance-policy.json").unlink()
        claude_directory.rmdir()
        self.assertFalse(claude_directory.exists())
        self.assertFalse((self.project / ".claude").exists())


if __name__ == "__main__":
    unittest.main()
