from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from clu_governance import git_diff_adapter as adapter
from clu_governance import source_mutation_demo_runtime as runtime
from clu_governance import source_mutation_policy_gate as gate
from clu_governance import strict_json


FIXED_TIME = "2026-06-26T00:00:00Z"


def _write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _duplicate_same_line(path: Path, line: str) -> None:
    document = path.read_text(encoding="utf-8")
    if document.count(line) != 1:
        raise AssertionError(f"fixture line count changed: {line!r}")
    path.write_text(document.replace(line, line + line, 1), encoding="utf-8")


class StrictJSONBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="clu-strict-json-test.")).resolve()

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _demo(self, name: str) -> dict[str, object]:
        result = runtime.demo_init(self.root / name)
        self.assertEqual(result["result"], "ready")
        return result

    def test_loader_preserves_valid_json_and_rejects_nested_duplicates(self) -> None:
        document = (
            '{"outer":{"first":1,"second":[true,null,1.25]},'
            '"name":"demo","literal":"[[{{"}'
        )
        self.assertEqual(strict_json.loads(document), json.loads(document))
        with self.assertRaisesRegex(strict_json.DuplicateJSONKeyError, "duplicate_json_key"):
            strict_json.loads('{"outer":{"same":"value","same":"value"}}')
        with self.assertRaises(json.JSONDecodeError):
            strict_json.loads('{"missing":')

    def test_non_finite_numbers_are_bounded_json_errors(self) -> None:
        for document in ("NaN", "Infinity", "-Infinity", "[1e999]", "[-1e999]"):
            with self.subTest(document=document):
                with self.assertRaises(strict_json.NonFiniteJSONNumberError) as caught:
                    strict_json.loads(document)
                self.assertIsInstance(caught.exception, json.JSONDecodeError)
                self.assertEqual(caught.exception.doc, "")
                self.assertEqual(caught.exception.pos, 0)
                self.assertLess(len(str(caught.exception)), 100)

    def test_excessive_nesting_is_bounded_json_error(self) -> None:
        limit = strict_json.MAX_JSON_NESTING_DEPTH
        accepted = "[" * limit + "0" + "]" * limit
        self.assertIsInstance(strict_json.loads(accepted), list)
        for depth in (limit + 1, 5000):
            with self.subTest(depth=depth):
                document = "[" * depth + "0" + "]" * depth
                with self.assertRaises(strict_json.JSONNestingDepthError) as caught:
                    strict_json.loads(document)
                self.assertIsInstance(caught.exception, json.JSONDecodeError)
                self.assertEqual(caught.exception.doc, "")
                self.assertEqual(caught.exception.pos, 0)
                self.assertLess(len(str(caught.exception)), 100)

    def test_unicode_surrogate_pairs_normalize_and_lone_surrogates_block(self) -> None:
        self.assertEqual(strict_json.loads(r'"\ud83d\ude00"'), "😀")
        for document in (r'{"outer":["\ud800"]}', r'{"key":"\udc00"}'):
            with self.subTest(document=document):
                with self.assertRaises(strict_json.InvalidUnicodeJSONError):
                    strict_json.loads(document)
        with self.assertRaises(strict_json.DuplicateJSONKeyError):
            strict_json.loads(r'{"\ud83d\ude00":1,"😀":2}')

    def test_policy_and_request_duplicate_members_fail_closed(self) -> None:
        policy_demo = self._demo("policy-workspace")
        policy_path = Path(str(policy_demo["policy_path"]))
        _duplicate_same_line(policy_path, '  "default_decision": "deny",\n')
        policy_result = gate.evaluate_source_mutation_request(
            policy_path=policy_path,
            request_path=Path(str(policy_demo["allowed_request_path"])),
            source_root=Path(str(policy_demo["demo_repo"])),
            event_timestamp=FIXED_TIME,
        )
        self.assertEqual(policy_result["decision"], "deny")
        self.assertEqual(policy_result["exact_blocker"], "policy_malformed_json")

        request_demo = self._demo("request-workspace")
        request_path = Path(str(request_demo["allowed_request_path"]))
        _duplicate_same_line(request_path, '  "requested_scope": "docs_only",\n')
        request_result = gate.evaluate_source_mutation_request(
            policy_path=Path(str(request_demo["policy_path"])),
            request_path=request_path,
            source_root=Path(str(request_demo["demo_repo"])),
            event_timestamp=FIXED_TIME,
        )
        self.assertEqual(request_result["decision"], "deny")
        self.assertEqual(request_result["exact_blocker"], "request_malformed_json")

    def test_rollback_duplicate_member_fails_before_semantic_use(self) -> None:
        demo = self._demo("rollback-workspace")
        rollback_path = Path(str(demo["rollback_snapshot_path"]))
        _duplicate_same_line(rollback_path, '      "content_encoding": "utf-8",\n')
        request_path = Path(str(demo["allowed_request_path"]))
        request = json.loads(request_path.read_text(encoding="utf-8"))
        request["rollback_readiness"]["artifact_sha256"] = gate.sha256_file(rollback_path)
        _write_json(request_path, request)
        result = gate.evaluate_source_mutation_request(
            policy_path=Path(str(demo["policy_path"])),
            request_path=request_path,
            source_root=Path(str(demo["demo_repo"])),
            event_timestamp=FIXED_TIME,
        )
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["exact_blocker"], "rollback_artifact_malformed_json")

    def test_decision_and_approval_verifiers_reject_same_value_duplicates(self) -> None:
        demo = self._demo("verifier-workspace")
        decision = gate.evaluate_source_mutation_request(
            policy_path=Path(str(demo["policy_path"])),
            request_path=Path(str(demo["allowed_request_path"])),
            source_root=Path(str(demo["demo_repo"])),
            event_timestamp=FIXED_TIME,
        )
        self.assertEqual(decision["decision"], "allow")
        decision_path = _write_json(self.root / "decision.json", decision)
        self.assertIs(gate.verify_decision_artifact(decision_path)["verified"], True)
        _duplicate_same_line(decision_path, '  "decision": "allow",\n')
        decision_verification = gate.verify_decision_artifact(decision_path)
        self.assertIs(decision_verification["verified"], False)
        self.assertEqual(
            decision_verification["exact_blocker"],
            "decision_read_failed:duplicate_json_key: line 1 column 1 (char 0)",
        )

        approval = {
            "schema_name": gate.APPROVAL_SCHEMA_NAME,
            "schema_version": "1",
            "approved": True,
        }
        approval["approval_artifact_hash"] = gate.payload_integrity_hash(
            approval, "approval_artifact_hash"
        )
        approval_path = _write_json(self.root / "approval.json", approval)
        self.assertIs(runtime.verify_approval_artifact(approval_path)["verified"], True)
        _duplicate_same_line(approval_path, '  "approved": true,\n')
        approval_verification = runtime.verify_approval_artifact(approval_path)
        self.assertIs(approval_verification["verified"], False)
        self.assertEqual(
            approval_verification["exact_blocker"],
            "approval_read_failed:duplicate_json_key: line 1 column 1 (char 0)",
        )

    def test_adapter_owned_artifact_reader_rejects_duplicate_members(self) -> None:
        class FakeOwned:
            @staticmethod
            def read_expected_file(_relative: str) -> bytes:
                return b'{"schema_name":"same","schema_name":"same"}'

        with self.assertRaisesRegex(
            adapter.GitAdapterError,
            "generated_policy_decision_genuine_artifact_binding_failed",
        ):
            adapter._read_owned_json(FakeOwned(), "source_mutation_request.json")

    def test_completion_record_duplicate_member_blocks_publication(self) -> None:
        class FakeOwned:
            @staticmethod
            def read_expected_file(relative: str) -> bytes:
                if relative != "BUNDLE_COMPLETE.json":
                    raise AssertionError(relative)
                return b'{"bundle_complete":true,"bundle_complete":true}'

        with self.assertRaisesRegex(
            adapter.GitAdapterError,
            "output_bundle_completion_record_invalid",
        ):
            adapter._read_owned_completion_json(FakeOwned())


if __name__ == "__main__":
    unittest.main()
