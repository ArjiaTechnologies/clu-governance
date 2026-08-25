from __future__ import annotations

import copy
import hashlib
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

from clu_governance import evidence_envelope
from clu_governance.source_mutation_policy_gate import (
    canonical_json,
    canonical_sha256,
    demo_init,
    evaluate_source_mutation_request,
    source_tree_hash,
)


ROOT = Path(__file__).resolve().parents[1]


class EvidenceEnvelopeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="clu-governance-evidence-test.")).resolve()
        self.init = demo_init(self.root / "workspace", reset=True)
        self.assertEqual(self.init["result"], "ready")
        self.source = Path(str(self.init["demo_repo"]))

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def decision(self, *, denied: bool = False) -> dict[str, object]:
        return evaluate_source_mutation_request(
            policy_path=Path(str(self.init["policy_path"])),
            request_path=Path(str(self.init["denied_request_path" if denied else "allowed_request_path"])),
            source_root=self.source,
            event_timestamp="2026-08-25T00:00:00Z",
            sequence_index=7,
        )

    def run_cli(self, command: str, value: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT / "src"))
        return subprocess.run(
            [sys.executable, "-B", "-m", "clu_governance.cli", command, "--json"],
            cwd=ROOT,
            env=environment,
            input=value,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    @staticmethod
    def rehash_decision(decision: dict[str, object]) -> None:
        decision["audit_event_hash"] = canonical_sha256(
            {key: value for key, value in decision.items() if key != "audit_event_hash"}
        )

    @staticmethod
    def rehash_envelope(envelope: dict[str, object]) -> None:
        envelope["body_sha256"] = hashlib.sha256(
            evidence_envelope.HASH_DOMAIN + canonical_json(envelope["body"]).encode("utf-8")
        ).hexdigest()

    def test_allow_binds_all_artifacts_offline_without_mutation_or_approval(self) -> None:
        decision = self.decision()
        before_hash = source_tree_hash(self.source)
        before_files = sorted(path.relative_to(self.root).as_posix() for path in self.root.rglob("*"))
        with (
            mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess forbidden")),
            mock.patch("socket.create_connection", side_effect=AssertionError("network forbidden")),
        ):
            envelope = evidence_envelope.build_envelope(decision)
            result = evidence_envelope.verify_envelope(envelope)

        binding = envelope["body"]["artifact_binding"]
        self.assertEqual(binding["policy_sha256"], decision["policy_hash"])
        self.assertEqual(binding["request_sha256"], decision["canonical_request_hash"])
        self.assertEqual(binding["proposal_sha256"], decision["proposal_hash_verified"])
        self.assertEqual(binding["source_tree_sha256"], decision["source_hash_verified"])
        self.assertEqual(binding["audit_event_sha256"], decision["audit_event_hash"])
        self.assertEqual(binding["execution_binding_sha256"], decision["execution_binding_hash"])
        self.assertEqual(binding["rollback_artifact_sha256"], decision["execution_binding"]["rollback_artifact_hash"])
        self.assertTrue(result["verified"])
        self.assertTrue(result["artifact_binding_verified"])
        for field in (
            "approval_recorded",
            "mutation_authorized",
            "mutation_applied",
            "signature_verified",
            "signer_identity_verified",
            "timestamp_witnessed",
            "storage_immutable",
        ):
            self.assertIs(result[field], False, field)
        self.assertEqual(result["network_calls"], 0)
        self.assertEqual(before_hash, source_tree_hash(self.source))
        self.assertEqual(before_files, sorted(path.relative_to(self.root).as_posix() for path in self.root.rglob("*")))

    def test_deny_round_trips_without_execution_or_approval(self) -> None:
        envelope = evidence_envelope.build_envelope(self.decision(denied=True))
        result = evidence_envelope.verify_envelope(envelope)
        self.assertTrue(result["verified"])
        self.assertEqual(result["decision"], "deny")
        self.assertIsNone(envelope["body"]["artifact_binding"]["execution_binding_sha256"])
        self.assertIsNone(envelope["body"]["artifact_binding"]["rollback_artifact_sha256"])
        self.assertIs(envelope["body"]["approval_boundary"]["eligible_for_human_approval"], False)

    def test_identical_evidence_is_reproducible_and_domain_separated(self) -> None:
        decision = self.decision()
        first = evidence_envelope.build_envelope(decision)
        second = evidence_envelope.build_envelope(copy.deepcopy(decision))
        self.assertEqual(first, second)
        self.assertNotEqual(first["body_sha256"], canonical_sha256(first["body"]))

    def test_cli_emits_one_object_and_verifies_offline(self) -> None:
        built = self.run_cli("evidence-envelope", json.dumps(self.decision()))
        self.assertEqual(built.returncode, 0, built.stderr or built.stdout)
        self.assertEqual(built.stderr, "")
        envelope = json.loads(built.stdout)
        self.assertEqual(envelope["schema_name"], evidence_envelope.ENVELOPE_SCHEMA_NAME)
        verified = self.run_cli("verify-evidence-envelope", built.stdout)
        self.assertEqual(verified.returncode, 0, verified.stderr or verified.stdout)
        self.assertEqual(verified.stderr, "")
        self.assertTrue(json.loads(verified.stdout)["verified"])

    def test_duplicate_malformed_nonfinite_and_trailing_json_fail_closed(self) -> None:
        for document in ('{"body":1,"body":2}', "{", '{"value":NaN}', "{}\n{}"):
            with self.subTest(document=document):
                build_code, build_result = evidence_envelope.run(document)
                verify_code, verify_result = evidence_envelope.run(document, verify=True)
                self.assertEqual(build_code, 1)
                self.assertEqual(verify_code, 2)
                self.assertFalse(build_result["verified"])
                self.assertFalse(verify_result["verified"])

    def test_tampered_body_without_rehash_is_rejected(self) -> None:
        envelope = evidence_envelope.build_envelope(self.decision())
        envelope["body"]["decision"]["reason_text"] = "tampered"
        with self.assertRaisesRegex(evidence_envelope.EvidenceEnvelopeError, "body_hash_mismatch"):
            evidence_envelope.verify_envelope(envelope)

    def test_tampered_decision_with_rehashed_outer_body_is_rejected(self) -> None:
        envelope = evidence_envelope.build_envelope(self.decision())
        envelope["body"]["decision"]["reason_text"] = "tampered"
        self.rehash_envelope(envelope)
        with self.assertRaisesRegex(evidence_envelope.EvidenceEnvelopeError, "decision_audit_hash_mismatch"):
            evidence_envelope.verify_envelope(envelope)

    def test_swapped_artifact_binding_with_rehashed_outer_body_is_rejected(self) -> None:
        for field in ("policy_sha256", "request_sha256", "proposal_sha256", "source_tree_sha256", "audit_event_sha256", "execution_binding_sha256", "rollback_artifact_sha256"):
            with self.subTest(field=field):
                envelope = evidence_envelope.build_envelope(self.decision())
                envelope["body"]["artifact_binding"][field] = "f" * 64
                self.rehash_envelope(envelope)
                with self.assertRaisesRegex(evidence_envelope.EvidenceEnvelopeError, "artifact_binding_mismatch"):
                    evidence_envelope.verify_envelope(envelope)

    def test_forged_approval_and_attestation_claims_are_rejected_after_rehash(self) -> None:
        for section, field in (
            ("approval_boundary", "approval_recorded"),
            ("approval_boundary", "mutation_authorized"),
            ("approval_boundary", "mutation_applied"),
            ("attestation", "signature_present"),
            ("attestation", "signer_identity_verified"),
            ("attestation", "timestamp_witnessed"),
            ("attestation", "storage_immutable"),
        ):
            with self.subTest(section=section, field=field):
                envelope = evidence_envelope.build_envelope(self.decision())
                envelope["body"][section][field] = True
                self.rehash_envelope(envelope)
                with self.assertRaises(evidence_envelope.EvidenceEnvelopeError):
                    evidence_envelope.verify_envelope(envelope)

    def test_unknown_missing_schema_and_algorithm_fields_are_rejected(self) -> None:
        mutations = (
            lambda envelope: envelope.update(unexpected=True),
            lambda envelope: envelope.pop("body_sha256"),
            lambda envelope: envelope.update(schema_name="other"),
            lambda envelope: envelope.update(schema_version="2"),
            lambda envelope: envelope.update(hash_algorithm="sha1"),
            lambda envelope: envelope["body"].update(unexpected=True),
            lambda envelope: envelope["body"]["attestation"].update(unexpected=False),
            lambda envelope: envelope["body"]["approval_boundary"].pop("approval_recorded"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                envelope = evidence_envelope.build_envelope(self.decision())
                mutate(envelope)
                if "body_sha256" in envelope:
                    self.rehash_envelope(envelope)
                with self.assertRaises(evidence_envelope.EvidenceEnvelopeError):
                    evidence_envelope.verify_envelope(envelope)

    def test_rehashed_execution_binding_cannot_swap_policy_request_or_rollback(self) -> None:
        for field in ("canonical_policy_hash", "canonical_request_hash", "proposal_body_hash", "source_tree_hash", "request_id", "requested_scope"):
            with self.subTest(field=field):
                decision = self.decision()
                binding = decision["execution_binding"]
                binding[field] = "f" * 64 if "hash" in field else "swapped"
                binding["execution_binding_hash"] = canonical_sha256(
                    {key: value for key, value in binding.items() if key != "execution_binding_hash"}
                )
                decision["execution_binding_hash"] = binding["execution_binding_hash"]
                self.rehash_decision(decision)
                with self.assertRaises(evidence_envelope.EvidenceEnvelopeError):
                    evidence_envelope.build_envelope(decision)

    def test_contradictory_decision_identity_rollback_and_effect_claims_are_rejected(self) -> None:
        mutations = (
            lambda decision: decision.update(eligible_for_human_approval=False),
            lambda decision: decision.update(operator_approval_required=False),
            lambda decision: decision.update(mutation_authorized=True),
            lambda decision: decision.update(mutation_applied=True),
            lambda decision: decision.update(actor_identity_authenticated=True),
            lambda decision: decision.update(actor_identity_source="authenticated"),
            lambda decision: decision.update(rollback_readiness_verified=False),
            lambda decision: decision.update(source_hash_supplied="f" * 64),
            lambda decision: decision.update(proposal_hash_supplied="f" * 64),
            lambda decision: decision.update(sequence_index=True),
            lambda decision: decision.update(network_calls=1),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                decision = self.decision()
                mutate(decision)
                self.rehash_decision(decision)
                with self.assertRaises(evidence_envelope.EvidenceEnvelopeError):
                    evidence_envelope.build_envelope(decision)

    def test_denial_cannot_forge_execution_binding_or_eligibility(self) -> None:
        for mutate in (
            lambda decision: decision.update(eligible_for_human_approval=True),
            lambda decision: decision.update(execution_binding={"unexpected": True}),
            lambda decision: decision.update(exact_blocker=None),
        ):
            decision = self.decision(denied=True)
            mutate(decision)
            self.rehash_decision(decision)
            with self.assertRaises(evidence_envelope.EvidenceEnvelopeError):
                evidence_envelope.build_envelope(decision)

    def test_cli_rejection_does_not_echo_sensitive_caller_input(self) -> None:
        secret = "private-caller-path-and-sensitive-value"
        value = json.dumps({"secret": secret})
        result = self.run_cli("verify-evidence-envelope", value)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "")
        self.assertNotIn(secret, result.stdout)
        self.assertFalse(json.loads(result.stdout)["verified"])


if __name__ == "__main__":
    unittest.main()
