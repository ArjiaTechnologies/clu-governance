"""Canonical, unsigned, offline-verifiable policy-decision evidence.

An envelope binds an existing decision and its policy, request, proposal,
source, rollback, and execution artifacts. It never evaluates policy, records
approval, applies a change, authenticates identity, or produces a signature.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from typing import Any, TextIO

from . import strict_json
from . import new_file_proposal as new_file
from .source_mutation_policy_gate import (
    DECISION_SCHEMA_NAME,
    DENIAL_EXIT_CODE,
    canonical_json,
    canonical_sha256,
    normalize_relative_path,
)


ENVELOPE_SCHEMA_NAME = "clu_governance_unsigned_evidence_envelope.v1"
BODY_SCHEMA_NAME = "clu_governance_unsigned_evidence_body.v1"
VERIFICATION_SCHEMA_NAME = "clu_governance_evidence_envelope_verification.v1"
ERROR_SCHEMA_NAME = "clu_governance_evidence_envelope_error.v1"
SCHEMA_VERSION = "1"
HASH_ALGORITHM = "sha256"
HASH_DOMAIN = b"clu-governance:unsigned-evidence-envelope:v1\x00"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ENVELOPE_FIELDS = {"schema_name", "schema_version", "hash_algorithm", "body", "body_sha256"}
_BODY_FIELDS = {"schema_name", "schema_version", "decision", "artifact_binding", "approval_boundary", "attestation"}
_BINDING_FIELDS = {
    "policy_sha256",
    "request_sha256",
    "proposal_sha256",
    "source_tree_sha256",
    "audit_event_sha256",
    "execution_binding_sha256",
    "rollback_artifact_sha256",
}
_BOUNDARY_FIELDS = {"eligible_for_human_approval", "operator_approval_required", "approval_recorded", "mutation_authorized", "mutation_applied"}
_ATTESTATION_FIELDS = {"signature_present", "signer_identity_verified", "timestamp_witnessed", "storage_immutable"}


class EvidenceEnvelopeError(ValueError):
    """A stable, privacy-bounded failure in an unsigned evidence envelope."""


def _fail(reason: str) -> None:
    raise EvidenceEnvelopeError(reason)


def _exact_fields(value: Any, expected: set[str], *, blocker: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _fail(blocker)
    return value


def _digest(value: Any, *, blocker: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(blocker)
    return value


def _decision(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_name") != DECISION_SCHEMA_NAME or value.get("schema_version") != SCHEMA_VERSION:
        _fail("evidence_decision_schema_invalid")
    supplied_audit = _digest(value.get("audit_event_hash"), blocker="evidence_decision_audit_hash_invalid")
    actual_audit = canonical_sha256({key: item for key, item in value.items() if key != "audit_event_hash"})
    if supplied_audit != actual_audit:
        _fail("evidence_decision_audit_hash_mismatch")
    decision = value.get("decision")
    if decision not in {"allow", "deny"}:
        _fail("evidence_decision_kind_invalid")
    if value.get("eligible_for_human_approval") is not (decision == "allow"):
        _fail("evidence_decision_eligibility_inconsistent")
    if value.get("operator_approval_required") is not True:
        _fail("evidence_decision_operator_approval_required")
    if value.get("mutation_authorized") is not False or value.get("mutation_applied") is not False:
        _fail("evidence_decision_mutation_boundary_violated")
    if value.get("actor_identity_authenticated") is not False or value.get("actor_identity_source") != "caller_declared":
        _fail("evidence_decision_actor_identity_claim_invalid")
    for field in ("policy_hash", "canonical_request_hash", "proposal_hash_supplied", "proposal_hash_verified", "source_hash_supplied", "source_hash_verified"):
        _digest(value.get(field), blocker=f"evidence_decision_{field}_invalid")
    if value["proposal_hash_supplied"] != value["proposal_hash_verified"]:
        _fail("evidence_decision_proposal_hash_mismatch")
    if value["source_hash_supplied"] != value["source_hash_verified"]:
        _fail("evidence_decision_source_hash_mismatch")
    sequence = value.get("sequence_index")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        _fail("evidence_decision_sequence_invalid")
    timestamp = value.get("event_timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        _fail("evidence_decision_timestamp_invalid")
    if any(value.get(field) != 0 or isinstance(value.get(field), bool) for field in ("network_calls", "provider_calls", "advisor_calls", "mem0_runs", "benchmark_runs")):
        _fail("evidence_decision_external_effect_claim_invalid")
    if decision == "allow":
        if value.get("reason_code") != "eligible_for_human_approval" or value.get("exact_blocker") is not None:
            _fail("evidence_decision_allow_reason_invalid")
        if value.get("rollback_readiness_verified") is not True:
            _fail("evidence_decision_rollback_not_verified")
        _execution_binding(value)
    else:
        if not isinstance(value.get("exact_blocker"), str) or not value["exact_blocker"]:
            _fail("evidence_decision_denial_blocker_missing")
        if value.get("reason_code") != value["exact_blocker"]:
            _fail("evidence_decision_denial_reason_mismatch")
        if value.get("execution_binding") is not None or value.get("execution_binding_hash") is not None:
            _fail("evidence_decision_denial_execution_binding_present")
    return value


def _execution_binding(decision: dict[str, Any]) -> dict[str, Any]:
    binding = decision.get("execution_binding")
    if not isinstance(binding, dict) or binding.get("schema_name") != "clu_governance_source_mutation_execution_binding.v1":
        _fail("evidence_execution_binding_schema_invalid")
    digest = _digest(binding.get("execution_binding_hash"), blocker="evidence_execution_binding_hash_invalid")
    if digest != canonical_sha256({key: item for key, item in binding.items() if key != "execution_binding_hash"}):
        _fail("evidence_execution_binding_hash_mismatch")
    if decision.get("execution_binding_hash") != digest:
        _fail("evidence_execution_binding_decision_hash_mismatch")
    for binding_field, decision_field in (
        ("canonical_policy_hash", "policy_hash"),
        ("canonical_request_hash", "canonical_request_hash"),
        ("proposal_body_hash", "proposal_hash_verified"),
        ("source_tree_hash", "source_hash_verified"),
        ("request_id", "request_id"),
        ("proposal_id", "proposal_id"),
        ("declared_actor_id", "declared_actor_id"),
        ("requested_scope", "requested_scope"),
        ("matched_rule_id", "matched_rule_id"),
    ):
        if binding.get(binding_field) != decision.get(decision_field):
            _fail(f"evidence_execution_binding_{binding_field}_mismatch")
    _digest(binding.get("rollback_artifact_hash"), blocker="evidence_execution_binding_rollback_hash_invalid")
    operations = binding.get("ordered_operations")
    checked = decision.get("checked_paths_and_operations")
    if not isinstance(operations, list) or not operations or not isinstance(checked, list):
        _fail("evidence_execution_binding_operations_invalid")
    if binding.get("checked_operation_digest") != canonical_sha256(checked):
        _fail("evidence_execution_binding_checked_operations_mismatch")
    paths: list[str] = []
    hashes: list[str | None] = []
    for operation in operations:
        if not isinstance(operation, dict) or operation.get("operation") not in {"modify", "create"}:
            _fail("evidence_execution_binding_operation_invalid")
        if operation.get("operation") == "create":
            try:
                new_file.validate_operation(operation)
            except new_file.NewFileProposalError:
                _fail("evidence_execution_binding_create_contract_invalid")
            if len(operations) != 1:
                _fail("evidence_execution_binding_create_contract_invalid")
        raw_path = operation.get("path")
        try:
            normalized = normalize_relative_path(raw_path)
        except Exception:
            _fail("evidence_execution_binding_path_invalid")
        if normalized != raw_path or normalized in paths:
            _fail("evidence_execution_binding_path_invalid")
        paths.append(normalized)
        hashes.append(None if operation["operation"] == "create" else _digest(operation.get("before_sha256"), blocker="evidence_execution_binding_before_hash_invalid"))
    if binding.get("normalized_target_paths") != paths or binding.get("before_file_hashes") != hashes:
        _fail("evidence_execution_binding_operation_projection_mismatch")
    if checked != operations:
        _fail("evidence_execution_binding_operation_evidence_mismatch")
    return binding


def _body_sha256(body: dict[str, Any]) -> str:
    return hashlib.sha256(HASH_DOMAIN + canonical_json(body).encode("utf-8")).hexdigest()


def _expected_binding(decision: dict[str, Any]) -> dict[str, str | None]:
    execution = decision.get("execution_binding")
    return {
        "policy_sha256": decision["policy_hash"],
        "request_sha256": decision["canonical_request_hash"],
        "proposal_sha256": decision["proposal_hash_verified"],
        "source_tree_sha256": decision["source_hash_verified"],
        "audit_event_sha256": decision["audit_event_hash"],
        "execution_binding_sha256": decision.get("execution_binding_hash"),
        "rollback_artifact_sha256": execution.get("rollback_artifact_hash") if isinstance(execution, dict) else None,
    }


def _expected_boundary(decision: dict[str, Any]) -> dict[str, bool]:
    return {
        "eligible_for_human_approval": decision["eligible_for_human_approval"],
        "operator_approval_required": True,
        "approval_recorded": False,
        "mutation_authorized": False,
        "mutation_applied": False,
    }


def build_envelope(decision: dict[str, Any]) -> dict[str, Any]:
    """Bind a validated evaluator decision without adding authority or identity."""

    decision = _decision(decision)
    body = {
        "schema_name": BODY_SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "decision": decision,
        "artifact_binding": _expected_binding(decision),
        "approval_boundary": _expected_boundary(decision),
        "attestation": {field: False for field in sorted(_ATTESTATION_FIELDS)},
    }
    return {
        "schema_name": ENVELOPE_SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "body": body,
        "body_sha256": _body_sha256(body),
    }


def verify_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    """Verify exact canonical evidence and semantic binding completely offline."""

    envelope = _exact_fields(envelope, _ENVELOPE_FIELDS, blocker="evidence_envelope_fields_invalid")
    if envelope.get("schema_name") != ENVELOPE_SCHEMA_NAME or envelope.get("schema_version") != SCHEMA_VERSION:
        _fail("evidence_envelope_schema_invalid")
    if envelope.get("hash_algorithm") != HASH_ALGORITHM:
        _fail("evidence_envelope_hash_algorithm_invalid")
    digest = _digest(envelope.get("body_sha256"), blocker="evidence_envelope_body_hash_invalid")
    body = _exact_fields(envelope.get("body"), _BODY_FIELDS, blocker="evidence_envelope_body_fields_invalid")
    if body.get("schema_name") != BODY_SCHEMA_NAME or body.get("schema_version") != SCHEMA_VERSION:
        _fail("evidence_envelope_body_schema_invalid")
    if digest != _body_sha256(body):
        _fail("evidence_envelope_body_hash_mismatch")
    decision = _decision(body.get("decision"))
    binding = _exact_fields(body.get("artifact_binding"), _BINDING_FIELDS, blocker="evidence_envelope_artifact_binding_fields_invalid")
    if binding != _expected_binding(decision):
        _fail("evidence_envelope_artifact_binding_mismatch")
    boundary = _exact_fields(body.get("approval_boundary"), _BOUNDARY_FIELDS, blocker="evidence_envelope_approval_boundary_fields_invalid")
    if boundary != _expected_boundary(decision):
        _fail("evidence_envelope_approval_boundary_mismatch")
    attestation = _exact_fields(body.get("attestation"), _ATTESTATION_FIELDS, blocker="evidence_envelope_attestation_fields_invalid")
    if any(value is not False for value in attestation.values()):
        _fail("evidence_envelope_attestation_claim_invalid")
    return {
        "schema_name": VERIFICATION_SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "verified": True,
        "decision": decision["decision"],
        "body_sha256": digest,
        "artifact_binding_verified": True,
        "approval_recorded": False,
        "mutation_authorized": False,
        "mutation_applied": False,
        "signature_verified": False,
        "signer_identity_verified": False,
        "timestamp_witnessed": False,
        "storage_immutable": False,
        "network_calls": 0,
        "exact_blocker": None,
    }


def _error(blocker: str, *, verification: bool) -> dict[str, Any]:
    return {
        "schema_name": VERIFICATION_SCHEMA_NAME if verification else ERROR_SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "verified": False,
        "approval_recorded": False,
        "mutation_authorized": False,
        "mutation_applied": False,
        "signature_verified": False,
        "signer_identity_verified": False,
        "timestamp_witnessed": False,
        "storage_immutable": False,
        "network_calls": 0,
        "exact_blocker": blocker,
    }


def run(document: str, *, verify: bool = False) -> tuple[int, dict[str, Any]]:
    """Process one strict stdin document with stable, privacy-bounded errors."""

    try:
        value = strict_json.loads(document)
    except strict_json.DuplicateJSONKeyError:
        return (DENIAL_EXIT_CODE if verify else 1), _error("evidence_input_duplicate_json_key", verification=verify)
    except Exception:
        return (DENIAL_EXIT_CODE if verify else 1), _error("evidence_input_malformed_json", verification=verify)
    try:
        payload = verify_envelope(value) if verify else build_envelope(value)
    except EvidenceEnvelopeError as exc:
        return (DENIAL_EXIT_CODE if verify else 1), _error(str(exc), verification=verify)
    return 0, payload


def main(*, verify: bool = False, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    exit_code, payload = run((stdin or sys.stdin).read(), verify=verify)
    (stdout or sys.stdout).write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return exit_code
