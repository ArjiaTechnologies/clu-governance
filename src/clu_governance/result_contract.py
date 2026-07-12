"""Pure final-state consistency checks for verifier and adapter results."""

from __future__ import annotations

from typing import Any


class ResultContractError(ValueError):
    pass


def validate_verifier_result(result: dict[str, Any]) -> None:
    if result.get("result") not in {"verified", "invalid", "failed"}:
        raise ResultContractError("verifier_result_enum_invalid")
    if (result.get("result") == "verified") != (result.get("verified") is True):
        raise ResultContractError("verifier_result_boolean_mismatch")
    anomalies = sum(
        (list(result.get(name) or []) for name in (
            "unknown_entries", "missing_entries", "symlink_entries",
            "hardlink_entries", "nonregular_entries",
        )),
        [],
    )
    if anomalies and (
        result.get("bundle_exact_set_verified_at_return") is True
        or result.get("exact_file_set_verified") is True
        or result.get("checksums_verified") is True
    ):
        raise ResultContractError("final_anomalies_with_exact_success")
    if result.get("verified") is True:
        required = (
            "bundle_full_ancestor_chain_bound",
            "bundle_full_ancestor_chain_reverified_at_return",
            "caller_visible_bundle_path_bound_at_return",
            "caller_visible_bundle_root_identity_verified",
            "bundle_exact_set_verified_at_return",
            "exact_file_set_verified",
            "checksums_verified",
            "completion_verified",
            "publication_binding_verified",
        )
        if any(result.get(name) is not True for name in required):
            raise ResultContractError("verified_without_final_binding_or_integrity")
        if result.get("exact_blocker") is not None:
            raise ResultContractError("verified_with_blocker")


def validate_adapter_result(result: dict[str, Any]) -> None:
    if result.get("result") not in {"adapted", "policy_denied", "blocked", "failed"}:
        raise ResultContractError("adapter_result_enum_invalid")
    anomalies = sum(
        (list(result.get(name) or []) for name in (
            "output_bundle_unknown_entries_at_return",
            "output_bundle_missing_entries_at_return",
            "output_bundle_type_mismatches_at_return",
            "output_bundle_symlink_entries_at_return",
            "output_bundle_hardlink_entries_at_return",
        )),
        [],
    )
    if anomalies and (
        result.get("published_bundle_exact_set_verified") is True
        or result.get("published_bundle_checksum_coverage_exact") is True
        or result.get("output_bundle_valid_at_return") is True
    ):
        raise ResultContractError("final_anomalies_with_published_success")
    if result.get("result") in {"adapted", "policy_denied"}:
        required = (
            "publication_operation_completed",
            "published_bundle_exact_set_verified",
            "published_bundle_checksum_coverage_exact",
            "post_publication_bundle_verified",
            "caller_visible_bundle_path_bound_at_return",
            "requested_final_output_present_at_return",
            "requested_final_output_is_adapter_owned_at_return",
            "requested_final_output_ownership_verified_at_return",
            "output_bundle_valid_at_return",
            "bundle_exact_set_verified_at_return",
            "output_bundle_exact_file_set_verified",
            "output_bundle_checksum_coverage_exact",
            "output_bundle_sealed",
            "completion_record_authoritative_at_return",
        )
        if any(result.get(name) is not True for name in required):
            raise ResultContractError("successful_adapter_result_without_final_state_proof")
    if result.get("result") in {"blocked", "failed"}:
        if result.get("eligible_for_separate_approval") is True:
            raise ResultContractError("blocked_result_eligible_for_approval")
        for name in (
            "published_bundle_exact_set_verified",
            "published_bundle_checksum_coverage_exact",
            "post_publication_bundle_verified",
            "caller_visible_bundle_path_bound_at_return",
            "output_bundle_valid_at_return",
            "output_bundle_exact_file_set_verified",
            "output_bundle_checksum_coverage_exact",
            "output_bundle_sealed",
            "bundle_exact_set_verified_at_return",
            "completion_record_authoritative_at_return",
        ):
            if result.get(name) is True:
                raise ResultContractError(f"blocked_result_retains_success:{name}")
    if result.get("requested_final_output_ownership_verified_at_return") is True and (
        result.get("requested_final_output_is_adapter_owned_at_return") is not True
        or result.get("caller_visible_bundle_path_bound_at_return") is not True
    ):
        raise ResultContractError("ownership_verified_without_owned_bound_path")
    final_valid = result.get("output_bundle_valid_at_return") is True
    for name in (
        "published_bundle_exact_set_verified",
        "published_bundle_checksum_coverage_exact",
        "post_publication_bundle_verified",
        "caller_visible_bundle_path_bound_at_return",
        "bundle_exact_set_verified_at_return",
        "output_bundle_exact_file_set_verified",
        "output_bundle_checksum_coverage_exact",
        "output_bundle_sealed",
        "completion_record_authoritative_at_return",
    ):
        if (result.get(name) is True) != final_valid:
            raise ResultContractError(f"final_validity_field_mismatch:{name}")
    if result.get("requested_final_output_presence_known_at_return") is True:
        if result.get("requested_final_output_present_after_failed_seal") != result.get(
            "requested_final_output_present_at_return"
        ):
            raise ResultContractError("legacy_presence_field_mismatch")
    if result.get("requested_final_output_is_adapter_owned") != result.get(
        "requested_final_output_is_adapter_owned_at_return"
    ):
        raise ResultContractError("legacy_ownership_field_mismatch")
