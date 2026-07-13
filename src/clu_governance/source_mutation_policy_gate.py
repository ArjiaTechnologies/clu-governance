"""Read-only pre-execution policy gate for source-mutation manifests.

The gate decides whether a proposed coding-agent source mutation is eligible
for a separate approval decision. It never applies the mutation and an allow
decision is not approval.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import strict_json
from .safe_artifact_io import (
    SafeArtifactWriteError,
    absolute_raw_path,
    existing_components,
    safe_atomic_write_json,
    validate_output_outside_roots,
)


POLICY_SCHEMA_NAME = "clu_governance_source_mutation_policy.v1"
REQUEST_SCHEMA_NAME = "clu_governance_source_mutation_request.v1"
ROLLBACK_SCHEMA_NAME = "clu_governance_source_mutation_rollback_readiness.v1"
DECISION_SCHEMA_NAME = "clu_governance_source_mutation_policy_decision.v1"
APPROVAL_SCHEMA_NAME = "clu_governance_source_mutation_demo_approval.v1"
EXECUTION_SCHEMA_NAME = "clu_governance_source_mutation_demo_execution.v1"
WORKSPACE_SCHEMA_NAME = "clu_source_mutation_policy_gate_demo_workspace.v1"
WORKSPACE_SCHEMA_VERSION = "1"
DEMO_CREATED_BY = "clu_governance.source_mutation_policy_gate"

ALLOWED_DECISIONS = {"allow", "deny"}
ALLOWED_EFFECTS = {"allow", "deny"}
SAFE_OPERATION_SET = {"modify"}
UNSUPPORTED_OPERATIONS = {"delete", "rename", "chmod", "symlink", "binary_replace"}
DENIAL_EXIT_CODE = 2
HELP_BOUNDARY = (
    "Local-first tool: policy allow means eligible for a separate approval decision, not approval. "
    "Actor identity is caller-declared and unauthenticated; scripted demo approval does not verify human presence. "
    "This pre-alpha gate is not production-ready or non-bypassable."
)
DEMO_MARKER_FILENAME = ".clu_source_mutation_policy_gate_demo.json"
DEMO_TOP_LEVEL_ALLOWLIST = {DEMO_MARKER_FILENAME, "demo_repo", "artifacts"}
DEMO_ARTIFACT_ALLOWLIST = {
    "demo_policy.json",
    "allowed_request.json",
    "denied_request.json",
    "rollback_snapshot.json",
    "denied_decision.json",
    "allowed_decision.json",
    "approval.json",
    "approved_execution.json",
}

DEMO_POLICY_ID = "clu-governance-demo-source-mutation-policy-v1"
DEMO_ALLOWED_REQUEST_ID = "demo-allowed-doc-mutation"
DEMO_DENIED_REQUEST_ID = "demo-denied-source-deletion"
DEMO_ALLOWED_PROPOSAL_ID = "demo-proposal-doc-readme"
DEMO_DENIED_PROPOSAL_ID = "demo-proposal-source-delete"
DEMO_APPROVAL_ID = "demo-policy-gate-approval-001"
DEMO_INITIAL_README = "# Demo Repo\n\nInitial governance demo state.\n"
DEMO_PROPOSED_README = "# Demo Repo\n\nApproved documentation-only governance demo change.\n"


class PolicyGateError(ValueError):
    """Raised when a policy gate input cannot be evaluated safely."""


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json_file(path: Path) -> Any:
    return strict_json.loads(path.read_text(encoding="utf-8"))


def write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def normalize_relative_path(raw_path: Any) -> str:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise PolicyGateError("path_missing_or_not_string")
    if "\x00" in raw_path:
        raise PolicyGateError("path_contains_nul")
    portable = raw_path.replace("\\", "/")
    if portable.startswith("/") or portable.startswith("//"):
        raise PolicyGateError("absolute_or_unc_path_denied")
    if len(portable) >= 3 and portable[1] == ":" and portable[2] == "/":
        raise PolicyGateError("drive_letter_path_denied")
    parts = [part for part in portable.split("/") if part not in {"", "."}]
    if not parts:
        raise PolicyGateError("empty_path_denied")
    if any(part == ".." for part in parts):
        raise PolicyGateError("path_traversal_denied")
    return "/".join(parts)


def path_has_sensitive_name(rel_path: str) -> bool:
    parts = rel_path.split("/")
    lowered = [part.lower() for part in parts]
    if ".git" in lowered:
        return True
    basename = lowered[-1]
    if basename in {".env", ".env.local", ".envrc"} or basename.startswith(".env."):
        return True
    if basename in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts"}:
        return True
    if basename.endswith((".pem", ".key", ".p12", ".pfx")):
        return True
    if "private" in basename and "key" in basename:
        return True
    return False


def resolve_inside_source_root(source_root: Path, rel_path: str) -> Path:
    root = source_root.expanduser().resolve(strict=True)
    candidate = root / rel_path
    current = root
    for part in rel_path.split("/"):
        current = current / part
        if current.exists() or current.is_symlink():
            resolved = current.resolve(strict=True)
            if not is_relative_to(resolved, root):
                raise PolicyGateError("source_root_escape_denied")
    resolved_candidate = candidate.resolve(strict=False)
    if not is_relative_to(resolved_candidate, root):
        raise PolicyGateError("source_root_escape_denied")
    return candidate


def source_tree_hash(source_root: Path) -> str:
    root = source_root.expanduser().resolve(strict=True)
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*")):
        if path.is_dir() and path.is_symlink():
            rel = path.relative_to(root).as_posix()
            digest.update(rel.encode("utf-8"))
            digest.update(b"\0SYMLINK_DIR\0")
            digest.update(os.readlink(path).encode("utf-8"))
            digest.update(b"\0")
            continue
        if not path.is_file() and not path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"SYMLINK_FILE\0")
            digest.update(os.readlink(path).encode("utf-8"))
        else:
            digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def output_path_is_safe(output_path: Path, source_root: Path) -> bool:
    output_resolved = output_path.expanduser().resolve(strict=False)
    source_resolved = source_root.expanduser().resolve(strict=True)
    return not is_relative_to(output_resolved, source_resolved)


def paths_overlap(first: Path, second: Path) -> bool:
    first_resolved = first.expanduser().resolve(strict=False)
    second_resolved = second.expanduser().resolve(strict=False)
    return is_relative_to(first_resolved, second_resolved) or is_relative_to(second_resolved, first_resolved)


def safe_source_tree_hash(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.exists() or not path.is_dir():
            return None
        return source_tree_hash(path)
    except Exception:
        return None


def payload_integrity_hash(payload: dict[str, Any], field_name: str) -> str:
    return canonical_sha256({key: value for key, value in payload.items() if key != field_name})


def canonical_request_hash(request: dict[str, Any]) -> str:
    return canonical_sha256(request)


def normalized_operation_binding(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for operation in operations:
        normalized.append(
            {
                "operation": operation.get("operation"),
                "path": operation.get("path"),
                "before_sha256": operation.get("before_sha256"),
            }
        )
    return normalized


def execution_binding_for(
    *,
    request: dict[str, Any],
    policy_hash: str | None,
    checked_operations: list[dict[str, Any]],
    matched_rule_id: str | None,
) -> dict[str, Any]:
    operations = normalized_operation_binding(request.get("operations", []))
    rollback = request.get("rollback_readiness") if isinstance(request.get("rollback_readiness"), dict) else {}
    binding = {
        "schema_name": "clu_governance_source_mutation_execution_binding.v1",
        "canonical_policy_hash": policy_hash,
        "canonical_request_hash": canonical_request_hash(request),
        "request_id": request.get("request_id"),
        "proposal_id": request.get("proposal_id"),
        "proposal_body_hash": canonical_sha256(request.get("proposal_body")),
        "declared_actor_id": request.get("declared_actor_id"),
        "requested_scope": request.get("requested_scope"),
        "ordered_operations": operations,
        "normalized_target_paths": [operation.get("path") for operation in operations],
        "before_file_hashes": [operation.get("before_sha256") for operation in operations],
        "source_tree_hash": request.get("source_tree_hash"),
        "rollback_artifact_path": rollback.get("artifact_path"),
        "rollback_artifact_hash": rollback.get("artifact_sha256"),
        "checked_operation_digest": canonical_sha256(checked_operations),
        "matched_rule_id": matched_rule_id,
    }
    binding["execution_binding_hash"] = canonical_sha256(binding)
    return binding


def artifact_path_has_unsafe_part(path: Path) -> bool:
    for part in path.parts:
        if path_has_sensitive_name(part):
            return True
    return False


def validate_rollback_artifact_contents(
    *,
    request: dict[str, Any],
    source_root: Path,
    require_current_target_hash: bool,
) -> tuple[dict[str, Any] | None, str | None]:
    readiness = request.get("rollback_readiness")
    if not isinstance(readiness, dict):
        return None, "rollback_readiness_missing"
    if readiness.get("schema_name") != ROLLBACK_SCHEMA_NAME or readiness.get("schema_version") != "1":
        return None, "rollback_readiness_wrong_schema"
    artifact_path_raw = readiness.get("artifact_path")
    if not isinstance(artifact_path_raw, str):
        return None, "rollback_artifact_path_missing"
    artifact_path = Path(artifact_path_raw).expanduser()
    if not artifact_path.is_absolute():
        return None, "rollback_artifact_path_must_be_absolute"
    if artifact_path.is_symlink():
        return None, "rollback_artifact_symlink_denied"
    if artifact_path_has_unsafe_part(artifact_path):
        return None, "rollback_artifact_unsafe_path_denied"
    artifact_hash = readiness.get("artifact_sha256")
    if not isinstance(artifact_hash, str) or not artifact_hash:
        return None, "rollback_artifact_hash_missing"
    try:
        actual_artifact_hash = sha256_file(artifact_path)
    except OSError:
        return None, "rollback_artifact_missing"
    if actual_artifact_hash != artifact_hash:
        return None, "rollback_artifact_hash_mismatch"
    try:
        artifact = read_json_file(artifact_path)
    except json.JSONDecodeError:
        return None, "rollback_artifact_malformed_json"
    except Exception:
        return None, "rollback_artifact_unreadable"
    if not isinstance(artifact, dict):
        return None, "rollback_artifact_malformed"
    if artifact.get("schema_name") != ROLLBACK_SCHEMA_NAME:
        return None, "rollback_artifact_wrong_schema"
    if artifact.get("schema_version") != "1":
        return None, "rollback_artifact_wrong_version"
    if not (artifact.get("snapshot_id") or artifact.get("rollback_manifest_id")):
        return None, "rollback_artifact_id_missing"
    artifact_files = artifact.get("files")
    if not isinstance(artifact_files, dict) or not artifact_files:
        return None, "rollback_artifact_files_missing"
    wrapper_files = readiness.get("files")
    if not isinstance(wrapper_files, dict) or not wrapper_files:
        return None, "rollback_files_missing"

    covered_paths: set[str] = set()
    for operation in request.get("operations", []):
        rel_path = operation.get("path")
        try:
            normalized_path = normalize_relative_path(rel_path)
        except PolicyGateError as exc:
            return None, str(exc)
        if normalized_path in covered_paths:
            return None, "rollback_artifact_duplicate_file_entry"
        covered_paths.add(normalized_path)
        artifact_entry = artifact_files.get(normalized_path)
        if not isinstance(artifact_entry, dict):
            return None, "rollback_artifact_file_entry_missing"
        wrapper_entry = wrapper_files.get(normalized_path)
        if not isinstance(wrapper_entry, dict):
            return None, "rollback_file_entry_missing"
        before_hash = operation.get("before_sha256")
        if "path" not in artifact_entry:
            return None, "rollback_artifact_file_path_missing"
        artifact_entry_path = artifact_entry.get("path")
        if not isinstance(artifact_entry_path, str):
            return None, "rollback_artifact_file_path_not_string"
        try:
            normalized_artifact_path = normalize_relative_path(artifact_entry_path)
        except PolicyGateError:
            return None, "rollback_artifact_file_path_invalid"
        if artifact_entry_path != normalized_artifact_path:
            return None, "rollback_artifact_file_path_not_normalized"
        if normalized_artifact_path != normalized_path:
            return None, "rollback_artifact_file_path_mismatch"
        if artifact_entry.get("before_sha256") != before_hash:
            return None, "rollback_artifact_before_hash_mismatch"
        if wrapper_entry.get("before_sha256") != artifact_entry.get("before_sha256"):
            return None, "rollback_wrapper_artifact_mismatch"
        original_content = artifact_entry.get("original_content")
        if not isinstance(original_content, str):
            return None, "rollback_artifact_original_content_missing"
        encoding = artifact_entry.get("content_encoding")
        if encoding != "utf-8":
            return None, "rollback_artifact_content_encoding_unsupported"
        original_hash = hashlib.sha256(original_content.encode("utf-8")).hexdigest()
        if original_hash != before_hash:
            return None, "rollback_artifact_original_content_hash_mismatch"
        if require_current_target_hash:
            target = resolve_inside_source_root(source_root, normalized_path)
            if not target.exists() or not target.is_file() or target.is_symlink():
                return None, "rollback_current_target_invalid"
            if sha256_file(target) != before_hash:
                return None, "rollback_current_target_hash_mismatch"
    if set(artifact_files) != covered_paths:
        return None, "rollback_artifact_unrelated_file_entry"
    return {
        "artifact_path": str(artifact_path),
        "artifact_sha256": artifact_hash,
        "files": artifact_files,
    }, None


def load_policy(policy_path: Path | None) -> tuple[dict[str, Any] | None, str | None, str | None]:
    if policy_path is None:
        return None, None, "policy_missing"
    try:
        raw = policy_path.read_bytes()
    except OSError:
        return None, None, "policy_missing"
    try:
        policy = strict_json.loads(raw.decode("utf-8"))
    except Exception:
        return None, sha256_bytes(raw), "policy_malformed_json"
    return policy, canonical_sha256(policy), None


def load_request(request_path: Path | None) -> tuple[dict[str, Any] | None, str | None]:
    if request_path is None:
        return None, "request_missing"
    try:
        request = read_json_file(request_path)
    except FileNotFoundError:
        return None, "request_missing"
    except Exception:
        return None, "request_malformed_json"
    return request, None


def validate_policy(policy: dict[str, Any] | None) -> str | None:
    if not isinstance(policy, dict):
        return "policy_missing"
    if policy.get("schema_name") != POLICY_SCHEMA_NAME or policy.get("schema_version") != "1":
        return "policy_wrong_schema"
    if not policy.get("policy_id"):
        return "policy_id_missing"
    if policy.get("default_decision") != "deny":
        return "allow_by_default_policy_rejected"
    if policy.get("maximum_file_count") is None or not isinstance(policy.get("maximum_file_count"), int):
        return "maximum_file_count_missing"
    rules = policy.get("rules")
    if not isinstance(rules, list):
        return "rules_missing"
    seen: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            return "rule_malformed"
        rule_id = rule.get("rule_id")
        if not rule_id or rule_id in seen:
            return "rule_id_missing_or_duplicate"
        seen.add(str(rule_id))
        if rule.get("effect") not in ALLOWED_EFFECTS:
            return "unknown_rule_effect_denied"
    return None


def validate_request_shape(request: dict[str, Any] | None) -> str | None:
    if not isinstance(request, dict):
        return "request_missing"
    if request.get("schema_name") != REQUEST_SCHEMA_NAME or request.get("schema_version") != "1":
        return "request_wrong_schema"
    required = [
        "request_id",
        "declared_actor_id",
        "actor_identity_source",
        "requested_scope",
        "proposal_id",
        "proposal_body",
        "proposal_hash",
        "source_tree_hash",
        "operations",
    ]
    for key in required:
        if key not in request:
            return f"{key}_missing"
    if request.get("actor_identity_source") != "caller_declared":
        return "actor_identity_source_must_be_caller_declared"
    if not isinstance(request.get("operations"), list) or not request["operations"]:
        return "operations_missing"
    return None


def match_path(path: str, *, exact: list[str], prefixes: list[str], globs: list[str]) -> bool:
    if path in exact:
        return True
    if any(path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/") for prefix in prefixes):
        return True
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in globs)


def normalize_pattern_list(raw: Any) -> list[str]:
    if not raw:
        return []
    if not isinstance(raw, list):
        return []
    normalized: list[str] = []
    for item in raw:
        if isinstance(item, str):
            try:
                normalized.append(normalize_relative_path(item))
            except PolicyGateError:
                normalized.append(item.replace("\\", "/"))
    return normalized


def operation_matches_rule(operation: dict[str, Any], rule: dict[str, Any]) -> bool:
    op = str(operation.get("operation"))
    rel_path = str(operation.get("path"))
    operations = rule.get("operations") or []
    if operations and op not in operations:
        return False
    exact = normalize_pattern_list(rule.get("paths"))
    prefixes = normalize_pattern_list(rule.get("path_prefixes"))
    globs = [str(item).replace("\\", "/") for item in (rule.get("path_globs") or []) if isinstance(item, str)]
    if exact or prefixes or globs:
        return match_path(rel_path, exact=exact, prefixes=prefixes, globs=globs)
    return True


def first_matching_rule(policy: dict[str, Any], operation: dict[str, Any], effect: str) -> dict[str, Any] | None:
    for rule in policy.get("rules", []):
        if rule.get("effect") == effect and operation_matches_rule(operation, rule):
            return rule
    return None


def validate_actor_and_scope(policy: dict[str, Any], request: dict[str, Any]) -> str | None:
    actor = request.get("declared_actor_id")
    if not isinstance(actor, str) or not actor.strip():
        return "declared_actor_id_missing"
    allowed_actors = set(policy.get("allowed_declared_actor_ids") or [])
    if actor not in allowed_actors:
        return "declared_actor_id_not_allowed"
    scope = request.get("requested_scope")
    if not isinstance(scope, str) or not scope.strip():
        return "requested_scope_missing"
    allowed_scopes = set(policy.get("allowed_scopes") or [])
    if scope not in allowed_scopes:
        return "requested_scope_not_allowed"
    return None


def check_request_hashes(request: dict[str, Any], source_root: Path) -> str | None:
    supplied_proposal_hash = request.get("proposal_hash")
    if not isinstance(supplied_proposal_hash, str) or not supplied_proposal_hash:
        return "proposal_hash_missing"
    if canonical_sha256(request.get("proposal_body")) != supplied_proposal_hash:
        return "proposal_hash_mismatch"
    supplied_source_hash = request.get("source_tree_hash")
    if not isinstance(supplied_source_hash, str) or not supplied_source_hash:
        return "source_hash_missing"
    if source_tree_hash(source_root) != supplied_source_hash:
        return "source_hash_mismatch"
    return None


def check_rollback_readiness(request: dict[str, Any], source_root: Path, policy: dict[str, Any]) -> tuple[bool, str | None]:
    if not policy.get("rollback_readiness_required", True):
        return True, None
    _, rollback_error = validate_rollback_artifact_contents(
        request=request,
        source_root=source_root,
        require_current_target_hash=True,
    )
    return rollback_error is None, rollback_error


def check_operations(policy: dict[str, Any], request: dict[str, Any], source_root: Path) -> tuple[list[dict[str, Any]], str | None, str | None, str | None]:
    operations = request.get("operations", [])
    maximum = int(policy.get("maximum_file_count", 0))
    if len(operations) > maximum:
        return [], None, None, "maximum_file_count_exceeded"
    allowed_operations = set(policy.get("allowed_operations") or [])
    checked: list[dict[str, Any]] = []
    matched_allow_rule: str | None = None
    matched_deny_rule: str | None = None
    denied_paths = normalize_pattern_list(policy.get("denied_paths"))
    denied_prefixes = normalize_pattern_list(policy.get("denied_path_prefixes"))
    denied_globs = [str(item).replace("\\", "/") for item in (policy.get("denied_path_globs") or []) if isinstance(item, str)]
    allowed_paths = normalize_pattern_list(policy.get("allowed_paths"))
    allowed_prefixes = normalize_pattern_list(policy.get("allowed_path_prefixes"))
    allowed_globs = [str(item).replace("\\", "/") for item in (policy.get("allowed_path_globs") or []) if isinstance(item, str)]

    for raw_operation in operations:
        if not isinstance(raw_operation, dict):
            return checked, matched_allow_rule, matched_deny_rule, "operation_malformed"
        op_name = raw_operation.get("operation")
        if not isinstance(op_name, str) or not op_name:
            return checked, matched_allow_rule, matched_deny_rule, "operation_missing"
        if op_name in UNSUPPORTED_OPERATIONS:
            return checked, matched_allow_rule, matched_deny_rule, f"{op_name}_operation_denied"
        if op_name not in SAFE_OPERATION_SET or op_name not in allowed_operations:
            return checked, matched_allow_rule, matched_deny_rule, "unknown_or_disallowed_operation_denied"
        try:
            rel_path = normalize_relative_path(raw_operation.get("path"))
            if path_has_sensitive_name(rel_path):
                return checked, matched_allow_rule, matched_deny_rule, "sensitive_path_denied"
            target = resolve_inside_source_root(source_root, rel_path)
        except PolicyGateError as exc:
            return checked, matched_allow_rule, matched_deny_rule, str(exc)
        operation = {**raw_operation, "path": rel_path}
        if first_matching_rule(policy, operation, "deny") is not None:
            rule = first_matching_rule(policy, operation, "deny")
            matched_deny_rule = str(rule["rule_id"]) if rule else None
            return checked, matched_allow_rule, matched_deny_rule, "explicit_deny_rule_matched"
        if match_path(rel_path, exact=denied_paths, prefixes=denied_prefixes, globs=denied_globs):
            return checked, matched_allow_rule, matched_deny_rule, "explicit_denied_path_matched"
        if not match_path(rel_path, exact=allowed_paths, prefixes=allowed_prefixes, globs=allowed_globs):
            return checked, matched_allow_rule, matched_deny_rule, "path_not_explicitly_allowed"
        allow_rule = first_matching_rule(policy, operation, "allow")
        if allow_rule is None:
            return checked, matched_allow_rule, matched_deny_rule, "allow_rule_missing"
        matched_allow_rule = str(allow_rule["rule_id"])
        if op_name == "modify":
            if not target.exists():
                return checked, matched_allow_rule, matched_deny_rule, "modify_target_missing"
            if not target.is_file() or target.is_symlink():
                return checked, matched_allow_rule, matched_deny_rule, "modify_target_not_regular_file"
            supplied_before = raw_operation.get("before_sha256")
            if not isinstance(supplied_before, str) or not supplied_before:
                return checked, matched_allow_rule, matched_deny_rule, "before_file_hash_missing"
            actual_before = sha256_file(target)
            if actual_before != supplied_before:
                return checked, matched_allow_rule, matched_deny_rule, "before_file_hash_mismatch"
            checked.append({"operation": op_name, "path": rel_path, "before_sha256": actual_before})
    return checked, matched_allow_rule, matched_deny_rule, None


def build_decision(
    *,
    request: dict[str, Any] | None,
    policy: dict[str, Any] | None,
    policy_hash: str | None,
    source_root: Path,
    decision: str,
    reason_code: str,
    reason_text: str,
    exact_blocker: str | None,
    checked_operations: list[dict[str, Any]] | None = None,
    matched_rule_id: str | None = None,
    rollback_readiness_verified: bool = False,
    event_timestamp: str | None = None,
    sequence_index: int = 1,
    verified_source_hash: str | None = None,
) -> dict[str, Any]:
    request = request if isinstance(request, dict) else {}
    policy = policy if isinstance(policy, dict) else {}
    supplied_proposal_hash = request.get("proposal_hash")
    proposal_hash_verified = canonical_sha256(request.get("proposal_body")) if "proposal_body" in request else None
    supplied_source_hash = request.get("source_tree_hash")
    if verified_source_hash is None:
        try:
            verified_source_hash = source_tree_hash(source_root)
        except Exception:
            verified_source_hash = None
    artifact = {
        "schema_name": DECISION_SCHEMA_NAME,
        "schema_version": "1",
        "request_id": request.get("request_id"),
        "proposal_id": request.get("proposal_id"),
        "policy_id": policy.get("policy_id"),
        "policy_hash": policy_hash,
        "canonical_request_hash": canonical_sha256(request) if request else None,
        "decision": decision,
        "eligible_for_human_approval": decision == "allow",
        "operator_approval_required": True,
        "mutation_authorized": False,
        "mutation_applied": False,
        "declared_actor_id": request.get("declared_actor_id"),
        "actor_identity_authenticated": False,
        "actor_identity_source": "caller_declared",
        "requested_scope": request.get("requested_scope"),
        "checked_paths_and_operations": checked_operations or [],
        "matched_rule_id": matched_rule_id,
        "reason_code": reason_code,
        "reason_text": reason_text,
        "exact_blocker": exact_blocker,
        "proposal_hash_supplied": supplied_proposal_hash,
        "proposal_hash_verified": proposal_hash_verified,
        "source_hash_supplied": supplied_source_hash,
        "source_hash_verified": verified_source_hash,
        "rollback_readiness_verified": rollback_readiness_verified,
        "rollback_requested": False,
        "rollback_executed": False,
        "sequence_index": sequence_index,
        "event_timestamp": event_timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "network_calls": 0,
        "provider_calls": 0,
        "advisor_calls": 0,
        "mem0_runs": 0,
        "benchmark_runs": 0,
    }
    if decision == "allow":
        binding = execution_binding_for(
            request=request,
            policy_hash=policy_hash,
            checked_operations=checked_operations or [],
            matched_rule_id=matched_rule_id,
        )
        artifact["execution_binding"] = binding
        artifact["execution_binding_hash"] = binding["execution_binding_hash"]
    else:
        artifact["execution_binding"] = None
        artifact["execution_binding_hash"] = None
    artifact["audit_event_hash"] = canonical_sha256({k: v for k, v in artifact.items() if k != "audit_event_hash"})
    return artifact


def evaluate_source_mutation_request(
    *,
    policy_path: Path | None,
    request_path: Path | None,
    source_root: Path,
    event_timestamp: str | None = None,
    sequence_index: int = 1,
) -> dict[str, Any]:
    policy, policy_hash, policy_load_error = load_policy(policy_path)
    request, request_load_error = load_request(request_path)
    source_root = source_root.expanduser().resolve(strict=True)

    def deny(reason_code: str, reason_text: str | None = None, *, matched_rule_id: str | None = None) -> dict[str, Any]:
        return build_decision(
            request=request,
            policy=policy,
            policy_hash=policy_hash,
            source_root=source_root,
            decision="deny",
            reason_code=reason_code,
            reason_text=reason_text or reason_code.replace("_", " "),
            exact_blocker=reason_code,
            matched_rule_id=matched_rule_id,
            event_timestamp=event_timestamp,
            sequence_index=sequence_index,
        )

    if policy_load_error:
        return deny(policy_load_error)
    policy_error = validate_policy(policy)
    if policy_error:
        return deny(policy_error)
    if request_load_error:
        return deny(request_load_error)
    request_error = validate_request_shape(request)
    if request_error:
        return deny(request_error)
    assert policy is not None and request is not None

    actor_scope_error = validate_actor_and_scope(policy, request)
    if actor_scope_error:
        return deny(actor_scope_error)
    hash_error = check_request_hashes(request, source_root)
    if hash_error:
        return deny(hash_error)
    checked_ops, allow_rule, deny_rule, operation_error = check_operations(policy, request, source_root)
    if operation_error:
        return deny(operation_error, matched_rule_id=deny_rule or allow_rule)
    rollback_verified, rollback_error = check_rollback_readiness(request, source_root, policy)
    if rollback_error:
        return deny(rollback_error, matched_rule_id=allow_rule)
    return build_decision(
        request=request,
        policy=policy,
        policy_hash=policy_hash,
        source_root=source_root,
        decision="allow",
        reason_code="eligible_for_human_approval",
        reason_text="Request satisfies v0.1 policy gate and is eligible for a separate approval decision only.",
        exact_blocker=None,
        checked_operations=checked_ops,
        matched_rule_id=allow_rule,
        rollback_readiness_verified=rollback_verified,
        event_timestamp=event_timestamp,
        sequence_index=sequence_index,
    )


def verify_decision_artifact(path: Path) -> dict[str, Any]:
    try:
        artifact = read_json_file(path)
    except Exception as exc:
        return {"schema_name": "clu_governance_source_mutation_decision_verification.v1", "verified": False, "exact_blocker": f"decision_read_failed:{exc}"}
    if not isinstance(artifact, dict) or artifact.get("schema_name") != DECISION_SCHEMA_NAME:
        return {"schema_name": "clu_governance_source_mutation_decision_verification.v1", "verified": False, "exact_blocker": "decision_wrong_schema"}
    supplied = artifact.get("audit_event_hash")
    computed = canonical_sha256({k: v for k, v in artifact.items() if k != "audit_event_hash"})
    return {
        "schema_name": "clu_governance_source_mutation_decision_verification.v1",
        "decision_path": str(path),
        "verified": supplied == computed,
        "supplied_audit_event_hash": supplied,
        "computed_audit_event_hash": computed,
        "artifact_integrity_only": True,
        "tamper_evident_audit_log_claim_allowed": False,
        "exact_blocker": None if supplied == computed else "decision_artifact_hash_mismatch",
    }


def write_decision_output(decision: dict[str, Any], output_path: Path, source_root: Path) -> None:
    source_before = source_tree_hash(source_root)
    raw_output = absolute_raw_path(output_path)
    if raw_output.is_symlink():
        raise PolicyGateError("decision_output_symlink_denied")
    if any(component.is_symlink() for component in existing_components(raw_output.parent)):
        raise PolicyGateError("decision_output_parent_symlink_denied")
    try:
        validate_output_outside_roots(raw_output, [source_root], blocker_prefix="decision_output")
        safe_atomic_write_json(raw_output, decision, blocker_prefix="decision_output", create_parent=False)
    except SafeArtifactWriteError as exc:
        raise PolicyGateError(str(exc)) from exc
    source_after = source_tree_hash(source_root)
    if source_after != source_before:
        raise PolicyGateError("decision_output_source_hash_changed")


from .source_mutation_demo_runtime import (  # noqa: E402
    actual_executable_source_root,
    build_demo_policy,
    build_request,
    demo_approve,
    demo_context,
    demo_execute,
    demo_init,
    demo_workspace_marker,
    ensure_artifact_path,
    ensure_demo_workspace,
    unsafe_workspace_path_reason,
    validate_demo_execution_confinement,
    validate_workspace_marker,
    verify_approval_artifact,
)


def demo_run_all() -> dict[str, Any]:
    """Run the standalone denied/eligible/approve/rollback demo in a temp workspace."""

    packaged_source_root = actual_executable_source_root()
    from .protected_source_manifest import protected_source_hash

    packaged_source_before = protected_source_hash()
    temp_root = Path(tempfile.mkdtemp(prefix="clu-governance-standalone-demo.")).resolve()
    workspace = temp_root / "workspace"
    try:
        init = demo_init(workspace, reset=True)
        if init.get("result") != "ready":
            raise PolicyGateError(str(init.get("exact_blocker", "demo_init_failed")))
        artifacts = Path(str(init["policy_path"])).parent
        demo_repo = Path(str(init["demo_repo"]))
        policy = Path(str(init["policy_path"]))
        denied_request = Path(str(init["denied_request_path"]))
        allowed_request = Path(str(init["allowed_request_path"]))
        denied_output = artifacts / "denied_decision.json"
        allowed_output = artifacts / "allowed_decision.json"
        approval_output = artifacts / "approval.json"

        denied_decision = evaluate_source_mutation_request(
            policy_path=policy,
            request_path=denied_request,
            source_root=demo_repo,
            event_timestamp="2026-06-26T00:00:00Z",
        )
        write_decision_output(denied_decision, denied_output, demo_repo)
        denied_exit_code = 0 if denied_decision.get("decision") == "allow" else DENIAL_EXIT_CODE

        allowed_decision = evaluate_source_mutation_request(
            policy_path=policy,
            request_path=allowed_request,
            source_root=demo_repo,
            event_timestamp="2026-06-26T00:00:00Z",
        )
        write_decision_output(allowed_decision, allowed_output, demo_repo)
        verification = verify_decision_artifact(allowed_output)
        approval = demo_approve(
            workspace,
            decision_path=allowed_output,
            approval_path=approval_output,
            decision="approved",
            approval_input_mode="scripted_demo",
        )
        execution = demo_execute(
            workspace=workspace,
            decision_path=allowed_output,
            approval_path=approval_output,
            request_path=allowed_request,
            policy_path=policy,
            source_root=demo_repo,
            packaged_source_root=packaged_source_root,
            retention_decision="rollback_requested",
        )
        packaged_source_after = protected_source_hash()
        checks = {
            "denied_request_blocked": denied_decision.get("decision") == "deny" and denied_exit_code == DENIAL_EXIT_CODE,
            "eligible_request_allowed": allowed_decision.get("decision") == "allow",
            "explicit_approval_recorded": approval.get("result") == "approval_recorded",
            "approved_execution_passed": execution.get("result") == "passed",
            "rollback_verified": execution.get("rollback_executed") is True and execution.get("mutation_present_after_execution") is False,
            "operation_count_correct": execution.get("approved_operation_count") == 1 and execution.get("executed_operation_count") == 1,
            "standalone_source_unchanged": packaged_source_before == packaged_source_after,
            "zero_external_calls": all(
                payload.get(key) == 0
                for payload in [denied_decision, allowed_decision, approval, execution]
                for key in ["provider_calls", "advisor_calls", "mem0_runs", "benchmark_runs", "network_calls"]
                if key in payload
            ),
        }
        result = "passed" if all(checks.values()) else "failed"
        return {
            "schema_name": "clu_governance_standalone_demo_run_all.v1",
            "result": result,
            "workspace": str(workspace),
            "packaged_source_root": str(packaged_source_root),
            "packaged_source_hash_before": packaged_source_before,
            "packaged_source_hash_after": packaged_source_after,
            "checks": checks,
            "denied_exit_code": denied_exit_code,
            "denied_decision": denied_decision,
            "allowed_decision": allowed_decision,
            "verification": verification,
            "approval": approval,
            "approval_input_mode": "scripted_demo",
            "actor_identity_authenticated": False,
            "approval_identity_authenticated": False,
            "human_presence_verified": False,
            "approval_rationale_recorded": False,
            "execution": execution,
            "provider_calls": 0,
            "advisor_calls": 0,
            "mem0_runs": 0,
            "benchmark_runs": 0,
            "network_calls": 0,
            "exact_blocker": None if result == "passed" else "standalone_demo_check_failed",
        }
    except Exception as exc:
        try:
            packaged_source_after = protected_source_hash()
        except Exception:
            packaged_source_after = None
        return {
            "schema_name": "clu_governance_standalone_demo_run_all.v1",
            "result": "blocked",
            "workspace": str(workspace),
            "packaged_source_root": str(packaged_source_root),
            "packaged_source_hash_before": packaged_source_before,
            "packaged_source_hash_after": packaged_source_after,
            "standalone_source_unchanged": packaged_source_before == packaged_source_after,
            "exact_blocker": str(exc),
            "approval_input_mode": "scripted_demo",
            "actor_identity_authenticated": False,
            "approval_identity_authenticated": False,
            "human_presence_verified": False,
            "approval_rationale_recorded": False,
            "provider_calls": 0,
            "advisor_calls": 0,
            "mem0_runs": 0,
            "benchmark_runs": 0,
            "network_calls": 0,
        }


def print_payload(payload: dict[str, Any], *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif "decision" in payload:
        print(f"decision={payload['decision']} reason={payload.get('reason_code', 'unknown')}")
    elif "verified" in payload:
        print(f"verified={str(bool(payload['verified'])).lower()}")
    else:
        print(f"result={payload.get('result', 'unknown')}")


def bounded_cli_error(exc: Exception) -> str:
    """Return useful bounded error text without local paths or credential-shaped data."""

    message = str(exc).strip() or exc.__class__.__name__
    home = str(Path.home())
    if home:
        message = message.replace(home, "<home>")
    message = re.sub(r"[^\s/]*private[^\s/]*\.zip", "<private-archive>", message, flags=re.IGNORECASE)
    message = re.sub(r"\b(?:gh[pousr]_|sk-)[A-Za-z0-9_-]{12,}\b", "<redacted-credential>", message)
    return message[:500]


def main(argv: list[str] | None = None) -> int:
    from . import __version__ as package_version

    parser = argparse.ArgumentParser(
        description="Evaluate CLU Governance source-mutation policy decisions through a local-first command surface.",
        epilog=HELP_BOUNDARY,
    )
    parser.add_argument("--version", action="version", version=f"clu-governance {package_version}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate_parser = subparsers.add_parser(
        "evaluate",
        help="Evaluate a request without mutating the source root.",
        description=f"{HELP_BOUNDARY} Evaluate a request without mutating the source root.",
    )
    evaluate_parser.add_argument("--policy", required=True)
    evaluate_parser.add_argument("--request", required=True)
    evaluate_parser.add_argument("--source-root", required=True)
    evaluate_parser.add_argument("--output", required=True)
    evaluate_parser.add_argument("--event-time")
    evaluate_parser.add_argument("--sequence-index", type=int, default=1)
    evaluate_parser.add_argument("--json", action="store_true")

    agent_preflight_parser = subparsers.add_parser(
        "agent-preflight",
        help="Evaluate one strict JSON stdin envelope without writing or applying a mutation.",
        description=(
            f"{HELP_BOUNDARY} Read one strict JSON adapter envelope from stdin, delegate to the "
            "existing read-only evaluator, and write one JSON decision to stdout. This command does not "
            "write an artifact, record approval, apply a mutation, or start an agent subprocess."
        ),
    )
    agent_preflight_parser.add_argument(
        "--json",
        action="store_true",
        help="Compatibility flag; agent-preflight always writes one JSON object to stdout.",
    )

    verify_parser = subparsers.add_parser(
        "verify", help="Verify a decision artifact hash.", description=f"{HELP_BOUNDARY} Verify a decision artifact hash."
    )
    verify_parser.add_argument("--decision", required=True)
    verify_parser.add_argument("--json", action="store_true")

    verify_bundle_parser = subparsers.add_parser(
        "verify-bundle",
        help="Verify a currently published Git-adapter bundle without modifying it.",
        description=(
            f"{HELP_BOUNDARY} Verify the exact file set, checksums, completion, "
            "publication binding, and governed artifacts of one local bundle. "
            "This verifies current bytes; it does not make the bundle immutable."
        ),
    )
    verify_bundle_parser.add_argument("--bundle", required=True)
    verify_bundle_parser.add_argument("--json", action="store_true")

    protected_manifest_parser = subparsers.add_parser(
        "protected-source-manifest",
        help="Report the exact CLU Governance protected-source ownership manifest.",
        description=(
            f"{HELP_BOUNDARY} Report the exact package and distribution-metadata files "
            "protected in the current source, editable, or wheel execution mode without changing them."
        ),
    )
    protected_manifest_parser.add_argument("--json", action="store_true")

    init_parser = subparsers.add_parser(
        "demo-init",
        help="Create a marker-owned temporary demo repo and requests.",
        description=f"{HELP_BOUNDARY} Create a marker-owned temporary demo repo and requests.",
    )
    init_parser.add_argument("--workspace", required=True)
    init_parser.add_argument("--reset", action="store_true")
    init_parser.add_argument("--json", action="store_true")

    approve_parser = subparsers.add_parser(
        "demo-approve",
        help="Record a separate caller-supplied approval decision for an allow decision.",
        description=f"{HELP_BOUNDARY} Record a separate caller-supplied, unauthenticated approval decision.",
    )
    approve_parser.add_argument("--workspace", required=True)
    approve_parser.add_argument("--decision-artifact", required=True)
    approve_parser.add_argument("--approval-output", required=True)
    approve_parser.add_argument("--decision", choices=("approved", "rejected"), required=True)
    approve_parser.add_argument("--json", action="store_true")

    execute_parser = subparsers.add_parser(
        "demo-execute",
        help="Apply a temporary demo mutation only after revalidation and approval.",
        description=f"{HELP_BOUNDARY} Apply a temporary demo mutation only after exact revalidation and approval.",
    )
    execute_parser.add_argument("--workspace", required=True)
    execute_parser.add_argument("--policy", required=True)
    execute_parser.add_argument("--request", required=True)
    execute_parser.add_argument("--decision-artifact", required=True)
    execute_parser.add_argument("--approval", required=True)
    execute_parser.add_argument("--source-root", required=True)
    execute_parser.add_argument("--packaged-source-root", required=True)
    execute_parser.add_argument("--retention-decision", default="rollback_requested", choices=("rollback_requested", "keep"))
    execute_parser.add_argument("--json", action="store_true")

    run_all_parser = subparsers.add_parser(
        "demo-run-all",
        help="Run the complete scripted local demo in a marker-owned temp workspace.",
        description=f"{HELP_BOUNDARY} Run the complete scripted local demo in a marker-owned temp workspace.",
    )
    run_all_parser.add_argument("--json", action="store_true")

    git_adapt_parser = subparsers.add_parser(
        "git-adapt",
        help="Experimental: adapt one trusted-local tracked unstaged UTF-8 Git modification into governed artifacts without changing the repository.",
        description=(
            f"{HELP_BOUNDARY} EXPERIMENTAL TRUSTED-LOCAL BOUNDARY: git-adapt is intended for "
            "single-user local repositories. It is not a sandbox and does not defend against a malicious Git executable, "
            "hostile local process, operating-system administrator, concurrent same-user filesystem modification, or tampering "
            "after point-in-time verification. Read only one local tracked unstaged UTF-8 text modification, build a one-file "
            "HEAD baseline bundle outside the repository, and evaluate it without approval, apply, commit, or push."
        ),
    )
    git_adapt_parser.add_argument("--repo", required=True)
    git_adapt_parser.add_argument("--policy", required=True)
    git_adapt_parser.add_argument("--declared-actor-id", required=True)
    git_adapt_parser.add_argument("--scope", required=True)
    git_adapt_parser.add_argument("--output-dir", required=True)
    git_adapt_parser.add_argument("--event-time")
    git_adapt_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "evaluate":
            source_root = Path(args.source_root)
            output = Path(args.output)
            decision = evaluate_source_mutation_request(
                policy_path=Path(args.policy),
                request_path=Path(args.request),
                source_root=source_root,
                event_timestamp=args.event_time,
                sequence_index=args.sequence_index,
            )
            write_decision_output(decision, output, source_root)
            print_payload(decision, json_output=bool(args.json))
            return 0 if decision["decision"] == "allow" else DENIAL_EXIT_CODE
        if args.command == "agent-preflight":
            from .agent_preflight import main as agent_preflight_main

            return agent_preflight_main([])
        if args.command == "verify":
            result = verify_decision_artifact(Path(args.decision))
            print_payload(result, json_output=bool(args.json))
            return 0 if result["verified"] is True else DENIAL_EXIT_CODE
        if args.command == "verify-bundle":
            from .bundle_verifier import exit_code_for_result as bundle_exit_code
            from .bundle_verifier import verify_bundle

            result = verify_bundle(Path(args.bundle))
            print_payload(result, json_output=bool(args.json))
            return bundle_exit_code(result)
        if args.command == "protected-source-manifest":
            from .protected_source_manifest import (
                ProtectedSourceManifestError,
                diagnostic_manifest,
            )

            try:
                result = diagnostic_manifest()
            except ProtectedSourceManifestError as exc:
                result = {
                    "schema_name": "clu_governance_protected_source_manifest.v1",
                    "schema_version": "1",
                    "result": "blocked",
                    "exact_blocker": str(exc),
                    "provider_calls": 0,
                    "advisor_calls": 0,
                    "mem0_runs": 0,
                    "benchmark_runs": 0,
                    "network_calls": 0,
                }
                print_payload(result, json_output=bool(args.json))
                return DENIAL_EXIT_CODE
            print_payload(result, json_output=bool(args.json))
            return 0
        if args.command == "demo-init":
            result = demo_init(Path(args.workspace), reset=bool(args.reset))
            print_payload(result, json_output=bool(args.json))
            return 0 if result.get("result") == "ready" else DENIAL_EXIT_CODE
        if args.command == "demo-approve":
            result = demo_approve(
                Path(args.workspace),
                decision_path=Path(args.decision_artifact),
                approval_path=Path(args.approval_output),
                decision=args.decision,
            )
            print_payload(result, json_output=bool(args.json))
            return 0 if result["result"] == "approval_recorded" else DENIAL_EXIT_CODE
        if args.command == "demo-execute":
            result = demo_execute(
                workspace=Path(args.workspace),
                decision_path=Path(args.decision_artifact),
                approval_path=Path(args.approval),
                request_path=Path(args.request),
                policy_path=Path(args.policy),
                source_root=Path(args.source_root),
                packaged_source_root=Path(args.packaged_source_root),
                retention_decision=args.retention_decision,
            )
            print_payload(result, json_output=bool(args.json))
            return 0 if result["result"] == "passed" else DENIAL_EXIT_CODE
        if args.command == "demo-run-all":
            result = demo_run_all()
            print_payload(result, json_output=bool(args.json))
            return 0 if result["result"] == "passed" else DENIAL_EXIT_CODE
        if args.command == "git-adapt":
            from .git_diff_adapter import adapt_git_diff, exit_code_for_result

            result = adapt_git_diff(
                repo_path=Path(args.repo),
                policy_path=Path(args.policy),
                declared_actor_id=args.declared_actor_id,
                requested_scope=args.scope,
                output_dir=Path(args.output_dir),
                event_time=args.event_time,
            )
            print_payload(result, json_output=bool(args.json))
            return exit_code_for_result(result)
    except Exception as exc:  # pragma: no cover - CLI defensive boundary.
        payload = {
            "schema_name": "clu_governance_source_mutation_policy_gate_error.v1",
            "result": "failed",
            "exact_blocker": bounded_cli_error(exc),
            "provider_calls": 0,
            "advisor_calls": 0,
            "mem0_runs": 0,
            "benchmark_runs": 0,
            "network_calls": 0,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
