"""Marker-owned demo runtime for the source-mutation policy gate.

This module contains the bounded mutation-capable demo path. The policy gate
module remains the read-only evaluator and command shim.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import strict_json
from .protected_source_manifest import (
    build_protected_source_manifest,
    protected_source_hash,
    protected_source_roots,
)

POLICY_SCHEMA_NAME = "clu_governance_source_mutation_policy.v1"
REQUEST_SCHEMA_NAME = "clu_governance_source_mutation_request.v1"
ROLLBACK_SCHEMA_NAME = "clu_governance_source_mutation_rollback_readiness.v1"
APPROVAL_SCHEMA_NAME = "clu_governance_source_mutation_demo_approval.v1"
EXECUTION_SCHEMA_NAME = "clu_governance_source_mutation_demo_execution.v1"
WORKSPACE_SCHEMA_NAME = "clu_source_mutation_policy_gate_demo_workspace.v1"
WORKSPACE_SCHEMA_VERSION = "1"
DEMO_CREATED_BY = "clu_governance.source_mutation_policy_gate"

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

POST_APPLY_TEST_HOOK: Any = None


class PostApplyFailure(Exception):
    def __init__(self, blocker: str) -> None:
        super().__init__(blocker)
        self.blocker = blocker


def _gate() -> Any:
    main = sys.modules.get("__main__")
    if getattr(main, "__package__", None) == "clu_governance" and hasattr(main, "evaluate_source_mutation_request"):
        return main
    from . import source_mutation_policy_gate as gate

    return gate


def _raise(blocker: str) -> None:
    raise _gate().PolicyGateError(blocker)


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _paths_overlap(first: Path, second: Path) -> bool:
    first_resolved = first.expanduser().resolve(strict=False)
    second_resolved = second.expanduser().resolve(strict=False)
    return _is_relative_to(first_resolved, second_resolved) or _is_relative_to(second_resolved, first_resolved)


def _absolute_raw_path(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_absolute():
        return expanded
    return Path.cwd() / expanded


def _existing_components(path: Path) -> list[Path]:
    absolute = _absolute_raw_path(path)
    if not absolute.parts:
        return []
    current = Path(absolute.anchor)
    components = [current]
    for part in absolute.parts[1:]:
        current = current / part
        if current.exists() or current.is_symlink():
            components.append(current)
            continue
        break
    return components


def _has_existing_symlink_component(path: Path) -> bool:
    return any(component.is_symlink() for component in _existing_components(path))


def actual_executable_source_root() -> Path:
    manifest = build_protected_source_manifest()
    package_root = Path(str(manifest["package_root"]))
    # Preserve the documented source/editable ``src`` argument surface.  A
    # wheel has no source-layout parent, so its exact package directory is the
    # compatibility root; it is never widened to all of site-packages.
    if manifest["distribution_mode"] in {"source_tree", "editable_install"}:
        return package_root.parent
    return package_root


def unsafe_workspace_path_reason(workspace: Path) -> str | None:
    raw_absolute = _absolute_raw_path(workspace)
    if raw_absolute == Path(raw_absolute.anchor):
        return "demo_workspace_reserved_path_denied"
    if raw_absolute.is_symlink():
        return "demo_workspace_symlink_denied"
    components = _existing_components(workspace)
    if any(component.is_symlink() for component in components[:-1]):
        return "demo_workspace_parent_symlink_denied"
    if components and components[-1].is_symlink() and components[-1] == raw_absolute:
        return "demo_workspace_symlink_denied"
    if components and components[-1].is_symlink():
        return "demo_workspace_parent_symlink_denied"
    if raw_absolute.exists() and not raw_absolute.is_dir():
        return "demo_workspace_not_directory"

    resolved = raw_absolute.resolve(strict=False)
    home = Path.home().resolve(strict=False)
    cwd = Path.cwd().resolve(strict=False)
    if resolved == home:
        return "demo_workspace_reserved_path_denied"
    if any(_paths_overlap(resolved, protected) for protected in protected_source_roots()):
        return "demo_workspace_actual_source_overlap_denied"
    if resolved == cwd:
        return "demo_workspace_current_working_directory_denied"
    return None


def demo_workspace_marker(workspace: Path) -> Path:
    return workspace / DEMO_MARKER_FILENAME


def write_json_file(path: Path, payload: Any) -> None:
    data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _atomic_replace_bytes(path, data, mode=0o644)


def _read_json_file(path: Path) -> Any:
    return strict_json.loads(path.read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    return _gate().sha256_file(path)


def _sha256_bytes(data: bytes) -> str:
    return _gate().sha256_bytes(data)


def _canonical_sha256(payload: Any) -> str:
    return _gate().canonical_sha256(payload)


def _source_tree_hash(path: Path) -> str:
    return _gate().source_tree_hash(path)


def _safe_source_tree_hash(path: Path) -> str | None:
    return _gate().safe_source_tree_hash(path)


def _normalize_relative_path(raw_path: Any) -> str:
    return _gate().normalize_relative_path(raw_path)


def _validate_rollback_artifact_contents(
    *,
    request: dict[str, Any],
    source_root: Path,
    require_current_target_hash: bool,
) -> tuple[dict[str, Any] | None, str | None]:
    return _gate().validate_rollback_artifact_contents(
        request=request,
        source_root=source_root,
        require_current_target_hash=require_current_target_hash,
    )


def _payload_integrity_hash(payload: dict[str, Any], field_name: str) -> str:
    return _gate().payload_integrity_hash(payload, field_name)


def _require_real_directory(path: Path, blocker: str) -> None:
    if path.is_symlink():
        _raise("demo_workspace_reset_symlink_blocked")
    if not path.exists():
        _raise(f"{blocker}_missing")
    if not path.is_dir():
        _raise(f"{blocker}_wrong_type")


def _require_regular_file(path: Path, blocker: str) -> None:
    if path.is_symlink():
        _raise("demo_workspace_reset_symlink_blocked")
    if not path.exists():
        _raise(f"{blocker}_missing")
    if not path.is_file():
        _raise(f"{blocker}_wrong_type")


def validate_workspace_marker(workspace: Path) -> dict[str, Any]:
    unsafe = unsafe_workspace_path_reason(workspace)
    if unsafe:
        _raise(unsafe)
    workspace_resolved = _absolute_raw_path(workspace).resolve(strict=True)
    marker = demo_workspace_marker(workspace_resolved)
    _require_regular_file(marker, "demo_workspace_marker")
    marker_payload = _read_json_file(marker)
    if marker_payload.get("schema_name") != WORKSPACE_SCHEMA_NAME or marker_payload.get("schema_version") != WORKSPACE_SCHEMA_VERSION:
        _raise("demo_workspace_marker_invalid")
    if marker_payload.get("canonical_workspace_path") != str(workspace_resolved):
        _raise("demo_workspace_marker_path_mismatch")
    if marker_payload.get("created_by") != DEMO_CREATED_BY or not marker_payload.get("workspace_id"):
        _raise("demo_workspace_marker_identity_invalid")
    return marker_payload


def _validate_initialized_inventory(workspace: Path) -> None:
    marker = demo_workspace_marker(workspace)
    _require_regular_file(marker, "demo_workspace_marker")

    for item in workspace.iterdir():
        if item.is_symlink():
            _raise("demo_workspace_reset_symlink_blocked")
        if item.name not in DEMO_TOP_LEVEL_ALLOWLIST:
            _raise("demo_workspace_unexpected_content_blocked")

    demo_repo = workspace / "demo_repo"
    artifacts = workspace / "artifacts"
    _require_real_directory(demo_repo, "demo_workspace_expected_directory")
    _require_real_directory(artifacts, "demo_workspace_expected_directory")

    readme = demo_repo / "README.md"
    for child in demo_repo.iterdir():
        if child.is_symlink():
            _raise("demo_workspace_reset_symlink_blocked")
        if child.name != "README.md":
            _raise("demo_workspace_unexpected_content_blocked")
    _require_regular_file(readme, "demo_workspace_expected_file")

    for child in artifacts.iterdir():
        if child.is_symlink():
            _raise("demo_workspace_reset_symlink_blocked")
        if child.name not in DEMO_ARTIFACT_ALLOWLIST:
            _raise("demo_workspace_unexpected_content_blocked")
        if not child.is_file():
            _raise("demo_workspace_expected_file_wrong_type")


def _clear_validated_initialized_workspace(workspace: Path) -> None:
    _validate_initialized_inventory(workspace)
    readme = workspace / "demo_repo" / "README.md"
    readme.unlink()
    for child in list((workspace / "artifacts").iterdir()):
        child.unlink()
    (workspace / "artifacts").rmdir()
    (workspace / "demo_repo").rmdir()


def ensure_demo_workspace(workspace: Path, *, reset: bool = False) -> Path:
    unsafe = unsafe_workspace_path_reason(workspace)
    if unsafe:
        _raise(unsafe)
    raw_absolute = _absolute_raw_path(workspace)
    if raw_absolute.exists() and not raw_absolute.is_dir():
        _raise("demo_workspace_not_directory")
    if not raw_absolute.exists():
        raw_absolute.mkdir(parents=True)
    workspace_resolved = raw_absolute.resolve(strict=True)
    marker = demo_workspace_marker(workspace_resolved)
    contents = list(workspace_resolved.iterdir())

    if marker.exists() or marker.is_symlink():
        validate_workspace_marker(workspace_resolved)
        _validate_initialized_inventory(workspace_resolved)
        if not reset:
            _raise("demo_workspace_reset_required")
        _clear_validated_initialized_workspace(workspace_resolved)
        return workspace_resolved

    if contents:
        _raise("demo_workspace_nonempty_without_marker")

    write_json_file(
        marker,
        {
            "schema_name": WORKSPACE_SCHEMA_NAME,
            "schema_version": WORKSPACE_SCHEMA_VERSION,
            "canonical_workspace_path": str(workspace_resolved),
            "created_by": DEMO_CREATED_BY,
            "workspace_id": str(uuid.uuid4()),
            "allowlisted_top_level": sorted(DEMO_TOP_LEVEL_ALLOWLIST),
            "allowlisted_artifacts": sorted(DEMO_ARTIFACT_ALLOWLIST),
        },
    )
    return workspace_resolved


def demo_context(workspace: Path, *, require_initialized: bool = True) -> dict[str, Any]:
    unsafe = unsafe_workspace_path_reason(workspace)
    if unsafe:
        _raise(unsafe)
    workspace_resolved = _absolute_raw_path(workspace).resolve(strict=True)
    marker = validate_workspace_marker(workspace_resolved)
    demo_repo = workspace_resolved / "demo_repo"
    artifacts = workspace_resolved / "artifacts"
    if require_initialized:
        if demo_repo.is_symlink() or not demo_repo.exists() or not demo_repo.is_dir():
            _raise("demo_repo_not_real_directory")
        if artifacts.is_symlink() or not artifacts.exists() or not artifacts.is_dir():
            _raise("artifacts_not_real_directory")
    return {
        "workspace": workspace_resolved,
        "marker": marker,
        "workspace_id": marker["workspace_id"],
        "demo_repo": demo_repo,
        "artifacts": artifacts,
    }


def ensure_artifact_path(path: Path, ctx: dict[str, Any], *, must_exist: bool, output: bool = False) -> Path:
    artifacts = ctx["artifacts"].resolve(strict=True)
    raw = path.expanduser()
    if raw.is_symlink():
        _raise("demo_artifact_symlink_denied")
    resolved = raw.resolve(strict=False)
    if not _is_relative_to(resolved, artifacts):
        _raise("demo_artifact_path_outside_workspace")
    if resolved.parent.resolve(strict=True) != artifacts:
        _raise("demo_artifact_nested_path_denied")
    if resolved.name not in DEMO_ARTIFACT_ALLOWLIST and not output:
        _raise("demo_artifact_not_allowlisted")
    if must_exist:
        if not resolved.exists() or not resolved.is_file() or resolved.is_symlink():
            _raise("demo_artifact_file_invalid")
    elif resolved.exists() and (not resolved.is_file() or resolved.is_symlink()):
        _raise("demo_artifact_output_invalid")
    return resolved


def validate_demo_execution_confinement(
    *,
    workspace: Path,
    source_root: Path,
    packaged_source_root: Path,
    policy_path: Path,
    request_path: Path,
    decision_path: Path,
    approval_path: Path,
) -> dict[str, Any]:
    actual_source_root = actual_executable_source_root()
    packaged_resolved = packaged_source_root.expanduser().resolve(strict=True)
    if packaged_resolved != actual_source_root:
        _raise("false_packaged_source_root_mismatch")

    ctx = demo_context(workspace, require_initialized=True)
    workspace_path = ctx["workspace"]
    if any(_paths_overlap(workspace_path, protected) for protected in protected_source_roots()):
        _raise("workspace_actual_source_overlap_denied")

    demo_repo = ctx["demo_repo"]
    artifacts = ctx["artifacts"]
    source_raw = source_root.expanduser()
    if source_raw.is_symlink() or source_raw.resolve(strict=False) != demo_repo.resolve(strict=True):
        _raise("source_root_not_marker_owned_demo_repo")
    if artifacts.is_symlink() or artifacts.resolve(strict=True) != (workspace_path / "artifacts").resolve(strict=True):
        _raise("artifacts_directory_not_marker_owned")
    for file_path in [policy_path, request_path, decision_path, approval_path]:
        ensure_artifact_path(file_path, ctx, must_exist=True, output=True)
    return ctx


def build_demo_policy() -> dict[str, Any]:
    return {
        "schema_name": POLICY_SCHEMA_NAME,
        "schema_version": "1",
        "policy_id": DEMO_POLICY_ID,
        "default_decision": "deny",
        "allowed_declared_actor_ids": ["demo_operator"],
        "allowed_actor_classes": ["operator"],
        "allowed_scopes": ["docs_only"],
        "allowed_operations": ["modify"],
        "allowed_paths": ["README.md"],
        "allowed_path_prefixes": [],
        "allowed_path_globs": ["*.md"],
        "denied_paths": [".env", ".env.local"],
        "denied_path_prefixes": [".git", "clu", "SOURCE", "secrets"],
        "denied_path_globs": ["*.py", "*.pem", "*.key"],
        "maximum_file_count": 1,
        "rollback_readiness_required": True,
        "rules": [
            {"rule_id": "deny-sensitive-or-source-code", "effect": "deny", "operations": ["modify", "delete", "rename", "chmod", "symlink"], "path_prefixes": [".git", "clu", "SOURCE", "secrets"], "path_globs": ["*.py", "*.pem", "*.key"]},
            {"rule_id": "allow-doc-readme-modify", "effect": "allow", "operations": ["modify"], "paths": ["README.md"]},
        ],
    }


def build_request(
    *,
    request_id: str,
    proposal_id: str,
    proposal_body: dict[str, Any],
    operation: str,
    path: str,
    source_root: Path,
    rollback_artifact: Path | None,
    declared_actor_id: str = "demo_operator",
    requested_scope: str = "docs_only",
) -> dict[str, Any]:
    rel_path = _normalize_relative_path(path)
    target = source_root / rel_path
    before_hash = _sha256_file(target) if target.exists() and target.is_file() and not target.is_symlink() else None
    request: dict[str, Any] = {
        "schema_name": REQUEST_SCHEMA_NAME,
        "schema_version": "1",
        "request_id": request_id,
        "declared_actor_id": declared_actor_id,
        "actor_identity_source": "caller_declared",
        "requested_scope": requested_scope,
        "proposal_id": proposal_id,
        "proposal_body": proposal_body,
        "proposal_hash": _canonical_sha256(proposal_body),
        "source_tree_hash": _source_tree_hash(source_root),
        "operations": [{"operation": operation, "path": rel_path, "before_sha256": before_hash}],
    }
    if rollback_artifact is not None:
        readiness = {
            "schema_name": ROLLBACK_SCHEMA_NAME,
            "schema_version": "1",
            "artifact_path": str(rollback_artifact),
            "artifact_sha256": _sha256_file(rollback_artifact),
            "files": {rel_path: {"before_sha256": before_hash}},
        }
        request["rollback_readiness"] = readiness
    return request


def _atomic_replace_bytes(path: Path, data: bytes, *, mode: int | None = None) -> str:
    parent = path.parent
    if parent.is_symlink() or not parent.exists() or not parent.is_dir():
        _raise("atomic_write_parent_invalid")
    if path.is_symlink():
        _raise("atomic_write_target_symlink_denied")
    temp_path = parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temp_path, flags, mode or 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(temp_path, mode)
        if _sha256_file(temp_path) != _sha256_bytes(data):
            _raise("atomic_write_temp_hash_mismatch")
        os.replace(temp_path, path)
    except Exception:
        try:
            if temp_path.exists() or temp_path.is_symlink():
                temp_path.unlink()
        finally:
            raise
    return _sha256_file(path)


def _write_text_file(path: Path, content: str, *, mode: int = 0o644) -> None:
    _atomic_replace_bytes(path, content.encode("utf-8"), mode=mode)


def _safe_mkdir_child(parent: Path, name: str) -> Path:
    child = parent / name
    if child.exists() or child.is_symlink():
        _raise("demo_workspace_expected_absent_before_init")
    child.mkdir()
    return child


def demo_init(workspace: Path, *, reset: bool = False) -> dict[str, Any]:
    try:
        workspace = ensure_demo_workspace(workspace, reset=reset)
        artifacts = _safe_mkdir_child(workspace, "artifacts")
        demo_repo = _safe_mkdir_child(workspace, "demo_repo")
        readme = demo_repo / "README.md"
        _write_text_file(readme, DEMO_INITIAL_README)
        policy = build_demo_policy()
        policy_path = artifacts / "demo_policy.json"
        write_json_file(policy_path, policy)
        rollback_snapshot = {
            "schema_name": ROLLBACK_SCHEMA_NAME,
            "schema_version": "1",
            "snapshot_id": "demo-readme-snapshot",
            "files": {
                "README.md": {
                    "path": "README.md",
                    "before_sha256": _sha256_file(readme),
                    "original_content": DEMO_INITIAL_README,
                    "content_encoding": "utf-8",
                }
            },
        }
        rollback_path = artifacts / "rollback_snapshot.json"
        write_json_file(rollback_path, rollback_snapshot)
        allowed_proposal = {
            "proposal_id": DEMO_ALLOWED_PROPOSAL_ID,
            "description": "Modify README.md documentation in the temporary demo repository.",
            "new_content": DEMO_PROPOSED_README,
        }
        denied_proposal = {
            "proposal_id": DEMO_DENIED_PROPOSAL_ID,
            "description": "Attempt to delete source code in the temporary demo repository.",
            "target": "clu/danger.py",
        }
        allowed_request = build_request(
            request_id=DEMO_ALLOWED_REQUEST_ID,
            proposal_id=DEMO_ALLOWED_PROPOSAL_ID,
            proposal_body=allowed_proposal,
            operation="modify",
            path="README.md",
            source_root=demo_repo,
            rollback_artifact=rollback_path,
        )
        denied_request = build_request(
            request_id=DEMO_DENIED_REQUEST_ID,
            proposal_id=DEMO_DENIED_PROPOSAL_ID,
            proposal_body=denied_proposal,
            operation="delete",
            path="clu/danger.py",
            source_root=demo_repo,
            rollback_artifact=None,
        )
        allowed_request_path = artifacts / "allowed_request.json"
        denied_request_path = artifacts / "denied_request.json"
        write_json_file(allowed_request_path, allowed_request)
        write_json_file(denied_request_path, denied_request)
        return {
            "schema_name": "clu_source_mutation_policy_gate_demo_init.v1",
            "result": "ready",
            "workspace": str(workspace),
            "demo_repo": str(demo_repo),
            "policy_path": str(policy_path),
            "allowed_request_path": str(allowed_request_path),
            "denied_request_path": str(denied_request_path),
            "rollback_snapshot_path": str(rollback_path),
            "source_tree_hash": _source_tree_hash(demo_repo),
            "provider_calls": 0,
            "advisor_calls": 0,
            "mem0_runs": 0,
            "benchmark_runs": 0,
            "network_calls": 0,
        }
    except Exception as exc:
        return {
            "schema_name": "clu_source_mutation_policy_gate_demo_init.v1",
            "result": "blocked",
            "exact_blocker": str(exc),
            "mutation_applied": False,
            "provider_calls": 0,
            "advisor_calls": 0,
            "mem0_runs": 0,
            "benchmark_runs": 0,
            "network_calls": 0,
        }


def demo_approve(
    workspace: Path,
    *,
    decision_path: Path,
    approval_path: Path,
    decision: str,
    approval_input_mode: str = "cli_argument",
) -> dict[str, Any]:
    if decision not in {"approved", "rejected"}:
        _raise("approval_decision_invalid")
    if approval_input_mode not in {"cli_argument", "scripted_demo"}:
        _raise("approval_input_mode_invalid")
    try:
        ctx = demo_context(workspace, require_initialized=True)
        decision_path = ensure_artifact_path(decision_path, ctx, must_exist=True, output=True)
        approval_path = ensure_artifact_path(approval_path, ctx, must_exist=False, output=True)
    except Exception as exc:
        return {
            "schema_name": APPROVAL_SCHEMA_NAME,
            "result": "blocked",
            "exact_blocker": str(exc),
            "approval_recorded": False,
            "mutation_applied": False,
            "provider_calls": 0,
            "advisor_calls": 0,
            "mem0_runs": 0,
            "benchmark_runs": 0,
            "network_calls": 0,
        }
    gate_decision = _read_json_file(decision_path)
    if gate_decision.get("decision") != "allow":
        return {
            "schema_name": APPROVAL_SCHEMA_NAME,
            "result": "blocked",
            "exact_blocker": "policy_denial_cannot_be_approved",
            "approval_recorded": False,
            "provider_calls": 0,
            "advisor_calls": 0,
            "mem0_runs": 0,
            "benchmark_runs": 0,
            "network_calls": 0,
        }
    verification = _gate().verify_decision_artifact(decision_path)
    if verification.get("verified") is not True:
        return {
            "schema_name": APPROVAL_SCHEMA_NAME,
            "result": "blocked",
            "exact_blocker": "decision_artifact_hash_mismatch",
            "approval_recorded": False,
            "provider_calls": 0,
            "advisor_calls": 0,
            "mem0_runs": 0,
            "benchmark_runs": 0,
            "network_calls": 0,
        }
    approval = {
        "schema_name": APPROVAL_SCHEMA_NAME,
        "schema_version": "1",
        "approval_id": DEMO_APPROVAL_ID,
        "request_id": gate_decision.get("request_id"),
        "proposal_id": gate_decision.get("proposal_id"),
        "decision_artifact_hash": _sha256_file(decision_path),
        "audit_event_hash": gate_decision.get("audit_event_hash"),
        "execution_binding_hash": gate_decision.get("execution_binding_hash"),
        "canonical_policy_hash": gate_decision.get("policy_hash"),
        "canonical_request_hash": gate_decision.get("canonical_request_hash"),
        "decision": decision,
        "approved": decision == "approved",
        "approval_input_mode": approval_input_mode,
        "operator_input_required": True,
        "actor_identity_authenticated": False,
        "approval_identity_authenticated": False,
        "human_presence_verified": False,
        "approval_rationale_recorded": False,
    }
    approval["approval_artifact_hash"] = _payload_integrity_hash(approval, "approval_artifact_hash")
    write_json_file(approval_path, approval)
    return {
        "schema_name": APPROVAL_SCHEMA_NAME,
        "result": "approval_recorded",
        "approval_path": str(approval_path),
        "approval_hash": _sha256_file(approval_path),
        "decision": decision,
        "approved": decision == "approved",
        "approval_input_mode": approval_input_mode,
        "actor_identity_authenticated": False,
        "approval_identity_authenticated": False,
        "human_presence_verified": False,
        "approval_rationale_recorded": False,
        "mutation_applied": False,
        "provider_calls": 0,
        "advisor_calls": 0,
        "mem0_runs": 0,
        "benchmark_runs": 0,
        "network_calls": 0,
    }


def verify_approval_artifact(path: Path) -> dict[str, Any]:
    try:
        artifact = _read_json_file(path)
    except Exception as exc:
        return {"schema_name": "clu_governance_source_mutation_approval_verification.v1", "verified": False, "exact_blocker": f"approval_read_failed:{exc}"}
    if not isinstance(artifact, dict) or artifact.get("schema_name") != APPROVAL_SCHEMA_NAME or artifact.get("schema_version") != "1":
        return {"schema_name": "clu_governance_source_mutation_approval_verification.v1", "verified": False, "exact_blocker": "approval_wrong_schema"}
    supplied = artifact.get("approval_artifact_hash")
    computed = _payload_integrity_hash(artifact, "approval_artifact_hash")
    return {
        "schema_name": "clu_governance_source_mutation_approval_verification.v1",
        "approval_path": str(path),
        "verified": supplied == computed,
        "supplied_approval_artifact_hash": supplied,
        "computed_approval_artifact_hash": computed,
        "artifact_integrity_only": True,
        "approval_signature_claim_allowed": False,
        "exact_blocker": None if supplied == computed else "approval_artifact_hash_mismatch",
    }


def _validate_package_root_assertion(packaged_source_root: Path) -> tuple[Path, str | None, str | None]:
    actual_source_root = actual_executable_source_root()
    try:
        before_hash = protected_source_hash()
    except Exception:
        return actual_source_root, None, "protected_source_manifest_invalid"
    try:
        caller_root = packaged_source_root.expanduser().resolve(strict=True)
    except Exception:
        return actual_source_root, before_hash, "false_packaged_source_root_mismatch"
    if caller_root != actual_source_root:
        return actual_source_root, before_hash, "false_packaged_source_root_mismatch"
    return actual_source_root, before_hash, None


def _restore_preimage(target: Path, original_bytes: bytes, mode: int, pre_apply_hash: str) -> tuple[bool, str | None]:
    try:
        _atomic_replace_bytes(target, original_bytes, mode=mode)
        final_hash = _sha256_file(target)
        return final_hash == pre_apply_hash, final_hash
    except Exception:
        try:
            return False, _sha256_file(target)
        except Exception:
            return False, None


def _target_hash(path: Path) -> str | None:
    try:
        if path.exists() and path.is_file() and not path.is_symlink():
            return _sha256_file(path)
    except Exception:
        return None
    return None


def _target_state(path: Path, *, pre_apply_target_hash: str | None = None) -> dict[str, Any]:
    state: dict[str, Any] = {
        "final_target_kind": "unreadable",
        "final_target_hash": None,
        "final_target_mode": None,
        "target_restored_to_preimage": False,
    }
    try:
        status = path.lstat()
    except FileNotFoundError:
        state["final_target_kind"] = "missing"
        return state
    except OSError:
        return state

    mode = stat.S_IMODE(status.st_mode)
    state["final_target_mode"] = oct(mode)
    if stat.S_ISLNK(status.st_mode):
        state["final_target_kind"] = "symlink"
        return state
    if stat.S_ISDIR(status.st_mode):
        state["final_target_kind"] = "directory"
        return state
    if not stat.S_ISREG(status.st_mode):
        state["final_target_kind"] = "other"
        return state
    state["final_target_kind"] = "regular_file"
    try:
        final_hash = _sha256_file(path)
    except OSError:
        state["final_target_kind"] = "unreadable"
        return state
    state["final_target_hash"] = final_hash
    state["target_restored_to_preimage"] = (
        pre_apply_target_hash is not None and final_hash == pre_apply_target_hash
    )
    return state


def _final_target_blocker(state: dict[str, Any], expected_hash: str) -> str | None:
    kind = state.get("final_target_kind")
    if kind == "missing":
        return "final_target_missing"
    if kind == "symlink":
        return "final_target_symlink_detected"
    if kind != "regular_file":
        return "final_target_not_regular_file"
    if state.get("final_target_hash") != expected_hash:
        return "final_target_hash_mismatch"
    return None


def _operation_count_summary(
    request: dict[str, Any] | None,
    decision: dict[str, Any] | None,
    *,
    executed_count: int,
) -> dict[str, int]:
    request_ops = request.get("operations") if isinstance(request, dict) else None
    decision_ops = decision.get("checked_paths_and_operations") if isinstance(decision, dict) else None
    binding = decision.get("execution_binding") if isinstance(decision, dict) else None
    binding_ops = binding.get("ordered_operations") if isinstance(binding, dict) else None
    approved = len(decision_ops) if isinstance(decision_ops, list) else 0
    requested = len(request_ops) if isinstance(request_ops, list) else 0
    bound = len(binding_ops) if isinstance(binding_ops, list) else 0
    executable = requested if requested == approved == bound == 1 else 0
    return {
        "approved_operation_count": approved,
        "requested_operation_count": requested,
        "binding_operation_count": bound,
        "executable_operation_count": executable,
        "executed_operation_count": executed_count,
    }


def _normalized_operation(operation: Any) -> dict[str, Any] | None:
    if not isinstance(operation, dict):
        return None
    return {
        "operation": operation.get("operation"),
        "path": operation.get("path"),
        "before_sha256": operation.get("before_sha256"),
    }


def _single_operation_contract_error(
    request: dict[str, Any],
    decision: dict[str, Any],
    reevaluated: dict[str, Any] | None = None,
) -> str | None:
    request_ops = request.get("operations")
    decision_ops = decision.get("checked_paths_and_operations")
    binding = decision.get("execution_binding")
    binding_ops = binding.get("ordered_operations") if isinstance(binding, dict) else None
    reevaluated_ops = reevaluated.get("checked_paths_and_operations") if isinstance(reevaluated, dict) else None
    if (
        not isinstance(request_ops, list)
        or not isinstance(decision_ops, list)
        or not isinstance(binding_ops, list)
        or len(request_ops) != 1
        or len(decision_ops) != 1
        or len(binding_ops) != 1
        or (reevaluated_ops is not None and (not isinstance(reevaluated_ops, list) or len(reevaluated_ops) != 1))
    ):
        return "demo_runtime_multiple_operations_unsupported"
    request_op = _normalized_operation(request_ops[0])
    decision_op = _normalized_operation(decision_ops[0])
    binding_op = _normalized_operation(binding_ops[0])
    reevaluated_op = _normalized_operation(reevaluated_ops[0]) if isinstance(reevaluated_ops, list) else request_op
    if request_op is None or request_op != decision_op or request_op != binding_op or request_op != reevaluated_op:
        return "demo_runtime_operation_binding_mismatch"
    return None


def _demo_execution_blocked(
    blocker: str,
    source_root: Path,
    packaged_source_root: Path,
    packaged_source_before: str | None,
    source_hash_before: str | None,
    *,
    retention_decision: str | None = None,
    target: Path | None = None,
    pre_apply_target_hash: str | None = None,
    mutation_was_applied: bool = False,
    rollback_executed: bool = False,
    compensation_attempted: bool = False,
    compensation_succeeded: bool = False,
    final_target_hash: str | None = None,
    target_state: dict[str, Any] | None = None,
    operation_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    source_hash_after = _safe_source_tree_hash(source_root)
    try:
        packaged_source_after = protected_source_hash()
    except Exception:
        packaged_source_after = None
    if target_state is None and target is not None:
        target_state = _target_state(target, pre_apply_target_hash=pre_apply_target_hash)
    if target_state is None:
        target_state = {
            "final_target_kind": None,
            "final_target_hash": final_target_hash,
            "final_target_mode": None,
            "target_restored_to_preimage": False,
        }
    if final_target_hash is None:
        final_target_hash = target_state.get("final_target_hash")
    target_restored = target_state.get("target_restored_to_preimage") is True
    mutation_present = not target_restored if mutation_was_applied else False
    rollback_requested = retention_decision == "rollback_requested" if retention_decision is not None else False
    payload = {
        "schema_name": EXECUTION_SCHEMA_NAME,
        "result": "blocked",
        "exact_blocker": blocker,
        "mutation_applied": mutation_was_applied,
        "mutation_was_applied": mutation_was_applied,
        "mutation_applied_at_least_once": mutation_was_applied,
        "mutation_present_after_execution": mutation_present,
        "rollback_requested": rollback_requested,
        "rollback_executed": rollback_executed,
        "compensation_attempted": compensation_attempted,
        "compensation_succeeded": compensation_succeeded,
        "final_target_hash": final_target_hash,
        "final_target_kind": target_state.get("final_target_kind"),
        "final_target_mode": target_state.get("final_target_mode"),
        "target_restored_to_preimage": target_restored,
        "pre_apply_target_hash": pre_apply_target_hash,
        "source_hash_before_block": source_hash_before,
        "source_hash_after_block": source_hash_after,
        "final_source_tree_hash": source_hash_after,
        "source_restored_to_pre_apply_hash": source_hash_before == source_hash_after if source_hash_before is not None and source_hash_after is not None else None,
        "external_target_unchanged": source_hash_before == source_hash_after if source_hash_before is not None else None,
        "packaged_source_root": str(packaged_source_root),
        "packaged_source_hash_before": packaged_source_before,
        "packaged_source_hash_after": packaged_source_after,
        "packaged_source_mutated": packaged_source_before != packaged_source_after if packaged_source_before is not None and packaged_source_after is not None else False,
        "provider_calls": 0,
        "advisor_calls": 0,
        "mem0_runs": 0,
        "benchmark_runs": 0,
        "network_calls": 0,
    }
    if operation_counts is not None:
        payload.update(operation_counts)
    return payload


def _post_apply_blocked_payload(
    *,
    blocker: str,
    ctx: dict[str, Any],
    target: Path,
    original_bytes: bytes,
    original_mode: int,
    pre_apply_hash: str,
    source_root: Path,
    packaged_source_root: Path,
    packaged_source_before: str | None,
    source_hash_before: str | None,
    retention_decision: str,
    rollback_executed: bool,
    operation_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    try:
        _restore_preimage(target, original_bytes, original_mode, pre_apply_hash)
    except Exception:
        pass
    target_state = _target_state(target, pre_apply_target_hash=pre_apply_hash)
    compensation_succeeded = target_state.get("target_restored_to_preimage") is True
    payload = _demo_execution_blocked(
        blocker,
        source_root,
        packaged_source_root,
        packaged_source_before,
        source_hash_before,
        retention_decision=retention_decision,
        target=target,
        pre_apply_target_hash=pre_apply_hash,
        mutation_was_applied=True,
        rollback_executed=rollback_executed,
        compensation_attempted=True,
        compensation_succeeded=compensation_succeeded,
        target_state=target_state,
        operation_counts=operation_counts,
    )
    payload.update(
        {
            "workspace": str(ctx["workspace"]),
            "workspace_id": ctx["workspace_id"],
            "mutation_scope": f"marker_owned_demo_repo:{ctx['workspace_id']}",
        }
    )
    return payload


def demo_execute(
    *,
    workspace: Path,
    decision_path: Path,
    approval_path: Path,
    request_path: Path,
    policy_path: Path,
    source_root: Path,
    packaged_source_root: Path,
    retention_decision: str,
) -> dict[str, Any]:
    if retention_decision not in {"rollback_requested", "keep"}:
        _raise("retention_decision_invalid")

    source_before = _safe_source_tree_hash(source_root)
    actual_source_root, packaged_source_before, package_assertion_error = _validate_package_root_assertion(packaged_source_root)
    if package_assertion_error:
        return _demo_execution_blocked(package_assertion_error, source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision)
    unsafe_workspace = unsafe_workspace_path_reason(workspace)
    if unsafe_workspace:
        return _demo_execution_blocked(unsafe_workspace, source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision)
    try:
        ctx = validate_demo_execution_confinement(
            workspace=workspace,
            source_root=source_root,
            packaged_source_root=actual_source_root,
            policy_path=policy_path,
            request_path=request_path,
            decision_path=decision_path,
            approval_path=approval_path,
        )
    except Exception as exc:
        return _demo_execution_blocked(str(exc), source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision)

    source_root = ctx["demo_repo"].resolve(strict=True)
    artifacts = ctx["artifacts"].resolve(strict=True)
    policy_path = ensure_artifact_path(policy_path, ctx, must_exist=True, output=True)
    request_path = ensure_artifact_path(request_path, ctx, must_exist=True, output=True)
    decision_path = ensure_artifact_path(decision_path, ctx, must_exist=True, output=True)
    approval_path = ensure_artifact_path(approval_path, ctx, must_exist=True, output=True)

    try:
        decision = _read_json_file(decision_path)
        approval = _read_json_file(approval_path)
        request = _read_json_file(request_path)
    except Exception:
        return _demo_execution_blocked("approval_or_request_missing", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision)
    operation_counts = _operation_count_summary(request, decision, executed_count=0)

    rollback_path_raw = request.get("rollback_readiness", {}).get("artifact_path") if isinstance(request.get("rollback_readiness"), dict) else None
    if not isinstance(rollback_path_raw, str):
        return _demo_execution_blocked("rollback_artifact_path_missing", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)
    try:
        rollback_path = ensure_artifact_path(Path(rollback_path_raw), ctx, must_exist=True, output=True)
    except Exception as exc:
        return _demo_execution_blocked(str(exc), source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)
    if str(rollback_path) != rollback_path_raw:
        return _demo_execution_blocked("rollback_artifact_path_binding_mismatch", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)

    verification = _gate().verify_decision_artifact(decision_path)
    if verification.get("verified") is not True:
        return _demo_execution_blocked("gate_decision_artifact_invalid", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)
    if decision.get("decision") != "allow" or decision.get("eligible_for_human_approval") is not True:
        return _demo_execution_blocked("gate_decision_not_allow", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)
    approval_verification = verify_approval_artifact(approval_path)
    if approval_verification.get("verified") is not True:
        return _demo_execution_blocked(approval_verification.get("exact_blocker", "approval_artifact_invalid"), source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)
    if approval.get("approved") is not True or approval.get("decision") != "approved":
        return _demo_execution_blocked("approval_not_affirmative", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)
    if approval.get("decision_artifact_hash") != _sha256_file(decision_path):
        return _demo_execution_blocked("approval_decision_hash_mismatch", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)
    approval_bindings = {
        "audit_event_hash": "audit_event_hash",
        "execution_binding_hash": "execution_binding_hash",
        "canonical_policy_hash": "policy_hash",
        "canonical_request_hash": "canonical_request_hash",
        "request_id": "request_id",
        "proposal_id": "proposal_id",
    }
    for approval_key, decision_key in approval_bindings.items():
        if approval.get(approval_key) != decision.get(decision_key):
            return _demo_execution_blocked(f"approval_{approval_key}_binding_mismatch", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)

    if (
        operation_counts["requested_operation_count"] != 1
        or operation_counts["approved_operation_count"] != 1
        or operation_counts["binding_operation_count"] != 1
    ):
        return _demo_execution_blocked("demo_runtime_multiple_operations_unsupported", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)

    reevaluated = _gate().evaluate_source_mutation_request(
        policy_path=policy_path,
        request_path=request_path,
        source_root=source_root,
        event_timestamp=decision.get("event_timestamp"),
        sequence_index=int(decision.get("sequence_index", 1)),
    )
    if reevaluated.get("decision") != "allow":
        return _demo_execution_blocked("gate_reevaluation_failed", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)
    for key in [
        "execution_binding_hash",
        "policy_hash",
        "canonical_request_hash",
        "proposal_hash_verified",
        "source_hash_verified",
        "request_id",
        "proposal_id",
        "declared_actor_id",
        "requested_scope",
        "matched_rule_id",
    ]:
        if reevaluated.get(key) != decision.get(key):
            return _demo_execution_blocked(f"{key}_binding_mismatch", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)

    operation_error = _single_operation_contract_error(request, decision, reevaluated)
    if operation_error:
        return _demo_execution_blocked(operation_error, source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)

    rollback_metadata, rollback_before_error = _validate_rollback_artifact_contents(
        request=request,
        source_root=source_root,
        require_current_target_hash=True,
    )
    if rollback_before_error:
        return _demo_execution_blocked(rollback_before_error, source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)
    assert rollback_metadata is not None

    op = request["operations"][0]
    target = source_root / op["path"]
    if target.is_symlink() or not target.exists() or not target.is_file():
        return _demo_execution_blocked("target_not_regular_file_before_apply", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)
    pre_apply_hash = _sha256_file(target)
    if pre_apply_hash != op["before_sha256"]:
        return _demo_execution_blocked("before_hash_changed_before_apply", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)

    original_bytes = target.read_bytes()
    original_mode = stat.S_IMODE(target.stat().st_mode)
    if _sha256_bytes(original_bytes) != pre_apply_hash:
        return _demo_execution_blocked("pre_apply_preimage_hash_mismatch", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)
    rollback_entry = rollback_metadata["files"].get(op["path"], {})
    if rollback_entry.get("original_content", "").encode("utf-8") != original_bytes:
        return _demo_execution_blocked("rollback_artifact_preimage_mismatch", source_root, actual_source_root, packaged_source_before, source_before, retention_decision=retention_decision, operation_counts=operation_counts)

    proposed_bytes = str(request["proposal_body"]["new_content"]).encode("utf-8")
    proposed_hash = _sha256_bytes(proposed_bytes)
    rollback_requested = retention_decision == "rollback_requested"
    rollback_executed = False
    restored_hash = None
    post_apply_hash = None
    pre_apply_source_hash = _source_tree_hash(source_root)
    expected_post_apply_source_hash = None
    executed_operation_count = 0

    try:
        _atomic_replace_bytes(target, proposed_bytes, mode=original_mode)
        executed_operation_count = 1
        post_apply_hash = _sha256_file(target)
        if post_apply_hash != proposed_hash:
            raise PostApplyFailure("post_apply_hash_mismatch")
        expected_post_apply_source_hash = _source_tree_hash(source_root)

        hook = POST_APPLY_TEST_HOOK
        if hook is not None:
            hook(
                {
                    "workspace": ctx["workspace"],
                    "artifacts": artifacts,
                    "source_root": source_root,
                    "target": target,
                    "rollback_path": rollback_path,
                    "request_path": request_path,
                }
            )

        if rollback_requested:
            rollback_metadata, rollback_before_rollback_error = _validate_rollback_artifact_contents(
                request=request,
                source_root=source_root,
                require_current_target_hash=False,
            )
            if rollback_before_rollback_error:
                raise PostApplyFailure(rollback_before_rollback_error)
            assert rollback_metadata is not None
            snapshot = _read_json_file(Path(rollback_metadata["artifact_path"]))
            rollback_content = snapshot["files"][op["path"]]["original_content"].encode("utf-8")
            _atomic_replace_bytes(target, rollback_content, mode=original_mode)
            restored_hash = _sha256_file(target)
            rollback_executed = restored_hash == pre_apply_hash
            if not rollback_executed:
                raise PostApplyFailure("rollback_restore_hash_mismatch")

        packaged_source_after = protected_source_hash()
        if packaged_source_before != packaged_source_after:
            raise PostApplyFailure("packaged_source_hash_changed_during_execution")

        target_state = _target_state(target, pre_apply_target_hash=pre_apply_hash)
        expected_target_hash = pre_apply_hash if rollback_requested else proposed_hash
        final_target_error = _final_target_blocker(target_state, expected_target_hash)
        if final_target_error:
            raise PostApplyFailure(final_target_error)

        source_after = _source_tree_hash(source_root)
        expected_source_hash = pre_apply_source_hash if rollback_requested else expected_post_apply_source_hash
        if expected_source_hash is None or source_after != expected_source_hash:
            raise PostApplyFailure("final_demo_source_tree_hash_mismatch")

        operation_counts = _operation_count_summary(request, decision, executed_count=executed_operation_count)
        payload = {
            "schema_name": EXECUTION_SCHEMA_NAME,
            "result": "passed",
            "workspace": str(ctx["workspace"]),
            "workspace_id": ctx["workspace_id"],
            "decision_reverified_before_apply": True,
            "proposal_hash_rechecked_before_apply": True,
            "source_hash_rechecked_before_apply": True,
            "execution_binding_rechecked_before_apply": True,
            "rollback_artifact_reverified_before_apply": True,
            "rollback_artifact_reverified_before_rollback": rollback_requested,
            "approval_verified": True,
            "mutation_applied": True,
            "mutation_was_applied": True,
            "mutation_applied_at_least_once": True,
            "mutation_present_after_execution": target_state.get("target_restored_to_preimage") is not True,
            "mutation_scope": f"marker_owned_demo_repo:{ctx['workspace_id']}",
            "source_hash_before_apply": pre_apply_source_hash,
            "source_hash_after_execution": source_after,
            "final_source_tree_hash": source_after,
            "expected_post_apply_source_tree_hash": expected_post_apply_source_hash,
            "source_restored_to_pre_apply_hash": source_after == pre_apply_source_hash,
            "packaged_source_root": str(actual_source_root),
            "packaged_source_hash_before": packaged_source_before,
            "packaged_source_hash_after": packaged_source_after,
            "packaged_source_mutated": packaged_source_before != packaged_source_after,
            "retention_decision": retention_decision,
            "rollback_readiness_verified": decision.get("rollback_readiness_verified") is True,
            "rollback_requested": rollback_requested,
            "rollback_executed": rollback_executed,
            "compensation_attempted": False,
            "compensation_succeeded": False,
            "restored_state_hash": restored_hash,
            "pre_apply_file_hash": pre_apply_hash,
            "pre_apply_target_hash": pre_apply_hash,
            "post_apply_file_hash": post_apply_hash,
            "final_target_hash": target_state.get("final_target_hash"),
            "final_target_kind": target_state.get("final_target_kind"),
            "final_target_mode": target_state.get("final_target_mode"),
            "target_restored_to_preimage": target_state.get("target_restored_to_preimage") is True,
            "provider_calls": 0,
            "advisor_calls": 0,
            "mem0_runs": 0,
            "benchmark_runs": 0,
            "network_calls": 0,
            "exact_blocker": None,
        }
        payload.update(operation_counts)
        execution_output = artifacts / "approved_execution.json"
        try:
            write_json_file(execution_output, payload)
        except Exception:
            raise PostApplyFailure("execution_evidence_write_failed")
        return payload
    except PostApplyFailure as exc:
        return _post_apply_blocked_payload(
            blocker=exc.blocker,
            ctx=ctx,
            target=target,
            original_bytes=original_bytes,
            original_mode=original_mode,
            pre_apply_hash=pre_apply_hash,
            source_root=source_root,
            packaged_source_root=actual_source_root,
            packaged_source_before=packaged_source_before,
            source_hash_before=pre_apply_source_hash,
            retention_decision=retention_decision,
            rollback_executed=rollback_executed,
            operation_counts=_operation_count_summary(request, decision, executed_count=executed_operation_count),
        )
    except Exception:
        return _post_apply_blocked_payload(
            blocker="post_apply_unexpected_exception",
            ctx=ctx,
            target=target,
            original_bytes=original_bytes,
            original_mode=original_mode,
            pre_apply_hash=pre_apply_hash,
            source_root=source_root,
            packaged_source_root=actual_source_root,
            packaged_source_before=packaged_source_before,
            source_hash_before=pre_apply_source_hash,
            retention_decision=retention_decision,
            rollback_executed=rollback_executed,
            operation_counts=_operation_count_summary(request, decision, executed_count=executed_operation_count),
        )
