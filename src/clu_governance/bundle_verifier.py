"""Strict, read-only verification for a published CLU Governance bundle.

Verification establishes that the currently observed local bundle satisfies the
documented bundle structure and internal bindings. It does not authenticate the
unpackaged policy or the bundle's origin, and it is not a signature, immutable
filesystem guarantee, or proof that the bundle cannot change after return.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import difflib
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from . import strict_json
from .path_chain import AbsoluteDirectoryChainLease, PathChainError
from .result_contract import ResultContractError, validate_verifier_result
from . import source_mutation_policy_gate as gate


RESULT_SCHEMA_NAME = "clu_governance_git_adapter_bundle_verification.v1"
COMPLETION_SCHEMA_NAME = "clu_governance_git_adapter_bundle_completion.v4"
BUNDLE_VERIFICATION_CONTRACT_VERSION = 1
OWNERSHIP_SCHEMA_NAME = "clu_governance_git_adapter_output_ownership.v1"
REQUEST_SCHEMA_NAME = "clu_governance_source_mutation_request.v1"
ROLLBACK_SCHEMA_NAME = "clu_governance_source_mutation_rollback_readiness.v1"
DECISION_SCHEMA_NAME = "clu_governance_source_mutation_policy_decision.v1"
PROVENANCE_SCHEMA_NAME = "clu_governance_git_diff_provenance.v1"
SOURCE_SURFACE_MODE = "single_tracked_file_baseline_snapshot"
SUPPORTED_CHANGE_MODE = "single_tracked_unstaged_utf8_text_modify"
OWNERSHIP_MARKER_NAME = ".clu-git-adapter-ownership.json"
MAX_ENTRIES = 128
MAX_PROVENANCE_METADATA_ENTRIES = 4096
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_REGULAR_BYTES = 32 * 1024 * 1024
MAX_ADAPTER_FILE_BYTES = 1 * 1024 * 1024
JSON_FILES = {
    OWNERSHIP_MARKER_NAME,
    "source_mutation_request.json",
    "rollback_snapshot.json",
    "git_provenance.json",
    "policy_decision.json",
    "BUNDLE_COMPLETE.json",
}
PROVENANCE_KEYS = {
    "accepted_snapshot_status_independently_parsed",
    "assume_unchanged_index_entries_supported",
    "automatic_nonempty_failure_cleanup_performed",
    "baseline_blob_oid",
    "baseline_blob_size",
    "baseline_content_sha256",
    "baseline_git_blob_oid_recomputed",
    "baseline_git_blob_oid_verified",
    "branch_name",
    "candidate_and_accepted_snapshot_records_match",
    "change_preview_sha256",
    "config_sha256_after",
    "config_sha256_before",
    "content_sensitive_git_exec_sandbox_enforced",
    "content_sensitive_git_sandbox_backend",
    "content_sensitive_git_sandboxed_command_count",
    "contract_version",
    "declared_actor_identity_authenticated",
    "detached_head",
    "external_baseline_content_packaged",
    "external_object_database_used",
    "external_process_execution_blocked_by_configuration_policy",
    "external_ref_storage_content_packaged",
    "external_reftable_storage_used",
    "full_repository_governance_claim_allowed",
    "full_repository_hash_verified",
    "git_commands",
    "git_config_mutated",
    "git_environment_inheritance_bounded",
    "git_external_diff_executed",
    "git_external_object_database_supported",
    "git_head_mutated",
    "git_hooks_executed",
    "git_index_mutated",
    "git_lock_files_created",
    "git_metadata_descriptor_boundary_enforced",
    "git_metadata_direct_dot_git_only",
    "git_metadata_root_symlink_detected",
    "git_metadata_roots_bound",
    "git_network_commands",
    "git_no_lazy_fetch_enforced",
    "git_object_root_inside_repository",
    "git_object_root_symlink_detected",
    "git_ref_storage_backend",
    "git_ref_storage_backend_evidence_source",
    "git_ref_storage_backend_verified",
    "git_refs_mutated",
    "git_reftable_path_absent_required",
    "git_reftable_supported",
    "git_replace_objects_disabled",
    "git_shell_execution_used",
    "git_subprocess_output_capped_during_execution",
    "git_textconv_executed",
    "git_version",
    "head_file_mode",
    "head_oid",
    "head_signature_verified",
    "index_path",
    "index_sha256_after",
    "index_sha256_before",
    "index_state_sha256_after",
    "index_state_sha256_before",
    "lock_files_after",
    "lock_files_before",
    "metadata_inventory_after",
    "metadata_inventory_before",
    "object_format",
    "output_ownership_marker_retained",
    "output_parent_device_inode_bound",
    "output_parent_directory_descriptor_bound",
    "partial_or_promisor_repository_supported",
    "path_based_check_then_unlink_cleanup_used",
    "policy_decision",
    "policy_decision_verified",
    "porcelain_v2_status_sha256",
    "read_only_proof_scope",
    "recursive_unverified_output_cleanup_used",
    "refs_sha256_after",
    "refs_sha256_before",
    "remote_identity_verified",
    "repository_config_includes_supported",
    "repository_config_read_with_typed_git_semantics",
    "repository_configured_external_helpers_executed",
    "repository_files_changed",
    "repository_files_created",
    "repository_files_removed",
    "repository_filter_driver_config_supported",
    "repository_identity_authenticated",
    "repository_root",
    "runtime_network_access_observed",
    "schema_name",
    "schema_version",
    "selected_path",
    "selected_path_parent_components_no_follow_verified",
    "skip_worktree_index_entries_supported",
    "source_surface_mode",
    "sparse_checkout_or_sparse_index_supported",
    "status_uses_sanitized_local_config_view",
    "supported_change_mode",
    "supported_git_ref_storage_backend",
    "tracked_index_path_count",
    "unknown_repository_extensions_supported",
    "working_tree_content_sha256",
    "working_tree_mode",
    "working_tree_size",
}


class BundleVerificationError(ValueError):
    """Stable fail-closed bundle verification blocker."""


def _raise(blocker: str) -> None:
    raise BundleVerificationError(blocker)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return _sha256(encoded)


def _exact_int(value: Any, expected: int) -> bool:
    """Compare a JSON integer without accepting bool's int subclass."""

    return type(value) is int and value == expected


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _exact_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _exact_git_oid(value: Any, object_format: str) -> bool:
    length = {"sha1": 40, "sha256": 64}.get(object_format)
    return bool(
        length is not None
        and isinstance(value, str)
        and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None
    )


def _git_blob_oid(content: bytes, object_format: str) -> str:
    if object_format not in {"sha1", "sha256"}:
        _raise("bundle_provenance_binding_invalid")
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(content)}\0".encode("ascii"))
    digest.update(content)
    return digest.hexdigest()


def _expected_preview(selected: str, baseline_text: str, proposed_text: str) -> bytes:
    return "".join(
        difflib.unified_diff(
            baseline_text.splitlines(keepends=True),
            proposed_text.splitlines(keepends=True),
            fromfile=f"a/{selected}@HEAD",
            tofile=f"b/{selected}@working-tree",
            lineterm="\n",
        )
    ).encode("utf-8")


def _expected_execution_binding(
    request: dict[str, Any], decision: dict[str, Any]
) -> dict[str, Any]:
    """Reconstruct the gate's complete allow binding from verified artifacts."""

    checked = decision.get("checked_paths_and_operations")
    if not isinstance(checked, list):
        _raise("bundle_decision_integrity_invalid")
    return gate.execution_binding_for(
        request=request,
        policy_hash=decision.get("policy_hash"),
        checked_operations=checked,
        matched_rule_id=decision.get("matched_rule_id"),
    )


def _git_command_log_valid(
    commands: Any,
    *,
    selected_path: str,
    baseline_blob_oid: str,
    config_payloads: Any,
) -> bool:
    """Validate the adapter's bounded command-log grammar and zero-network claim."""

    if not isinstance(commands, list) or not commands:
        return False
    fixed_prefix = [
        "--no-optional-locks", "-c", "core.fsmonitor=false", "-c",
        "diff.external=", "-c", "maintenance.auto=false", "-c",
        "pager.status=false",
    ]
    status_record = [
        "status-sanitized-local-config-view", "--porcelain=v2", "-z",
        "--untracked-files=all", "--ignored=matching", "--ignore-submodules=all",
    ]
    if (
        not isinstance(config_payloads, list)
        or not config_payloads
        or any(
            not isinstance(item, tuple)
            or len(item) != 2
            or type(item[0]) is not int
            or item[0] < 0
            or not _exact_sha256(item[1])
            for item in config_payloads
        )
    ):
        return False
    expected_audits: set[tuple[str, int, str]] = set()
    for size, digest in config_payloads:
        for kind in ("key-list", "extension-values", "typed-booleans"):
            expected_audits.add((kind, size, digest))
    observed_audits: dict[tuple[str, int, str], int] = {}
    regular_payloads: set[tuple[str, ...]] = set()
    allowed_payloads = {
        ("rev-parse", "--show-toplevel"),
        ("rev-parse", "--is-bare-repository"),
        ("rev-parse", "--absolute-git-dir"),
        ("rev-parse", "HEAD"),
        ("rev-parse", "--show-object-format"),
        ("rev-parse", "--show-ref-format"),
        ("rev-parse", "--abbrev-ref", "HEAD"),
        ("rev-parse", "--git-path", "index"),
        ("ls-files", "-v", "--stage", "--sparse", "--full-name", "--no-abbrev", "-z"),
        ("ls-tree", "-z", "HEAD", "--", selected_path),
        ("cat-file", "-s", baseline_blob_oid),
        ("cat-file", "blob", baseline_blob_oid),
    }
    saw_status = False
    saw_ref_format_probe = False
    for command in commands:
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(token, str) for token in command)
        ):
            return False
        if command[0] == "config-audit":
            try:
                observed_size = int(command[2].removeprefix("input_bytes="))
                observed_digest = command[3].removeprefix("input_sha256=")
            except (ValueError, IndexError):
                return False
            if (
                len(command) != 4
                or command[1] not in {"key-list", "extension-values", "typed-booleans"}
                or command[2] != f"input_bytes={observed_size}"
                or command[3] != f"input_sha256={observed_digest}"
                or not _exact_sha256(observed_digest)
            ):
                return False
            key = (command[1], observed_size, observed_digest)
            observed_audits[key] = observed_audits.get(key, 0) + 1
            continue
        if command == status_record:
            saw_status = True
            continue
        if command[: len(fixed_prefix)] != fixed_prefix:
            return False
        payload = command[len(fixed_prefix) :]
        payload_tuple = tuple(payload)
        if payload_tuple not in allowed_payloads:
            return False
        regular_payloads.add(payload_tuple)
        if payload_tuple == ("rev-parse", "--show-ref-format"):
            saw_ref_format_probe = True
    return bool(
        set(observed_audits) == expected_audits
        and all(
            observed_audits[("key-list", size, digest)]
            == observed_audits[("extension-values", size, digest)]
            == observed_audits[("typed-booleans", size, digest)]
            > 0
            for size, digest in config_payloads
        )
        and regular_payloads == allowed_payloads
        and saw_status
        and saw_ref_format_probe
    )


def _metadata_relative_valid(relative: Any) -> bool:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        return False
    return not any(
        component in {"", ".", ".."}
        or any(ord(character) < 32 or ord(character) == 127 for character in component)
        for component in relative.split("/")
    )


def _metadata_inventory_valid(inventory: Any) -> bool:
    if (
        not isinstance(inventory, dict)
        or not 8 <= len(inventory) <= MAX_PROVENANCE_METADATA_ENTRIES
    ):
        return False
    required_kinds = {
        "HEAD": "file", "index": "file", "config": "file",
        "objects": "directory", "objects/pack": "directory",
        "objects/info": "directory", "refs": "directory", "info": "directory",
    }
    for path, kind in required_kinds.items():
        record = inventory.get(path)
        if not isinstance(record, dict) or record.get("kind") != kind:
            return False
    base_keys = {
        "ctime_ns", "device", "file_type", "inode", "kind", "link_count",
        "mode", "mtime_ns", "size",
    }
    for relative, record in inventory.items():
        if not _metadata_relative_valid(relative) or not isinstance(record, dict):
            return False
        kind = record.get("kind")
        expected_keys = base_keys | ({"sha256"} if "sha256" in record else set())
        if set(record) != expected_keys or kind not in {"file", "directory"}:
            return False
        for field in (
            "ctime_ns", "device", "file_type", "inode", "link_count", "mode",
            "mtime_ns", "size",
        ):
            if type(record.get(field)) is not int or record[field] < 0:
                return False
        if kind == "file":
            if record["file_type"] != stat.S_IFREG or record["link_count"] != 1:
                return False
            if "sha256" in record and not _exact_sha256(record["sha256"]):
                return False
            if not relative.startswith("objects/") and not _exact_sha256(
                record.get("sha256")
            ):
                return False
        elif record["file_type"] != stat.S_IFDIR or record["link_count"] < 1:
            return False
    return all(_exact_sha256(inventory[path].get("sha256")) for path in ("HEAD", "index", "config"))


def _hash_inventory_valid(
    hashes: Any,
    metadata: dict[str, Any],
    *,
    required: set[str],
) -> bool:
    if (
        not isinstance(hashes, dict)
        or not required.issubset(hashes)
        or len(hashes) > MAX_PROVENANCE_METADATA_ENTRIES
    ):
        return False
    for relative, digest in hashes.items():
        record = metadata.get(relative)
        if (
            not _metadata_relative_valid(relative)
            or not _exact_sha256(digest)
            or not isinstance(record, dict)
            or record.get("kind") != "file"
            or record.get("sha256") != digest
        ):
            return False
    return True


def _strict_json(data: bytes, relative: str) -> Any:
    try:
        text = data.decode("utf-8", errors="strict")
        return strict_json.loads(text)
    except strict_json.DuplicateJSONKeyError:
        _raise(f"bundle_json_duplicate_key:{relative}")
    except strict_json.NonFiniteJSONNumberError:
        _raise(f"bundle_json_nonfinite_number:{relative}")
    except strict_json.JSONNestingDepthError:
        _raise(f"bundle_json_nesting_limit_exceeded:{relative}")
    except strict_json.InvalidUnicodeJSONError:
        _raise(f"bundle_json_invalid_unicode:{relative}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        _raise(f"bundle_json_invalid:{relative}")


def _normalize_relative(path: Any) -> str:
    if not isinstance(path, str) or not path:
        _raise("bundle_selected_path_invalid")
    if "\\" in path or any(ord(char) < 32 or ord(char) == 127 for char in path):
        _raise("bundle_selected_path_invalid")
    candidate = Path(path)
    if candidate.is_absolute() or path.startswith("/"):
        _raise("bundle_selected_path_invalid")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        _raise("bundle_selected_path_invalid")
    normalized = "/".join(parts)
    if normalized == ".git" or normalized.startswith(".git/"):
        _raise("bundle_selected_path_invalid")
    return normalized


def _stat_token(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode),
    }


BUNDLE_PATH_CHAIN_TEST_HOOK = None


class BundleReader:
    """Descriptor-bound, no-follow bundle reader."""

    def __init__(self, path: Path):
        try:
            self.lease = AbsoluteDirectoryChainLease.acquire(
                path, hook=BUNDLE_PATH_CHAIN_TEST_HOOK, phase="initial"
            )
        except PathChainError as exc:
            _raise(str(exc))
        self.path = self.lease.path
        self.root_fd = self.lease.root_fd
        self.root_identity = self.lease.root_identity
        parent = self.lease.components[-2] if len(self.lease.components) > 1 else self.lease.components[-1]
        self.parent_identity = {"device": parent.device, "inode": parent.inode, "mode": parent.mode}
        self.owns_lease = True

    @classmethod
    def from_lease(cls, lease: AbsoluteDirectoryChainLease) -> "BundleReader":
        reader = cls.__new__(cls)
        reader.lease = lease
        reader.path = lease.path
        reader.root_fd = lease.root_fd
        reader.root_identity = lease.root_identity
        parent = lease.components[-2] if len(lease.components) > 1 else lease.components[-1]
        reader.parent_identity = {"device": parent.device, "inode": parent.inode, "mode": parent.mode}
        reader.owns_lease = False
        return reader

    def close(self) -> None:
        lease = getattr(self, "lease", None)
        if lease is not None and getattr(self, "owns_lease", False):
            lease.close()
        self.root_fd = None

    def binding_valid(self) -> bool:
        try:
            fresh = self.lease.fresh_rebind(
                hook=BUNDLE_PATH_CHAIN_TEST_HOOK,
                phase="binding",
                # This check immediately follows lease acquisition and proves
                # that the same static caller-visible path is still named.
                # Requiring temporal equality for every system-temp ancestor
                # here made valid bundles fail when an unrelated sibling was
                # created in a shared ancestor. The later final and
                # confirmation rebinds retain temporal comparison across the
                # actual verification window.
                compare_temporal=False,
            )
        except PathChainError:
            return False
        fresh.close()
        return True

    @staticmethod
    def _parts(relative: str) -> tuple[str, ...]:
        parts = tuple(relative.split("/"))
        if not parts or any(part in {"", ".", ".."} or "\x00" in part for part in parts):
            _raise("bundle_internal_path_invalid")
        return parts

    def read_file(self, relative: str, limit: int = MAX_FILE_BYTES) -> bytes:
        parts = self._parts(relative)
        directory = os.dup(self.root_fd)
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        try:
            for component in parts[:-1]:
                child = os.open(component, directory_flags, dir_fd=directory)
                os.close(directory)
                directory = child
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                _raise(f"bundle_file_type_or_link_invalid:{relative}")
            if before.st_size < 0 or before.st_size > limit:
                _raise(f"bundle_file_size_limit_exceeded:{relative}")
            remaining = limit + 1
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(descriptor)
            named = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
            if (
                _stat_token(before) != _stat_token(after)
                or _stat_token(after) != _stat_token(named)
                or len(data) != before.st_size
            ):
                _raise(f"bundle_file_changed_during_read:{relative}")
            return data
        except FileNotFoundError:
            _raise(f"bundle_file_missing:{relative}")
        except OSError:
            _raise(f"bundle_file_open_denied:{relative}")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    def inventory(self) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
        records: dict[str, dict[str, Any]] = {}
        issues = {"symlinks": [], "hardlinks": [], "nonregular": [], "limits": []}
        count = 0
        total_size = 0

        def visit(directory_fd: int, relative_root: str) -> None:
            nonlocal count, total_size
            before = os.fstat(directory_fd)
            names_before = sorted(os.listdir(directory_fd))
            records[relative_root] = {
                "type": "directory",
                **_directory_identity(before),
                "entries": names_before,
            }
            for name in names_before:
                count += 1
                if count > MAX_ENTRIES:
                    issues["limits"].append("entry_count")
                    return
                relative = f"{relative_root}/{name}" if relative_root else name
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError:
                    issues["nonregular"].append(relative)
                    continue
                if stat.S_ISLNK(info.st_mode):
                    issues["symlinks"].append(relative)
                    records[relative] = {"type": "symlink"}
                    continue
                if stat.S_ISDIR(info.st_mode):
                    flags = (
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                    )
                    try:
                        child = os.open(name, flags, dir_fd=directory_fd)
                    except OSError:
                        issues["nonregular"].append(relative)
                        continue
                    try:
                        visit(child, relative)
                    finally:
                        os.close(child)
                    continue
                if stat.S_ISREG(info.st_mode):
                    if info.st_nlink != 1:
                        issues["hardlinks"].append(relative)
                    total_size += max(0, info.st_size)
                    if info.st_size > MAX_FILE_BYTES or total_size > MAX_TOTAL_REGULAR_BYTES:
                        issues["limits"].append(relative)
                        digest = None
                    else:
                        try:
                            digest = _sha256(self.read_file(relative))
                        except BundleVerificationError:
                            digest = None
                            issues["nonregular"].append(relative)
                    records[relative] = {
                        "type": "file", "device": info.st_dev, "inode": info.st_ino,
                        "mode": stat.S_IMODE(info.st_mode), "nlink": info.st_nlink,
                        "size": info.st_size, "mtime_ns": info.st_mtime_ns,
                        "ctime_ns": info.st_ctime_ns, "sha256": digest,
                    }
                    continue
                issues["nonregular"].append(relative)
                records[relative] = {"type": "nonregular", "mode": info.st_mode}
            names_after = sorted(os.listdir(directory_fd))
            after = os.fstat(directory_fd)
            if names_before != names_after or _stat_token(before) != _stat_token(after):
                issues["nonregular"].append(relative_root or ".changed")

        root = os.dup(self.root_fd)
        try:
            visit(root, "")
        finally:
            os.close(root)
        for key in issues:
            issues[key] = sorted(set(issues[key]))
        return records, issues


def _result(bundle: Path) -> dict[str, Any]:
    return {
        "schema_name": RESULT_SCHEMA_NAME,
        "result": "invalid",
        "verified": False,
        "exact_blocker": None,
        "bundle_path": str(bundle),
        "bundle_consumer_verifiable": True,
        "bundle_verification_contract_version": BUNDLE_VERIFICATION_CONTRACT_VERSION,
        "bundle_valid_only_when_strict_verifier_currently_passes": True,
        "bundle_immutable": False,
        "bundle_tamper_prevention_provided": False,
        "bundle_exact_set_verified_at_return": False,
        "bundle_full_ancestor_chain_bound": False,
        "bundle_full_ancestor_chain_reverified_at_return": False,
        "caller_visible_bundle_path_bound_at_return": False,
        "caller_visible_bundle_root_identity_verified": False,
        "caller_visible_bundle_root_identity": None,
        "bundle_verification_timestamp": None,
        "bundle_verification_location_binding": "same_location_instance",
        "bundle_portable_across_copy_or_rename": False,
        "bundle_verification_required_at_consumption": True,
        "bundle_immutable_after_return_claim_allowed": False,
        "concurrent_same_user_tamper_prevention_claim_allowed": False,
        "tamper_evident_storage_claim_allowed": False,
        "bundle_signed": False,
        "identity_authenticated": False,
        "future_mutation_prevented": False,
        "current_observation_only": True,
        "exact_file_set_verified": False,
        "checksums_verified": False,
        "completion_verified": False,
        "publication_binding_verified": False,
        "request_rollback_binding_verified": False,
        "decision_integrity_verified": False,
        "execution_binding_verified": False,
        "provenance_binding_verified": False,
        "preview_binding_verified": False,
        "git_blob_oid_verified": False,
        "unknown_entries": [],
        "missing_entries": [],
        "symlink_entries": [],
        "hardlink_entries": [],
        "nonregular_entries": [],
        "files_created_during_verification": [],
        "files_removed_during_verification": [],
        "files_changed_during_verification": [],
        "verification_mutation_performed": False,
        "cleanup_performed": False,
        "provider_calls": 0,
        "advisor_calls": 0,
        "mem0_runs": 0,
        "benchmark_runs": 0,
        "network_calls": 0,
    }


def _inventory_delta(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> tuple[list[str], list[str], list[str]]:
    created = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(key for key in set(before) & set(after) if before[key] != after[key])
    return created, removed, changed


def verify_bundle(bundle_path: Path) -> dict[str, Any]:
    """Verify a currently published bundle without mutating it."""

    result = _result(bundle_path)
    reader: BundleReader | None = None
    before: dict[str, dict[str, Any]] = {}
    try:
        reader = BundleReader(bundle_path)
        result["bundle_full_ancestor_chain_bound"] = True
        result["caller_visible_bundle_root_identity"] = dict(reader.root_identity)
        before, before_issues = reader.inventory()
        result["symlink_entries"] = before_issues["symlinks"]
        result["hardlink_entries"] = before_issues["hardlinks"]
        result["nonregular_entries"] = before_issues["nonregular"]
        if before_issues["symlinks"]:
            _raise("bundle_symlink_entry_detected")
        if before_issues["hardlinks"]:
            _raise("bundle_hardlink_entry_detected")
        if before_issues["nonregular"]:
            _raise("bundle_nonregular_entry_detected")
        if before_issues["limits"]:
            _raise("bundle_inventory_limit_exceeded")

        completion = _strict_json(reader.read_file("BUNDLE_COMPLETE.json"), "BUNDLE_COMPLETE.json")
        if not isinstance(completion, dict) or completion.get("schema_name") != COMPLETION_SCHEMA_NAME:
            _raise("bundle_completion_inconsistent")
        selected = _normalize_relative(completion.get("selected_path"))
        allowed_dirs = {"", "baseline_source"}
        current = "baseline_source"
        for component in selected.split("/")[:-1]:
            current = f"{current}/{component}"
            allowed_dirs.add(current)
        payload_files = {
            OWNERSHIP_MARKER_NAME,
            f"baseline_source/{selected}",
            "source_mutation_request.json",
            "rollback_snapshot.json",
            "git_provenance.json",
            "change_preview.diff",
            "policy_decision.json",
        }
        allowed_files = payload_files | {"CHECKSUMS.sha256", "BUNDLE_COMPLETE.json"}
        actual_dirs = {path for path, entry in before.items() if entry.get("type") == "directory"}
        actual_files = {path for path, entry in before.items() if entry.get("type") == "file"}
        result["unknown_entries"] = sorted((actual_dirs - allowed_dirs) | (actual_files - allowed_files))
        result["missing_entries"] = sorted((allowed_dirs - actual_dirs) | (allowed_files - actual_files))
        if result["unknown_entries"]:
            _raise("bundle_unknown_entry_detected")
        if result["missing_entries"]:
            _raise("bundle_missing_entry_detected")
        # This is an initial descriptor-bound observation.  Success fields are
        # set only after the independent caller-visible final rebind.

        parsed: dict[str, Any] = {"BUNDLE_COMPLETE.json": completion}
        for relative in sorted(JSON_FILES - {"BUNDLE_COMPLETE.json"}):
            parsed[relative] = _strict_json(reader.read_file(relative), relative)

        allowlist = {
            "directories": sorted(allowed_dirs),
            "files": sorted(allowed_files),
            "checksum_payload_files": sorted(payload_files),
        }
        completion_keys = {
            "schema_name", "bundle_complete", "seal_version",
            "bundle_verification_contract_version",
            "bundle_valid_only_when_strict_verifier_currently_passes",
            "bundle_immutable", "bundle_tamper_prevention_provided", "selected_path",
            "allowlist", "allowlist_sha256", "checksum_record_count", "checksums_sha256",
            "completion_requires_intended_final_binding",
            "hidden_staging_completion_claim_valid", "intended_final_name",
            "intended_parent_device", "intended_parent_inode", "owned_root_device",
            "owned_root_inode", "ownership_id", "policy_decision_verified",
        }
        if (
            set(completion) != completion_keys
            or not isinstance(completion.get("allowlist"), dict)
            or set(completion["allowlist"])
            != {"directories", "files", "checksum_payload_files"}
            or completion.get("bundle_complete") is not True
            or not _exact_int(completion.get("seal_version"), 1)
            or not _exact_int(
                completion.get("bundle_verification_contract_version"),
                BUNDLE_VERIFICATION_CONTRACT_VERSION,
            )
            or completion.get("bundle_valid_only_when_strict_verifier_currently_passes")
            is not True
            or completion.get("bundle_immutable") is not False
            or completion.get("bundle_tamper_prevention_provided") is not False
            or completion.get("allowlist") != allowlist
            or completion.get("allowlist_sha256") != _canonical_sha256(allowlist)
            or not _exact_int(
                completion.get("checksum_record_count"), len(payload_files)
            )
            or completion.get("completion_requires_intended_final_binding") is not True
            or completion.get("hidden_staging_completion_claim_valid") is not False
            or completion.get("intended_final_name") != reader.path.name
            or not _exact_int(
                completion.get("intended_parent_device"), reader.parent_identity["device"]
            )
            or not _exact_int(
                completion.get("intended_parent_inode"), reader.parent_identity["inode"]
            )
            or not _exact_int(
                completion.get("owned_root_device"), reader.root_identity["device"]
            )
            or not _exact_int(
                completion.get("owned_root_inode"), reader.root_identity["inode"]
            )
            or completion.get("policy_decision_verified") is not True
            or not isinstance(completion.get("ownership_id"), str)
            or not completion.get("ownership_id")
        ):
            _raise("bundle_completion_inconsistent")

        ownership = parsed[OWNERSHIP_MARKER_NAME]
        ownership_keys = {
            "schema_name", "ownership_id", "created_staging_name", "creation_mode",
            "intended_final_name", "intended_output_path", "parent_device",
            "parent_inode", "root_device", "root_inode",
        }
        if (
            not isinstance(ownership, dict)
            or set(ownership) != ownership_keys
            or ownership.get("schema_name") != OWNERSHIP_SCHEMA_NAME
            or ownership.get("ownership_id") != completion.get("ownership_id")
            or re.fullmatch(r"[0-9a-f]{32}", ownership.get("ownership_id", "")) is None
            or not isinstance(ownership.get("created_staging_name"), str)
            or re.fullmatch(
                rf"\.{re.escape(reader.path.name)}\.clu-git-adapt-[0-9a-f]{{32}}",
                ownership.get("created_staging_name", ""),
            )
            is None
            or not _exact_int(ownership.get("creation_mode"), 0o700)
            or ownership.get("intended_final_name") != reader.path.name
            or ownership.get("intended_output_path") != str(reader.path)
            or not _exact_int(
                ownership.get("parent_device"), reader.parent_identity["device"]
            )
            or not _exact_int(
                ownership.get("parent_inode"), reader.parent_identity["inode"]
            )
            or not _exact_int(
                ownership.get("root_device"), reader.root_identity["device"]
            )
            or not _exact_int(
                ownership.get("root_inode"), reader.root_identity["inode"]
            )
        ):
            _raise("bundle_publication_binding_invalid")
        if not reader.binding_valid():
            _raise("bundle_publication_binding_invalid")
        result["publication_binding_verified"] = True

        checksum_bytes = reader.read_file("CHECKSUMS.sha256")
        try:
            lines = checksum_bytes.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            _raise("bundle_checksum_invalid")
        expected_payload = sorted(payload_files)
        if len(lines) != len(expected_payload):
            _raise("bundle_checksum_invalid")
        seen: set[str] = set()
        for line, relative in zip(lines, expected_payload):
            try:
                digest, observed_path = line.split("  ", 1)
            except ValueError:
                _raise("bundle_checksum_invalid")
            if (
                observed_path != relative
                or observed_path in seen
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or before.get(relative, {}).get("sha256") != digest
            ):
                _raise("bundle_checksum_invalid")
            seen.add(observed_path)
        if completion.get("checksums_sha256") != _sha256(checksum_bytes):
            _raise("bundle_completion_inconsistent")
        result["checksums_verified"] = True
        result["completion_verified"] = True

        request = parsed["source_mutation_request.json"]
        rollback = parsed["rollback_snapshot.json"]
        provenance = parsed["git_provenance.json"]
        decision = parsed["policy_decision.json"]
        baseline = reader.read_file(f"baseline_source/{selected}")
        preview = reader.read_file("change_preview.diff")
        baseline_hash = _sha256(baseline)
        try:
            baseline_text = baseline.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            _raise("bundle_request_rollback_binding_invalid")
        if b"\0" in baseline or len(baseline) > MAX_ADAPTER_FILE_BYTES:
            _raise("bundle_request_rollback_binding_invalid")

        request_keys = {
            "schema_name", "schema_version", "request_id", "declared_actor_id",
            "actor_identity_source", "requested_scope", "proposal_id", "proposal_body",
            "proposal_hash", "source_tree_hash", "operations", "rollback_readiness",
            "git_provenance",
        }
        proposal_keys = {
            "description", "proposed_utf8_content", "selected_path", "head_commit_oid",
            "baseline_blob_oid", "baseline_content_sha256", "proposed_content_sha256",
            "source_surface_mode", "full_repository_hash_verified",
        }
        request_provenance_keys = {
            "head_oid", "object_format", "baseline_blob_oid", "source_surface_mode",
            "repository_identity_authenticated", "remote_identity_verified",
            "head_signature_verified",
        }
        readiness_keys = {
            "schema_name", "schema_version", "artifact_path", "artifact_sha256", "files",
        }
        rollback_keys = {"schema_name", "schema_version", "snapshot_id", "files"}
        rollback_entry_keys = {
            "path", "before_sha256", "original_content", "content_encoding",
        }
        proposal = request.get("proposal_body") if isinstance(request, dict) else None
        operations = request.get("operations") if isinstance(request, dict) else None
        readiness = request.get("rollback_readiness") if isinstance(request, dict) else None
        request_provenance = request.get("git_provenance") if isinstance(request, dict) else None
        rollback_files = rollback.get("files") if isinstance(rollback, dict) else None
        operation = operations[0] if isinstance(operations, list) and len(operations) == 1 else None
        readiness_files = readiness.get("files") if isinstance(readiness, dict) else None
        rollback_entry = (
            rollback_files.get(selected) if isinstance(rollback_files, dict) else None
        )
        proposed_text = proposal.get("proposed_utf8_content") if isinstance(proposal, dict) else None
        try:
            proposed_bytes = proposed_text.encode("utf-8") if isinstance(proposed_text, str) else None
        except UnicodeEncodeError:
            proposed_bytes = None
        object_format = (
            request_provenance.get("object_format")
            if isinstance(request_provenance, dict)
            else None
        )
        head_oid = (
            request_provenance.get("head_oid")
            if isinstance(request_provenance, dict)
            else None
        )
        baseline_blob_oid = (
            request_provenance.get("baseline_blob_oid")
            if isinstance(request_provenance, dict)
            else None
        )
        operation_expected = {
            "operation": "modify", "path": selected, "before_sha256": baseline_hash
        }
        if (
            not isinstance(request, dict)
            or set(request) != request_keys
            or request.get("schema_name") != REQUEST_SCHEMA_NAME
            or request.get("schema_version") != "1"
            or not _nonempty_string(request.get("declared_actor_id"))
            or not _nonempty_string(request.get("requested_scope"))
            or request.get("actor_identity_source") != "caller_declared"
            or not isinstance(proposal, dict)
            or set(proposal) != proposal_keys
            or proposal.get("description")
            != "Adapt one tracked unstaged UTF-8 text modification for local governance evaluation."
            or proposal.get("selected_path") != selected
            or proposal.get("source_surface_mode") != SOURCE_SURFACE_MODE
            or proposal.get("full_repository_hash_verified") is not False
            or proposal.get("baseline_content_sha256") != baseline_hash
            or not isinstance(proposed_bytes, bytes)
            or not 0 <= len(proposed_bytes) <= MAX_ADAPTER_FILE_BYTES
            or b"\0" in proposed_bytes
            or proposed_bytes == baseline
            or proposal.get("proposed_content_sha256") != _sha256(proposed_bytes)
            or request.get("proposal_hash") != _canonical_sha256(proposal)
            or not isinstance(request_provenance, dict)
            or set(request_provenance) != request_provenance_keys
            or request_provenance.get("source_surface_mode") != SOURCE_SURFACE_MODE
            or request_provenance.get("repository_identity_authenticated") is not False
            or request_provenance.get("remote_identity_verified") is not False
            or request_provenance.get("head_signature_verified") is not False
            or not _exact_git_oid(head_oid, object_format)
            or not _exact_git_oid(baseline_blob_oid, object_format)
            or proposal.get("head_commit_oid") != head_oid
            or proposal.get("baseline_blob_oid") != baseline_blob_oid
            or not isinstance(operations, list)
            or operations != [operation_expected]
            or not isinstance(operation, dict)
            or set(operation) != {"operation", "path", "before_sha256"}
            or not isinstance(readiness, dict)
            or set(readiness) != readiness_keys
            or readiness.get("schema_name") != ROLLBACK_SCHEMA_NAME
            or readiness.get("schema_version") != "1"
            or readiness.get("artifact_sha256")
            != before["rollback_snapshot.json"]["sha256"]
            or readiness.get("artifact_path") != str(reader.path / "rollback_snapshot.json")
            or readiness_files != {selected: {"before_sha256": baseline_hash}}
            or not isinstance(rollback, dict)
            or set(rollback) != rollback_keys
            or rollback.get("schema_name") != ROLLBACK_SCHEMA_NAME
            or rollback.get("schema_version") != "1"
            or not isinstance(rollback_files, dict)
            or set(rollback_files) != {selected}
            or not isinstance(rollback_entry, dict)
            or set(rollback_entry) != rollback_entry_keys
            or rollback_entry.get("path") != selected
            or rollback_entry.get("before_sha256") != baseline_hash
            or rollback_entry.get("content_encoding") != "utf-8"
            or rollback_entry.get("original_content") != baseline_text
        ):
            _raise("bundle_request_rollback_binding_invalid")
        tree_hasher = hashlib.sha256()
        tree_hasher.update(selected.encode("utf-8"))
        tree_hasher.update(b"\0")
        tree_hasher.update(baseline_hash.encode("ascii"))
        tree_hasher.update(b"\0")
        expected_source_hash = tree_hasher.hexdigest()
        identity_seed = _canonical_sha256(
            {
                "head": head_oid,
                "path": selected,
                "proposed": proposal["proposed_content_sha256"],
                "actor": request["declared_actor_id"],
                "scope": request["requested_scope"],
            }
        )[:20]
        snapshot_seed = _canonical_sha256(
            {"head_oid": head_oid, "path": selected, "baseline_sha256": baseline_hash}
        )[:20]
        if (
            request.get("source_tree_hash") != expected_source_hash
            or request.get("request_id") != f"git-adapt-request-{identity_seed}"
            or request.get("proposal_id") != f"git-adapt-proposal-{identity_seed}"
            or rollback.get("snapshot_id") != f"git-adapt-{snapshot_seed}"
        ):
            _raise("bundle_request_rollback_binding_invalid")
        result["request_rollback_binding_verified"] = True

        expected_preview = _expected_preview(selected, baseline_text, proposed_text)
        expected_mode = provenance.get("head_file_mode") if isinstance(provenance, dict) else None
        expected_true_provenance_fields = {
            "accepted_snapshot_status_independently_parsed",
            "baseline_git_blob_oid_recomputed", "baseline_git_blob_oid_verified",
            "candidate_and_accepted_snapshot_records_match",
            "content_sensitive_git_exec_sandbox_enforced",
            "external_process_execution_blocked_by_configuration_policy",
            "git_environment_inheritance_bounded",
            "git_metadata_descriptor_boundary_enforced",
            "git_metadata_direct_dot_git_only", "git_no_lazy_fetch_enforced",
            "git_object_root_inside_repository", "git_ref_storage_backend_verified",
            "git_reftable_path_absent_required", "git_replace_objects_disabled",
            "git_subprocess_output_capped_during_execution",
            "output_ownership_marker_retained", "output_parent_device_inode_bound",
            "output_parent_directory_descriptor_bound", "policy_decision_verified",
            "repository_config_read_with_typed_git_semantics",
            "selected_path_parent_components_no_follow_verified",
            "status_uses_sanitized_local_config_view",
        }
        expected_false_provenance_fields = {
            "assume_unchanged_index_entries_supported",
            "automatic_nonempty_failure_cleanup_performed",
            "external_reftable_storage_used", "external_ref_storage_content_packaged",
            "external_object_database_used", "external_baseline_content_packaged",
            "full_repository_hash_verified", "full_repository_governance_claim_allowed",
            "repository_identity_authenticated", "remote_identity_verified",
            "head_signature_verified", "declared_actor_identity_authenticated",
            "git_index_mutated", "git_head_mutated", "git_refs_mutated",
            "git_config_mutated", "git_lock_files_created", "git_external_diff_executed",
            "git_external_object_database_supported", "git_hooks_executed",
            "git_metadata_root_symlink_detected", "git_object_root_symlink_detected",
            "git_reftable_supported", "git_shell_execution_used", "git_textconv_executed",
            "partial_or_promisor_repository_supported",
            "path_based_check_then_unlink_cleanup_used",
            "recursive_unverified_output_cleanup_used",
            "repository_config_includes_supported",
            "repository_filter_driver_config_supported",
            "skip_worktree_index_entries_supported",
            "sparse_checkout_or_sparse_index_supported",
            "unknown_repository_extensions_supported",
        }
        repository_root_value = provenance.get("repository_root") if isinstance(provenance, dict) else None
        index_path_value = provenance.get("index_path") if isinstance(provenance, dict) else None
        metadata_before = provenance.get("metadata_inventory_before") if isinstance(provenance, dict) else None
        metadata_after = provenance.get("metadata_inventory_after") if isinstance(provenance, dict) else None
        refs_before = provenance.get("refs_sha256_before") if isinstance(provenance, dict) else None
        refs_after = provenance.get("refs_sha256_after") if isinstance(provenance, dict) else None
        config_before = provenance.get("config_sha256_before") if isinstance(provenance, dict) else None
        config_after = provenance.get("config_sha256_after") if isinstance(provenance, dict) else None
        logged_config_payloads: list[tuple[int, str]] = []
        if isinstance(metadata_before, dict) and isinstance(config_before, dict):
            for config_relative, config_digest in sorted(config_before.items()):
                config_record = metadata_before.get(config_relative)
                if isinstance(config_record, dict):
                    logged_config_payloads.append(
                        (config_record.get("size"), config_digest)
                    )
        expected_ref_hash_paths: set[str] = set()
        expected_config_hash_paths: set[str] = set()
        if isinstance(metadata_before, dict):
            expected_ref_hash_paths = {
                path
                for path, record in metadata_before.items()
                if isinstance(record, dict)
                and record.get("kind") == "file"
                and (path == "HEAD" or path == "packed-refs" or path.startswith("refs/"))
            }
            expected_config_hash_paths = {
                path
                for path in ("config", "config.worktree")
                if isinstance(metadata_before.get(path), dict)
                and metadata_before[path].get("kind") == "file"
            }
        if (
            not isinstance(provenance, dict)
            or set(provenance) != PROVENANCE_KEYS
            or provenance.get("schema_name") != PROVENANCE_SCHEMA_NAME
            or provenance.get("schema_version") != "1"
            or not _exact_int(provenance.get("contract_version"), 1)
            or provenance.get("supported_change_mode") != SUPPORTED_CHANGE_MODE
            or provenance.get("source_surface_mode") != SOURCE_SURFACE_MODE
            or provenance.get("selected_path") != selected
            or provenance.get("object_format") != object_format
            or provenance.get("head_oid") != head_oid
            or provenance.get("baseline_blob_oid") != baseline_blob_oid
            or not _exact_int(provenance.get("baseline_blob_size"), len(baseline))
            or provenance.get("baseline_content_sha256") != baseline_hash
            or provenance.get("working_tree_content_sha256")
            != proposal.get("proposed_content_sha256")
            or not _exact_int(provenance.get("working_tree_size"), len(proposed_bytes))
            or expected_mode not in {"100644", "100755"}
            or provenance.get("working_tree_mode") != expected_mode
            or provenance.get("change_preview_sha256") != _sha256(preview)
            or preview != expected_preview
            or provenance.get("baseline_git_blob_oid_recomputed") is not True
            or provenance.get("baseline_git_blob_oid_verified") is not True
            or provenance.get("supported_git_ref_storage_backend") != "files"
            or provenance.get("git_ref_storage_backend") != "files"
            or provenance.get("git_ref_storage_backend_verified") is not True
            or provenance.get("git_ref_storage_backend_evidence_source")
            not in {
                "git_rev_parse_show_ref_format",
                "captured_config_and_absent_reftable_fallback",
            }
            or provenance.get("git_reftable_supported") is not False
            or provenance.get("git_reftable_path_absent_required") is not True
            or provenance.get("unknown_repository_extensions_supported") is not False
            or provenance.get("git_metadata_roots_bound")
            != ["objects", "objects/pack", "objects/info", "refs", "info"]
            or provenance.get("content_sensitive_git_sandbox_backend")
            != "macos_sandbox_exec_network_and_non_git_descendant_exec_deny"
            or type(provenance.get("content_sensitive_git_sandboxed_command_count")) is not int
            or provenance.get("content_sensitive_git_sandboxed_command_count", 0) <= 0
            or type(provenance.get("tracked_index_path_count")) is not int
            or not 1 <= provenance.get("tracked_index_path_count", 0) <= 100000
            or not _nonempty_string(provenance.get("git_version"))
            or not _nonempty_string(provenance.get("read_only_proof_scope"))
            or not _git_command_log_valid(
                provenance.get("git_commands"),
                selected_path=selected,
                baseline_blob_oid=baseline_blob_oid,
                config_payloads=logged_config_payloads,
            )
            or not _nonempty_string(repository_root_value)
            or not Path(repository_root_value).is_absolute()
            or not _nonempty_string(index_path_value)
            or Path(index_path_value) != Path(repository_root_value) / ".git" / "index"
            or any(provenance.get(field) is not True for field in expected_true_provenance_fields)
            or any(provenance.get(field) is not False for field in expected_false_provenance_fields)
            or not _exact_int(provenance.get("git_network_commands"), 0)
            or not _exact_int(provenance.get("repository_configured_external_helpers_executed"), 0)
            or not _exact_int(provenance.get("runtime_network_access_observed"), 0)
            or not _metadata_inventory_valid(metadata_before)
            or metadata_after != metadata_before
            or not _hash_inventory_valid(
                refs_before, metadata_before, required={"HEAD"}
            )
            or set(refs_before) != expected_ref_hash_paths
            or refs_after != refs_before
            or not _hash_inventory_valid(
                config_before, metadata_before, required={"config"}
            )
            or set(config_before) != expected_config_hash_paths
            or config_after != config_before
            or not _exact_sha256(provenance.get("index_sha256_before"))
            or provenance.get("index_sha256_before")
            != metadata_before.get("index", {}).get("sha256")
            or provenance.get("index_sha256_after") != provenance.get("index_sha256_before")
            or not _exact_sha256(provenance.get("index_state_sha256_before"))
            or provenance.get("index_state_sha256_after")
            != provenance.get("index_state_sha256_before")
            or not _exact_sha256(provenance.get("porcelain_v2_status_sha256"))
            or provenance.get("lock_files_before") != []
            or provenance.get("lock_files_after") != []
            or provenance.get("repository_files_created") != []
            or provenance.get("repository_files_removed") != []
            or provenance.get("repository_files_changed") != []
            or provenance.get("index_sha256_before") != provenance.get("index_sha256_after")
            or provenance.get("index_state_sha256_before")
            != provenance.get("index_state_sha256_after")
            or provenance.get("refs_sha256_before") != provenance.get("refs_sha256_after")
            or provenance.get("config_sha256_before") != provenance.get("config_sha256_after")
            or provenance.get("lock_files_before") != provenance.get("lock_files_after")
            or provenance.get("metadata_inventory_before")
            != provenance.get("metadata_inventory_after")
            or provenance.get("policy_decision_verified") is not True
        ):
            _raise("bundle_provenance_binding_invalid")
        if _git_blob_oid(baseline, object_format) != baseline_blob_oid:
            _raise("bundle_provenance_binding_invalid")
        result["git_blob_oid_verified"] = True
        result["preview_binding_verified"] = True
        result["provenance_binding_verified"] = True

        decision_keys = {
            "schema_name", "schema_version", "request_id", "proposal_id", "policy_id",
            "policy_hash", "canonical_request_hash", "decision",
            "eligible_for_human_approval", "operator_approval_required",
            "mutation_authorized", "mutation_applied", "declared_actor_id",
            "actor_identity_authenticated", "actor_identity_source", "requested_scope",
            "checked_paths_and_operations", "matched_rule_id", "reason_code", "reason_text",
            "exact_blocker", "proposal_hash_supplied", "proposal_hash_verified",
            "source_hash_supplied", "source_hash_verified", "rollback_readiness_verified",
            "rollback_requested", "rollback_executed", "sequence_index", "event_timestamp",
            "network_calls", "provider_calls", "advisor_calls", "mem0_runs",
            "benchmark_runs", "execution_binding", "execution_binding_hash",
            "audit_event_hash",
        }
        supplied_audit_hash = decision.get("audit_event_hash") if isinstance(decision, dict) else None
        checked = decision.get("checked_paths_and_operations") if isinstance(decision, dict) else None
        if (
            not isinstance(decision, dict)
            or set(decision) != decision_keys
            or decision.get("schema_name") != DECISION_SCHEMA_NAME
            or decision.get("schema_version") != "1"
            or decision.get("decision") not in {"allow", "deny"}
            or not _exact_sha256(supplied_audit_hash)
            or supplied_audit_hash
            != _canonical_sha256(
                {key: value for key, value in decision.items() if key != "audit_event_hash"}
            )
            or decision.get("canonical_request_hash") != _canonical_sha256(request)
            or decision.get("proposal_hash_supplied") != request.get("proposal_hash")
            or decision.get("proposal_hash_verified") != request.get("proposal_hash")
            or decision.get("source_hash_supplied") != expected_source_hash
            or decision.get("source_hash_verified") != expected_source_hash
            or decision.get("request_id") != request.get("request_id")
            or decision.get("proposal_id") != request.get("proposal_id")
            or decision.get("declared_actor_id") != request.get("declared_actor_id")
            or decision.get("requested_scope") != request.get("requested_scope")
            or decision.get("actor_identity_source") != "caller_declared"
            or decision.get("actor_identity_authenticated") is not False
            or decision.get("operator_approval_required") is not True
            or decision.get("mutation_authorized") is not False
            or decision.get("mutation_applied") is not False
            or decision.get("rollback_requested") is not False
            or decision.get("rollback_executed") is not False
            or not _exact_sha256(decision.get("policy_hash"))
            or not _nonempty_string(decision.get("reason_code"))
            or not _nonempty_string(decision.get("reason_text"))
            or not _nonempty_string(decision.get("event_timestamp"))
            or not isinstance(checked, list)
            or any(item != operation_expected for item in checked)
            or not _exact_int(decision.get("sequence_index"), 1)
            or not _exact_int(decision.get("network_calls"), 0)
            or not _exact_int(decision.get("provider_calls"), 0)
            or not _exact_int(decision.get("advisor_calls"), 0)
            or not _exact_int(decision.get("mem0_runs"), 0)
            or not _exact_int(decision.get("benchmark_runs"), 0)
        ):
            _raise("bundle_decision_integrity_invalid")
        if decision["decision"] == "allow":
            expected_binding = _expected_execution_binding(request, decision)
            if (
                checked != [operation_expected]
                or not _nonempty_string(decision.get("policy_id"))
                or decision.get("eligible_for_human_approval") is not True
                or decision.get("rollback_readiness_verified") is not True
                or decision.get("exact_blocker") is not None
                or not _nonempty_string(decision.get("matched_rule_id"))
                or decision.get("reason_code") != "eligible_for_human_approval"
                or decision.get("reason_text")
                != "Request satisfies v0.1 policy gate and is eligible for a separate approval decision only."
                or decision.get("execution_binding") != expected_binding
                or decision.get("execution_binding_hash")
                != expected_binding["execution_binding_hash"]
            ):
                _raise("bundle_decision_integrity_invalid")
            result["execution_binding_verified"] = True
        else:
            exact_blocker = decision.get("exact_blocker")
            adapter_reachable_deny_reasons = {
                "policy_malformed_json", "policy_missing", "policy_wrong_schema",
                "policy_id_missing", "allow_by_default_policy_rejected",
                "maximum_file_count_missing", "rules_missing", "rule_malformed",
                "rule_id_missing_or_duplicate", "unknown_rule_effect_denied",
                "declared_actor_id_not_allowed", "requested_scope_not_allowed",
                "maximum_file_count_exceeded", "unknown_or_disallowed_operation_denied",
                "sensitive_path_denied", "explicit_deny_rule_matched",
                "explicit_denied_path_matched", "path_not_explicitly_allowed",
                "allow_rule_missing",
            }
            policy_id = decision.get("policy_id")
            policy_id_valid = (
                _nonempty_string(policy_id)
                or (
                    policy_id is None
                    and exact_blocker
                    in {"policy_malformed_json", "policy_missing", "policy_wrong_schema", "policy_id_missing"}
                )
            )
            matched_rule_valid = (
                _nonempty_string(decision.get("matched_rule_id"))
                if exact_blocker == "explicit_deny_rule_matched"
                else decision.get("matched_rule_id") is None
            )
            if (
                checked != []
                or decision.get("eligible_for_human_approval") is not False
                or decision.get("rollback_readiness_verified") is not False
                or not _nonempty_string(exact_blocker)
                or exact_blocker not in adapter_reachable_deny_reasons
                or not policy_id_valid
                or decision.get("reason_code") != exact_blocker
                or decision.get("reason_text") != exact_blocker.replace("_", " ")
                or decision.get("execution_binding") is not None
                or decision.get("execution_binding_hash") is not None
                or not matched_rule_valid
            ):
                _raise("bundle_decision_integrity_invalid")
            result["execution_binding_verified"] = True
        if provenance.get("policy_decision") != decision.get("decision"):
            _raise("bundle_provenance_binding_invalid")
        result["decision_integrity_verified"] = True

        after, after_issues = reader.inventory()
        created, removed, changed = _inventory_delta(before, after)
        result["files_created_during_verification"] = created
        result["files_removed_during_verification"] = removed
        result["files_changed_during_verification"] = changed
        if created or removed or changed or any(after_issues.values()):
            _raise("bundle_changed_during_verification")
        if BUNDLE_PATH_CHAIN_TEST_HOOK is not None:
            BUNDLE_PATH_CHAIN_TEST_HOOK("before_final_rebind", {"path": str(reader.path)})
        try:
            fresh_lease = reader.lease.fresh_rebind(
                hook=BUNDLE_PATH_CHAIN_TEST_HOOK, phase="final"
            )
        except PathChainError as exc:
            _raise(str(exc))
        try:
            fresh_reader = BundleReader.from_lease(fresh_lease)
            if BUNDLE_PATH_CHAIN_TEST_HOOK is not None:
                BUNDLE_PATH_CHAIN_TEST_HOOK(
                    "after_final_rebind_before_inventory", {"path": str(reader.path)}
                )
            final_inventory, final_issues = fresh_reader.inventory()
            final_created, final_removed, final_changed = _inventory_delta(before, final_inventory)
            result["files_created_during_verification"] = final_created
            result["files_removed_during_verification"] = final_removed
            result["files_changed_during_verification"] = final_changed
            if final_created or final_removed or final_changed or any(final_issues.values()):
                _raise("caller_visible_bundle_final_verification_failed")
            # Reopen from / once more after the final exact inventory so the
            # caller-visible edge is current at the recorded verification point.
            confirmation = reader.lease.fresh_rebind(
                hook=BUNDLE_PATH_CHAIN_TEST_HOOK, phase="confirmation"
            )
            try:
                confirmation_reader = BundleReader.from_lease(confirmation)
                confirmed_inventory, confirmed_issues = confirmation_reader.inventory()
                confirmed_created, confirmed_removed, confirmed_changed = _inventory_delta(
                    before, confirmed_inventory
                )
                result["files_created_during_verification"] = confirmed_created
                result["files_removed_during_verification"] = confirmed_removed
                result["files_changed_during_verification"] = confirmed_changed
                if (
                    confirmed_created or confirmed_removed or confirmed_changed
                    or any(confirmed_issues.values())
                ):
                    _raise("caller_visible_bundle_final_verification_failed")
                confirmation.assert_named_edges(compare_temporal=True)
            finally:
                confirmation.close()
        except PathChainError as exc:
            _raise(str(exc))
        finally:
            fresh_lease.close()
        result.update(
            {
                "exact_file_set_verified": True,
                "bundle_exact_set_verified_at_return": True,
                "bundle_full_ancestor_chain_reverified_at_return": True,
                "caller_visible_bundle_path_bound_at_return": True,
                "caller_visible_bundle_root_identity_verified": True,
                "bundle_verification_timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        result.update({"result": "verified", "verified": True, "exact_blocker": None})
        validate_verifier_result(result)
        return result
    except BundleVerificationError as exc:
        result["verified"] = False
        result["exact_file_set_verified"] = False
        result["checksums_verified"] = False
        result["completion_verified"] = False
        result["publication_binding_verified"] = False
        result["bundle_exact_set_verified_at_return"] = False
        result["exact_blocker"] = str(exc)
        if reader is not None:
            try:
                after, _issues = reader.inventory()
                created, removed, changed = _inventory_delta(before, after)
                result["files_created_during_verification"] = created
                result["files_removed_during_verification"] = removed
                result["files_changed_during_verification"] = changed
                result["unknown_entries"] = sorted(
                    set(result.get("unknown_entries") or []) | set(created)
                )
                result["missing_entries"] = sorted(
                    set(result.get("missing_entries") or []) | set(removed)
                )
                if created or removed or changed:
                    result["exact_blocker"] = "bundle_changed_during_verification"
            except Exception:
                pass
        validate_verifier_result(result)
        return result
    except Exception as exc:
        result["result"] = "failed"
        result["bundle_exact_set_verified_at_return"] = False
        result["exact_blocker"] = f"bundle_verifier_runtime_failure:{type(exc).__name__}"
        validate_verifier_result(result)
        return result
    finally:
        if reader is not None:
            reader.close()


def exit_code_for_result(result: dict[str, Any]) -> int:
    if result.get("verified") is True:
        return 0
    if result.get("result") == "failed":
        return 1
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify one currently published CLU Governance bundle without modifying it."
    )
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = verify_bundle(Path(args.bundle))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"verified={str(bool(result['verified'])).lower()}")
    return exit_code_for_result(result)


if __name__ == "__main__":
    raise SystemExit(main())
