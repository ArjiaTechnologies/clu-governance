"""Strict evidence for one absent-before UTF-8 file; never creates a file.

Directory identities are local, point-in-time observations, not a lock or an
authenticated attestation. Callers must revalidate before any separate apply.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any

from . import strict_json


OPERATION_FIELDS = {"operation", "path", "before_state", "before_sha256", "content_encoding",
                    "after_sha256", "parent_identities"}
_COMPONENT = re.compile(r"[A-Za-z0-9_.-]+\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DEVICES = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


class NewFileProposalError(ValueError):
    """A stable denial reason for the bounded create contract."""


def canonical_create_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise NewFileProposalError("create_path_not_canonical")
    for part in value.split("/"):
        if (not _COMPONENT.fullmatch(part) or part in {".", ".."} or part.endswith(".")
                or part.split(".", 1)[0].lower() in _DEVICES):
            raise NewFileProposalError("create_path_not_canonical")
    return value


def validate_operation(operation: Any) -> dict[str, Any]:
    if not isinstance(operation, dict) or set(operation) != OPERATION_FIELDS or operation.get("operation") != "create":
        raise NewFileProposalError("create_operation_contract_invalid")
    path = canonical_create_path(operation["path"])
    if operation["before_state"] != "absent" or operation["before_sha256"] is not None:
        raise NewFileProposalError("create_absent_before_required")
    if operation["content_encoding"] != "utf-8":
        raise NewFileProposalError("create_content_encoding_unsupported")
    if not isinstance(operation["after_sha256"], str) or not _DIGEST.fullmatch(operation["after_sha256"]):
        raise NewFileProposalError("create_after_hash_invalid")
    parents = operation["parent_identities"]
    parts = path.split("/")[:-1]
    expected_paths = ["."] + ["/".join(parts[:index + 1]) for index in range(len(parts))]
    if not isinstance(parents, list) or len(parents) != len(expected_paths):
        raise NewFileProposalError("create_parent_identity_invalid")
    for entry, expected in zip(parents, expected_paths):
        if (not isinstance(entry, dict) or set(entry) != {"path", "device", "inode"}
                or entry["path"] != expected or type(entry["device"]) is not int or entry["device"] < 0
                or type(entry["inode"]) is not int or entry["inode"] <= 0):
            raise NewFileProposalError("create_parent_identity_invalid")
    return operation


def validate_proposal(operation: dict[str, Any], proposal: Any) -> None:
    validate_operation(operation)
    if not isinstance(proposal, dict) or set(proposal) != {"operation", "path", "content_encoding", "proposed_content", "after_sha256"}:
        raise NewFileProposalError("create_proposal_contract_invalid")
    if any(proposal.get(key) != operation[key] for key in ("operation", "path", "content_encoding", "after_sha256")):
        raise NewFileProposalError("create_proposal_operation_mismatch")
    content = proposal.get("proposed_content")
    if not isinstance(content, str) or "\x00" in content:
        raise NewFileProposalError("create_proposed_content_invalid")
    try:
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    except UnicodeError:
        raise NewFileProposalError("create_proposed_content_invalid") from None
    if digest != operation["after_sha256"]:
        raise NewFileProposalError("create_proposed_content_hash_mismatch")


def _directory_identity(path: Path) -> tuple[int, int]:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_ino <= 0):
        raise NewFileProposalError("create_parent_link_or_identity_denied")
    return info.st_dev, info.st_ino


def inspect_absent_target(source_root: Path, relative: str) -> tuple[list[dict[str, Any]], list[tuple[str, int, int]]]:
    """Capture no-follow parents and reject existing names, including case aliases.

All ancestors of the supplied source root are checked before resolving it.
The second return value remains local and is used for final revalidation.
"""
    canonical_create_path(relative)
    root = source_root.expanduser().absolute()
    if ".." in root.parts:
        raise NewFileProposalError("create_source_root_not_canonical")
    chain: list[tuple[str, int, int]] = []
    identities: list[dict[str, Any]] = []
    try:
        for ancestor in [*reversed(root.parents), root]:
            device, inode = _directory_identity(ancestor)
            chain.append((str(ancestor), device, inode))
        identities.append({"path": ".", "device": chain[-1][1], "inode": chain[-1][2]})
        current = root
        parts = relative.split("/")
        for index, name in enumerate(parts):
            aliases = [entry.name for entry in current.iterdir() if entry.name.casefold() == name.casefold()]
            if index == len(parts) - 1:
                if aliases:
                    raise NewFileProposalError("create_target_not_absent")
                # Explicit lstat also catches dangling links and host aliases.
                try:
                    (current / name).lstat()
                except FileNotFoundError:
                    pass
                else:
                    raise NewFileProposalError("create_target_not_absent")
            else:
                if aliases != [name]:
                    raise NewFileProposalError("create_parent_missing_or_case_alias")
                current = current / name
                device, inode = _directory_identity(current)
                chain.append((str(current), device, inode))
                identities.append({"path": "/".join(parts[:index + 1]), "device": device, "inode": inode})
    except OSError:
        raise NewFileProposalError("create_target_observation_failed") from None
    return identities, chain


def validate_rollback(request: dict[str, Any], operation: dict[str, Any], schema_name: str) -> None:
    """Verify exact absence/conditional-removal evidence from one byte read."""
    readiness = request.get("rollback_readiness")
    if not isinstance(readiness, dict) or readiness.get("schema_name") != schema_name or readiness.get("schema_version") != "1":
        raise NewFileProposalError("create_rollback_readiness_required")
    raw_path = readiness.get("artifact_path")
    if not isinstance(raw_path, str) or not Path(raw_path).is_absolute():
        raise NewFileProposalError("create_rollback_path_invalid")
    path = Path(raw_path)
    try:
        for parent in reversed(path.parents):
            _directory_identity(parent)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise NewFileProposalError("create_rollback_link_or_type_denied")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != readiness.get("artifact_sha256"):
            raise NewFileProposalError("create_rollback_hash_mismatch")
        artifact = strict_json.loads(data.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        if isinstance(exc, NewFileProposalError):
            raise
        raise NewFileProposalError("create_rollback_unreadable") from None
    expected = {"path": operation["path"], "before_state": "absent", "before_sha256": None,
                "rollback_operation": "remove_created_file", "after_sha256": operation["after_sha256"],
                "parent_identities": operation["parent_identities"]}
    if (not isinstance(artifact, dict) or artifact.get("schema_name") != schema_name
            or artifact.get("schema_version") != "1" or not artifact.get("snapshot_id")
            or json.dumps(artifact.get("files"), sort_keys=True) != json.dumps({operation["path"]: expected}, sort_keys=True)
            or json.dumps(readiness.get("files"), sort_keys=True) != json.dumps(artifact["files"], sort_keys=True)):
        raise NewFileProposalError("create_rollback_absence_binding_mismatch")
