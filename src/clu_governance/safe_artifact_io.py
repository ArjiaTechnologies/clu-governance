"""Safe local artifact writes for governance evidence surfaces."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any


class SafeArtifactWriteError(ValueError):
    """Raised with a stable blocker when an artifact path is unsafe."""


def _raise(blocker: str) -> None:
    raise SafeArtifactWriteError(blocker)


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def absolute_raw_path(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_absolute():
        return expanded
    return Path.cwd() / expanded


def existing_components(path: Path) -> list[Path]:
    absolute = absolute_raw_path(path)
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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_parent(parent: Path, *, blocker_prefix: str, create_parent: bool) -> Path:
    parent_raw = absolute_raw_path(parent)
    for component in existing_components(parent_raw):
        if component.is_symlink():
            _raise(f"{blocker_prefix}_parent_symlink_denied")
    if not parent_raw.exists():
        if not create_parent:
            _raise(f"{blocker_prefix}_parent_missing")
        parent_raw.mkdir(parents=True, exist_ok=False)
    if parent_raw.is_symlink() or not parent_raw.is_dir():
        _raise(f"{blocker_prefix}_parent_invalid")
    return parent_raw.resolve(strict=True)


def _validate_existing_target(path: Path, *, blocker_prefix: str) -> None:
    if path.is_symlink():
        _raise(f"{blocker_prefix}_symlink_denied")
    if not path.exists():
        return
    try:
        status = path.stat()
    except OSError:
        _raise(f"{blocker_prefix}_non_regular_denied")
    if not stat.S_ISREG(status.st_mode):
        _raise(f"{blocker_prefix}_non_regular_denied")
    if status.st_nlink > 1:
        _raise(f"{blocker_prefix}_hardlink_denied")


def safe_atomic_write_bytes(
    path: Path,
    data: bytes,
    *,
    mode: int = 0o600,
    blocker_prefix: str = "artifact_output",
    create_parent: bool = False,
) -> str:
    """Write bytes through a new regular temp file and atomic replace."""

    target_raw = absolute_raw_path(path)
    parent = _validate_parent(target_raw.parent, blocker_prefix=blocker_prefix, create_parent=create_parent)
    target = parent / target_raw.name
    _validate_existing_target(target, blocker_prefix=blocker_prefix)

    temp_path = parent / f".{target.name}.tmp-{uuid.uuid4().hex}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temp_path, flags, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        if sha256_file(temp_path) != sha256_bytes(data):
            _raise(f"{blocker_prefix}_temp_hash_mismatch")
        os.replace(temp_path, target)
    except Exception:
        try:
            if temp_path.exists() or temp_path.is_symlink():
                temp_path.unlink()
        finally:
            raise
    return sha256_file(target)


def safe_atomic_write_json(
    path: Path,
    payload: Any,
    *,
    mode: int = 0o644,
    blocker_prefix: str = "artifact_output",
    create_parent: bool = False,
) -> str:
    data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    return safe_atomic_write_bytes(
        path,
        data,
        mode=mode,
        blocker_prefix=blocker_prefix,
        create_parent=create_parent,
    )


def validate_output_outside_roots(path: Path, forbidden_roots: list[Path], *, blocker_prefix: str) -> None:
    target_raw = absolute_raw_path(path)
    parent_raw = target_raw.parent
    for root in forbidden_roots:
        root_resolved = root.expanduser().resolve(strict=True)
        parent_resolved = parent_raw.resolve(strict=False)
        target_resolved = target_raw.resolve(strict=False)
        if target_resolved == root_resolved or is_relative_to(target_resolved, root_resolved):
            _raise(f"{blocker_prefix}_inside_source_root_denied")
        if parent_resolved == root_resolved or is_relative_to(parent_resolved, root_resolved):
            _raise(f"{blocker_prefix}_inside_source_root_denied")
