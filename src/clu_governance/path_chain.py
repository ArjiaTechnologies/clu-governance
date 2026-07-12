"""Descriptor-bound absolute directory path leases for POSIX runtimes.

The lease records every caller-visible component from the filesystem root and
keeps each directory descriptor open.  A fresh rebind therefore proves that a
later pathname still reaches the same directories; a stale descriptor alone is
never treated as caller-visible path proof.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


MAX_PATH_COMPONENTS = 128


class PathChainError(ValueError):
    """Stable caller-visible path binding failure."""


def _raise(blocker: str) -> None:
    raise PathChainError(blocker)


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
    )


def _temporal(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


@dataclass(frozen=True)
class DirectoryComponentBinding:
    name: str
    index: int
    device: int
    inode: int
    file_type: int
    mode: int
    nlink: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, name: str, index: int, info: os.stat_result) -> "DirectoryComponentBinding":
        return cls(
            name=name,
            index=index,
            device=info.st_dev,
            inode=info.st_ino,
            file_type=stat.S_IFMT(info.st_mode),
            mode=stat.S_IMODE(info.st_mode),
            nlink=info.st_nlink,
            mtime_ns=info.st_mtime_ns,
            ctime_ns=info.st_ctime_ns,
        )

    def static_identity(self) -> tuple[int, int, int, int]:
        return (self.device, self.inode, self.file_type, self.mode)

    def temporal_identity(self) -> tuple[int, int, int]:
        return (self.nlink, self.mtime_ns, self.ctime_ns)


class AbsoluteDirectoryChainLease:
    """An open, no-follow lease over every component of one directory path."""

    def __init__(self, path: Path, components: list[DirectoryComponentBinding], fds: list[int]):
        self.path = path
        self.components = components
        self._fds = fds
        self.closed = False

    @property
    def root_fd(self) -> int:
        return self._fds[-1]

    @property
    def parent_fd(self) -> int:
        if len(self._fds) < 2:
            return self._fds[0]
        return self._fds[-2]

    @property
    def root_identity(self) -> dict[str, int]:
        item = self.components[-1]
        return {"device": item.device, "inode": item.inode, "mode": item.mode}

    @staticmethod
    def normalize(raw_path: Path) -> Path:
        raw_text = os.fspath(raw_path)
        if not isinstance(raw_text, str) or not raw_text or "\x00" in raw_text:
            _raise("bundle_path_invalid")
        if any(ord(char) < 32 or ord(char) == 127 for char in raw_text):
            _raise("bundle_path_control_character_denied")
        raw = Path(raw_text)
        if not raw.is_absolute():
            raw = Path.cwd() / raw
        if len(raw.parts) > MAX_PATH_COMPONENTS + 1:
            _raise("bundle_path_component_limit_exceeded")
        if any(part in {"", ".", ".."} for part in raw.parts[1:]):
            _raise("bundle_path_traversal_denied")
        return raw

    @classmethod
    def acquire(
        cls,
        raw_path: Path,
        *,
        hook: Callable[[str, dict[str, object]], None] | None = None,
        phase: str = "initial",
    ) -> "AbsoluteDirectoryChainLease":
        path = cls.normalize(raw_path)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fds: list[int] = []
        bindings: list[DirectoryComponentBinding] = []
        try:
            root_fd = os.open(path.anchor, flags)
            fds.append(root_fd)
            root_info = os.fstat(root_fd)
            if not stat.S_ISDIR(root_info.st_mode):
                _raise("bundle_ancestor_chain_changed")
            bindings.append(DirectoryComponentBinding.from_stat(path.anchor, 0, root_info))
            for index, component in enumerate(path.parts[1:], start=1):
                if hook is not None:
                    hook(f"during_{phase}_rebind", {"index": index, "component": component, "path": str(path)})
                parent_before = os.fstat(fds[-1])
                named_before = os.stat(component, dir_fd=fds[-1], follow_symlinks=False)
                if stat.S_ISLNK(named_before.st_mode) or not stat.S_ISDIR(named_before.st_mode):
                    _raise("bundle_parent_symlink_or_identity_denied")
                child = os.open(component, flags, dir_fd=fds[-1])
                child_info = os.fstat(child)
                named_after = os.stat(component, dir_fd=fds[-1], follow_symlinks=False)
                parent_after = os.fstat(fds[-1])
                if (
                    _identity(parent_before) != _identity(parent_after)
                    or _temporal(parent_before) != _temporal(parent_after)
                    or _identity(named_before) != _identity(child_info)
                    or _identity(named_after) != _identity(child_info)
                    or _temporal(named_before) != _temporal(named_after)
                ):
                    os.close(child)
                    _raise("bundle_ancestor_chain_changed")
                fds.append(child)
                bindings.append(DirectoryComponentBinding.from_stat(component, index, child_info))
            return cls(path, bindings, fds)
        except PathChainError:
            for descriptor in reversed(fds):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        except (FileNotFoundError, NotADirectoryError):
            for descriptor in reversed(fds):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            # Initial acquisition did not bind a caller-visible bundle at all:
            # a missing leaf or ancestor is therefore a missing requested path,
            # not evidence that a previously bound path was replaced. A later
            # ``fresh_rebind`` translates this initial-acquisition blocker into
            # a replacement-specific result for an active lease.
            _raise("bundle_path_missing")
        except OSError:
            for descriptor in reversed(fds):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            _raise("bundle_parent_symlink_or_identity_denied")

    def _mismatch_blocker(self, index: int) -> str:
        leaf = len(self.components) - 1
        if index == leaf:
            return "bundle_root_identity_changed"
        if index == leaf - 1:
            return "bundle_parent_identity_changed"
        return "bundle_ancestor_chain_changed"

    def assert_named_edges(self, *, compare_temporal: bool = True) -> None:
        """Require every retained parent/name edge to still name its child fd."""

        temporal_start = max(0, len(self._fds) - 2)
        for index in range(1, len(self._fds)):
            expected = self.components[index]
            try:
                parent = os.fstat(self._fds[index - 1])
                child = os.fstat(self._fds[index])
                named = os.stat(expected.name, dir_fd=self._fds[index - 1], follow_symlinks=False)
            except OSError:
                _raise(self._mismatch_blocker(index))
            mismatch = (
                not stat.S_ISDIR(named.st_mode)
                or _identity(named) != _identity(child)
                or _identity(child) != expected.static_identity()
                or _identity(parent) != self.components[index - 1].static_identity()
            )
            # Temporal metadata for shared system ancestors changes when an
            # unrelated sibling is created or removed. It is not a stable
            # caller-path identity signal. Retain temporal comparison for the
            # bundle root and its immediate parent, while every ancestor edge
            # remains statically descriptor/no-follow bound.
            if compare_temporal and index >= temporal_start:
                mismatch = mismatch or _temporal(child) != expected.temporal_identity()
            if mismatch:
                _raise(self._mismatch_blocker(index))

    def fresh_rebind(
        self,
        *,
        hook: Callable[[str, dict[str, object]], None] | None = None,
        phase: str = "final",
        compare_temporal: bool = True,
    ) -> "AbsoluteDirectoryChainLease":
        try:
            fresh = type(self).acquire(self.path, hook=hook, phase=phase)
        except PathChainError as exc:
            if str(exc) == "caller_visible_bundle_path_replaced":
                raise
            _raise("caller_visible_bundle_path_replaced")
        if len(fresh.components) != len(self.components):
            fresh.close()
            _raise("bundle_ancestor_chain_changed")
        temporal_start = max(0, len(self.components) - 2)
        for expected, observed in zip(self.components, fresh.components):
            mismatch = expected.static_identity() != observed.static_identity()
            if compare_temporal and expected.index >= temporal_start:
                mismatch = mismatch or expected.temporal_identity() != observed.temporal_identity()
            if expected.name != observed.name or mismatch:
                blocker = self._mismatch_blocker(expected.index)
                fresh.close()
                _raise(blocker)
        fresh.assert_named_edges(compare_temporal=compare_temporal)
        return fresh

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for descriptor in reversed(self._fds):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._fds.clear()

    def __enter__(self) -> "AbsoluteDirectoryChainLease":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()
