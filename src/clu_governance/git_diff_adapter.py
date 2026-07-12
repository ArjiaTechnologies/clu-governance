"""Read-only adapter from one bounded Git worktree edit to CLU artifacts.

Supported v0.1 mode: exactly one tracked, unstaged, UTF-8 text modification.
The adapter never stages, applies, commits, pushes, or invokes a network Git
operation. It evaluates a one-file HEAD baseline snapshot, not the full repo.
"""

from __future__ import annotations

import difflib
import errno
import ctypes
import contextvars
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import source_mutation_policy_gate as gate
from . import strict_json
from .path_chain import AbsoluteDirectoryChainLease, PathChainError
from .result_contract import ResultContractError, validate_adapter_result
from .safe_artifact_io import (
    absolute_raw_path,
    existing_components,
    is_relative_to,
    sha256_bytes,
    sha256_file,
)


RESULT_SCHEMA_NAME = "clu_governance_git_diff_adapter_result.v1"
PROVENANCE_SCHEMA_NAME = "clu_governance_git_diff_provenance.v1"
CONTRACT_VERSION = 1
SUPPORTED_CHANGE_MODE = "single_tracked_unstaged_utf8_text_modify"
SUPPORTED_GIT_REF_STORAGE_BACKEND = "files"
SOURCE_SURFACE_MODE = "single_tracked_file_baseline_snapshot"
MAX_PROPOSED_FILE_SIZE = 1024 * 1024
GIT_TIMEOUT_SECONDS = 15
MAX_GIT_STDOUT_BYTES = 4 * 1024 * 1024
MAX_GIT_STATUS_BYTES = 2 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 64 * 1024
MAX_STATUS_RECORDS = 256
MAX_INDEX_STATE_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_INDEX_STATE_RECORDS = 10000
MAX_GIT_METADATA_INVENTORY_ENTRIES = 4096
MAX_OWNED_OUTPUT_ENTRIES = 1024
MAX_LOCAL_CONFIG_BYTES = 1024 * 1024
MAX_LOCAL_CONFIG_KEYS = 4096
MAX_GIT_INDEX_BYTES = 16 * 1024 * 1024
MAX_POLICY_BYTES = 4 * 1024 * 1024
OWNERSHIP_MARKER_NAME = ".clu-git-adapter-ownership.json"
INCOMPLETE_MARKER_NAME = "INCOMPLETE.json"
ALLOWED_GIT_COMMANDS = {"rev-parse", "status", "ls-tree", "cat-file", "ls-files"}
SANDBOXED_GIT_COMMANDS = {"status", "ls-tree", "cat-file"}
MACOS_SANDBOX_EXECUTABLE = Path("/usr/bin/sandbox-exec")
FORBIDDEN_GIT_COMMANDS = {
    "fetch", "pull", "push", "clone", "checkout", "restore", "reset",
    "add", "commit", "merge", "rebase", "clean", "tag", "config",
    "update-index", "apply", "am", "submodule",
}

# Focused tests may inject a repository race immediately before revalidation.
ADAPTER_TEST_HOOK: Callable[[Path], None] | None = None
# Focused race tests may inject changes at bounded descriptor-read phases.
WORKTREE_READ_TEST_HOOK: Callable[[str, Path, int], None] | None = None
STATUS_SNAPSHOT_TEST_HOOK: Callable[[Path], None] | None = None
OUTPUT_OWNERSHIP_TEST_HOOK: Callable[[str, Any], None] | None = None
OUTPUT_PARENT_TEST_HOOK: Callable[[str, Any], None] | None = None
PROCESS_LIMIT_TEST_OBSERVER: Callable[[dict[str, Any]], None] | None = None
EXACT_SEAL_TEST_HOOK: Callable[[str, Any], None] | None = None
GIT_METADATA_TEST_HOOK: Callable[[str, Any], None] | None = None
POST_PUBLICATION_PATH_TEST_HOOK: Callable[[str, Any], None] | None = None
WORKTREE_CONTENT_READ_CALLS = 0
_ACTIVE_INTERNAL_TEMP_ROOT: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "clu_git_adapter_internal_temp_root", default=None
)


def _require_internal_temp_root() -> str:
    lease = _ACTIVE_INTERNAL_TEMP_ROOT.get()
    if lease is None:
        _raise("internal_temp_root_not_established")
    lease.revalidate()
    return str(lease.path)


class GitAdapterError(ValueError):
    """Stable fail-closed adapter blocker."""


def _raise(blocker: str) -> None:
    raise GitAdapterError(blocker)


def _controlled_git_environment() -> dict[str, str]:
    """Return a small deterministic environment; inherited GIT_* is excluded."""

    keep = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR")
    environment = {key: os.environ[key] for key in keep if key in os.environ}
    temp_root = _require_internal_temp_root()
    environment.update(
        {
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "GIT_EXTERNAL_DIFF": "",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "TMPDIR": temp_root,
            "TMP": temp_root,
            "TEMP": temp_root,
        }
    )
    return environment


def _run_bounded_process(
    command: list[str], *, cwd: Path, max_stdout: int, input_bytes: bytes | None = None
) -> tuple[int, bytes, bytes]:
    """Drain both pipes concurrently and kill the child at the runtime byte cap."""

    active_temp = _ACTIVE_INTERNAL_TEMP_ROOT.get()
    if active_temp is None:
        _raise("internal_temp_root_not_established")
    active_temp.revalidate()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=_controlled_git_environment(),
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    stdout = bytearray()
    stderr = bytearray()
    exceeded: dict[str, bool] = {"stdout": False, "stderr": False}
    lock = threading.Lock()

    def drain(stream: Any, destination: bytearray, limit: int, label: str) -> None:
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                with lock:
                    remaining = max(0, limit + 1 - len(destination))
                    destination.extend(chunk[:remaining])
                    if len(destination) > limit:
                        exceeded[label] = True
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                        return
        finally:
            stream.close()

    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(target=drain, args=(process.stdout, stdout, max_stdout, "stdout"), daemon=True),
        threading.Thread(
            target=drain,
            args=(process.stderr, stderr, MAX_GIT_STDERR_BYTES, "stderr"),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    if input_bytes is not None:
        assert process.stdin is not None
        try:
            process.stdin.write(input_bytes)
            process.stdin.close()
        except BrokenPipeError:
            pass
    try:
        returncode = process.wait(timeout=GIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        for reader in readers:
            reader.join(timeout=1)
        active_temp.revalidate()
        _raise("git_command_timeout")
    for reader in readers:
        reader.join(timeout=1)
    if any(reader.is_alive() for reader in readers):
        process.kill()
        active_temp.revalidate()
        _raise("git_process_reader_shutdown_failed")
    active_temp.revalidate()
    if PROCESS_LIMIT_TEST_OBSERVER is not None:
        PROCESS_LIMIT_TEST_OBSERVER(
            {"pid": process.pid, "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
             "stdout_exceeded": exceeded["stdout"], "stderr_exceeded": exceeded["stderr"]}
        )
    if exceeded["stdout"]:
        _raise("git_stdout_limit_exceeded")
    if exceeded["stderr"]:
        _raise("git_stderr_limit_exceeded")
    return returncode, bytes(stdout), bytes(stderr)


def _resolve_git_executable(candidate: str) -> str:
    """Resolve the real Git binary behind Apple's developer-tool shim."""

    raw = Path(candidate)
    if sys.platform == "darwin":
        xcrun = Path("/usr/bin/xcrun")
        if not xcrun.is_file() or xcrun.is_symlink():
            _raise("content_sensitive_git_sandbox_unavailable")
        returncode, stdout, stderr = _run_bounded_process(
            [str(xcrun), "--find", "git"], cwd=Path.cwd(), max_stdout=4096
        )
        if returncode != 0 or stderr:
            _raise("content_sensitive_git_sandbox_unavailable")
        try:
            resolved = Path(stdout.decode("utf-8", errors="strict").strip()).resolve(strict=True)
        except (UnicodeDecodeError, OSError):
            _raise("content_sensitive_git_sandbox_unavailable")
    else:
        try:
            resolved = raw.resolve(strict=True)
        except OSError:
            _raise("git_executable_not_found")
    if not resolved.is_absolute() or resolved.is_symlink() or not resolved.is_file():
        _raise("content_sensitive_git_sandbox_unavailable")
    return str(resolved)


def _sandbox_content_sensitive_git_command(command: list[str], git_executable: str) -> list[str]:
    """Deny network and descendant exec for the executed macOS Git boundary."""

    if sys.platform != "darwin":
        _raise("content_sensitive_git_sandbox_unavailable")
    sandbox = MACOS_SANDBOX_EXECUTABLE
    executable = Path(git_executable)
    if (
        not sandbox.is_file() or sandbox.is_symlink()
        or not executable.is_absolute() or executable.is_symlink() or not executable.is_file()
    ):
        _raise("content_sensitive_git_sandbox_unavailable")
    literal = str(executable).replace("\\", "\\\\").replace('"', '\\"')
    profile = "\n".join(
        (
            "(version 1)",
            "(allow default)",
            "(deny network*)",
            "(deny process-exec)",
            f'(allow process-exec (literal "{literal}"))',
        )
    )
    return [str(sandbox), "-p", profile, *command]


def _sha256_optional_file(path: Path) -> str | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        _raise("git_metadata_non_regular_denied")
    return sha256_file(path)


def _paths_overlap(first: Path, second: Path) -> bool:
    a = first.resolve(strict=False)
    b = second.resolve(strict=False)
    return a == b or is_relative_to(a, b) or is_relative_to(b, a)


def _validate_raw_existing_directory(path: Path, *, prefix: str) -> Path:
    raw = absolute_raw_path(path)
    if raw.is_symlink():
        _raise(f"{prefix}_path_symlink_denied")
    if any(component.is_symlink() for component in existing_components(raw)):
        _raise(f"{prefix}_parent_symlink_denied")
    if not raw.exists() or not raw.is_dir():
        _raise(f"{prefix}_directory_missing")
    return raw.resolve(strict=True)


def _validate_policy_path(path: Path) -> Path:
    raw = absolute_raw_path(path)
    if raw.is_symlink() or any(component.is_symlink() for component in existing_components(raw)):
        _raise("policy_path_symlink_denied")
    if not raw.exists() or not raw.is_file():
        _raise("policy_file_missing")
    return raw.resolve(strict=True)


def _directory_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode),
        "file_type": stat.S_IFMT(info.st_mode),
    }


def _directory_temporal_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "nlink": info.st_nlink,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


def _repository_root_mutation_snapshot(repo: Path) -> dict[str, Any]:
    info = os.stat(repo, follow_symlinks=False)
    return {
        "identity": (
            info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        ),
        "entries": sorted(os.listdir(repo)),
    }


def _open_absolute_directory_chain(path: Path) -> tuple[int, list[dict[str, Any]]]:
    """Open an absolute directory through no-follow component traversal."""

    if not path.is_absolute():
        _raise("output_parent_missing_or_invalid")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path.anchor, flags)
    proof: list[dict[str, Any]] = []
    try:
        root_info = os.fstat(descriptor)
        if not stat.S_ISDIR(root_info.st_mode):
            _raise("output_parent_missing_or_invalid")
        proof.append({
            "component": path.anchor, **_directory_identity(root_info),
            **_directory_temporal_identity(root_info),
        })
        for component in path.parts[1:]:
            if component in {"", ".", ".."} or "/" in component or "\x00" in component:
                _raise("output_parent_missing_or_invalid")
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.EMLINK}:
                    _raise("output_parent_symlink_denied")
                _raise("output_parent_missing_or_invalid")
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                _raise("output_parent_missing_or_invalid")
            proof.append({
                "component": component, **_directory_identity(info),
                **_directory_temporal_identity(info),
            })
        return descriptor, proof
    except Exception:
        os.close(descriptor)
        raise


@dataclass
class OutputParentLease:
    raw_parent: Path
    final_name: str
    fd: int
    identity: dict[str, int]
    component_proof: list[dict[str, Any]]
    closed: bool = False

    @classmethod
    def acquire(cls, raw_parent: Path, final_name: str) -> "OutputParentLease":
        descriptor, proof = _open_absolute_directory_chain(raw_parent)
        info = os.fstat(descriptor)
        lease = cls(
            raw_parent=raw_parent,
            final_name=final_name,
            fd=descriptor,
            identity=_directory_identity(info),
            component_proof=proof,
        )
        lease.revalidate("acquire")
        return lease

    def revalidate(self, phase: str) -> None:
        del phase
        if self.closed:
            _raise("output_parent_identity_changed")
        current = os.fstat(self.fd)
        if _directory_identity(current) != self.identity or not stat.S_ISDIR(current.st_mode):
            _raise("output_parent_identity_changed")
        try:
            fresh_fd, fresh_proof = _open_absolute_directory_chain(self.raw_parent)
        except GitAdapterError:
            _raise("output_parent_identity_changed")
        try:
            static_keys = ("component", "device", "inode", "mode", "file_type")
            if [tuple(item[key] for key in static_keys) for item in fresh_proof] != [
                tuple(item[key] for key in static_keys) for item in self.component_proof
            ]:
                _raise("output_parent_identity_changed")
            fresh = os.fstat(fresh_fd)
            if _directory_identity(fresh) != self.identity:
                _raise("output_parent_identity_changed")
        finally:
            os.close(fresh_fd)

    def refresh_after_owned_parent_mutation(self) -> None:
        """Refresh only the immediate parent's temporal token after our mkdir/rename."""

        if self.closed:
            _raise("output_parent_identity_changed")
        try:
            fresh_fd, fresh_proof = _open_absolute_directory_chain(self.raw_parent)
        except GitAdapterError:
            _raise("output_parent_identity_changed")
        try:
            if len(fresh_proof) != len(self.component_proof):
                _raise("output_parent_identity_changed")
            static_keys = {"component", "device", "inode", "mode", "file_type"}
            for old, new in zip(self.component_proof[:-1], fresh_proof[:-1]):
                if {key: old[key] for key in static_keys} != {
                    key: new[key] for key in static_keys
                }:
                    _raise("output_parent_identity_changed")
            if {key: self.component_proof[-1][key] for key in static_keys} != {
                key: fresh_proof[-1][key] for key in static_keys
            }:
                _raise("output_parent_identity_changed")
            self.component_proof = fresh_proof
        finally:
            os.close(fresh_fd)

    def lstat_name(self, name: str) -> os.stat_result | None:
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            _raise("adapter_output_name_invalid")
        try:
            return os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def final_absent(self) -> bool:
        return self.lstat_name(self.final_name) is None

    def close(self) -> None:
        if not self.closed:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.closed = True


@dataclass
class InternalTempRootLease:
    """Random adapter-owned scratch root created under the bound output parent."""

    parent: OutputParentLease
    name: str
    path: Path
    fd: int
    device: int
    inode: int
    token: contextvars.Token[Any | None] | None
    closed: bool = False
    finalized: bool = False

    @classmethod
    def create(
        cls,
        parent: OutputParentLease,
        *,
        repo: Path,
        protected_sources: tuple[Path, ...],
        final_output: Path,
    ) -> "InternalTempRootLease":
        parent.revalidate("before_internal_temp_root")
        name = f".clu-git-adapt-internal-{uuid.uuid4().hex}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent.fd)
            flags = (
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(name, flags, dir_fd=parent.fd)
        except OSError:
            _raise("internal_temp_root_creation_failed")
        info = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        path = parent.raw_parent / name
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
            or stat.S_IMODE(info.st_mode) & 0o077
            or _paths_overlap(path, repo)
            or _paths_overlap(path, repo / ".git")
            or any(_paths_overlap(path, protected) for protected in protected_sources)
            or _paths_overlap(path, final_output)
        ):
            os.close(descriptor)
            _raise("internal_temp_root_overlap_or_type_denied")
        lease = cls(parent, name, path, descriptor, info.st_dev, info.st_ino, None)
        parent.refresh_after_owned_parent_mutation()
        lease.token = _ACTIVE_INTERNAL_TEMP_ROOT.set(lease)
        return lease

    def revalidate(self) -> None:
        self.parent.revalidate("internal_temp_root")
        try:
            named = os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False)
            current = os.fstat(self.fd)
        except OSError:
            _raise("internal_temp_cleanup_ownership_lost")
        if (
            not stat.S_ISDIR(named.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or (named.st_dev, named.st_ino) != (self.device, self.inode)
            or (current.st_dev, current.st_ino) != (self.device, self.inode)
        ):
            _raise("internal_temp_cleanup_ownership_lost")

    def workspace(
        self, prefix: str, *, allowed_dirs: set[str], allowed_files: set[str]
    ) -> "InternalTempWorkspace":
        self.revalidate()
        name = f"{prefix}{uuid.uuid4().hex}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=self.fd)
            flags = (
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(name, flags, dir_fd=self.fd)
            named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            opened = os.fstat(descriptor)
        except OSError:
            _raise("internal_temp_workspace_creation_failed")
        if (
            not stat.S_ISDIR(named.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            os.close(descriptor)
            _raise("internal_temp_cleanup_ownership_lost")
        return InternalTempWorkspace(
            root=self, name=name, path=self.path / name, fd=descriptor,
            device=opened.st_dev, inode=opened.st_ino,
            allowed_dirs=set(allowed_dirs) | {""}, allowed_files=set(allowed_files),
        )

    def finalize(self) -> None:
        if self.finalized:
            return
        self.revalidate()
        if os.listdir(self.fd):
            _raise("internal_temp_cleanup_ownership_lost")
        quarantine = f".clu-remove-{uuid.uuid4().hex}"
        _rename_quarantine_no_replace_at(self.parent.fd, self.name, quarantine)
        moved = os.stat(quarantine, dir_fd=self.parent.fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(moved.st_mode)
            or (moved.st_dev, moved.st_ino) != (self.device, self.inode)
        ):
            _raise("internal_temp_cleanup_ownership_lost")
        os.rmdir(quarantine, dir_fd=self.parent.fd)
        self.parent.refresh_after_owned_parent_mutation()
        if self.token is not None:
            _ACTIVE_INTERNAL_TEMP_ROOT.reset(self.token)
            self.token = None
        os.close(self.fd)
        self.finalized = True
        self.closed = True

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.token is not None:
            _ACTIVE_INTERNAL_TEMP_ROOT.reset(self.token)
            self.token = None
        try:
            os.close(self.fd)
        except OSError:
            pass


@dataclass
class InternalTempWorkspace:
    """Descriptor-owned scratch child with exact, nonrecursive cleanup."""

    root: InternalTempRootLease
    name: str
    path: Path
    fd: int
    device: int
    inode: int
    allowed_dirs: set[str]
    allowed_files: set[str]
    closed: bool = False
    expected_records: dict[str, tuple[int, ...]] = field(default_factory=dict)

    @staticmethod
    def _entry_token(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        )

    def revalidate(self) -> None:
        self.root.revalidate()
        try:
            named = os.stat(self.name, dir_fd=self.root.fd, follow_symlinks=False)
            opened = os.fstat(self.fd)
        except OSError:
            _raise("internal_temp_cleanup_ownership_lost")
        if (
            not stat.S_ISDIR(named.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or (named.st_dev, named.st_ino) != (self.device, self.inode)
            or (opened.st_dev, opened.st_ino) != (self.device, self.inode)
        ):
            _raise("internal_temp_cleanup_ownership_lost")

    @staticmethod
    def _parts(relative: str) -> tuple[str, ...]:
        parts = tuple(relative.split("/"))
        if not parts or any(part in {"", ".", ".."} or "\x00" in part for part in parts):
            _raise("internal_temp_relative_path_invalid")
        return parts

    def _open_parent(self, relative: str) -> tuple[int, str]:
        parts = self._parts(relative)
        descriptor = os.dup(self.fd)
        flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            built: list[str] = []
            for component in parts[:-1]:
                built.append(component)
                current = "/".join(built)
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                expected = self.expected_records.get(current)
                observed = self._entry_token(os.fstat(descriptor))
                if expected is None or expected[:3] != observed[:3]:
                    _raise("internal_temp_cleanup_ownership_lost")
            return descriptor, parts[-1]
        except Exception:
            os.close(descriptor)
            raise

    def mkdir(self, relative: str) -> None:
        if relative not in self.allowed_dirs:
            _raise("internal_temp_relative_path_invalid")
        parts = self._parts(relative)
        descriptor = os.dup(self.fd)
        flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            built: list[str] = []
            for component in parts:
                built.append(component)
                current = "/".join(built)
                if current not in self.allowed_dirs:
                    _raise("internal_temp_relative_path_invalid")
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    created = False
                    if current not in self.expected_records:
                        _raise("internal_temp_cleanup_ownership_lost")
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                observed = self._entry_token(os.fstat(descriptor))
                if not created and self.expected_records[current][:3] != observed[:3]:
                    _raise("internal_temp_cleanup_ownership_lost")
                self.expected_records[current] = observed
        finally:
            os.close(descriptor)
        self._refresh_directory_records()

    def write_bytes(self, relative: str, data: bytes, *, mode: int = 0o600) -> None:
        if relative not in self.allowed_files:
            _raise("internal_temp_relative_path_invalid")
        parent, name = self._open_parent(relative)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=parent,
            )
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
            self.expected_records[relative] = self._entry_token(os.fstat(descriptor))
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
        self._refresh_directory_records()

    def write_text(self, relative: str, text: str, *, encoding: str = "utf-8") -> None:
        self.write_bytes(relative, text.encode(encoding))

    def _refresh_directory_records(self) -> None:
        for relative in sorted(self.allowed_dirs - {""}, key=lambda value: value.count("/")):
            if relative not in self.expected_records:
                continue
            parts = self._parts(relative)
            descriptor = os.dup(self.fd)
            flags = (
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                for component in parts:
                    child = os.open(component, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
                observed = self._entry_token(os.fstat(descriptor))
                if self.expected_records[relative][:3] != observed[:3]:
                    _raise("internal_temp_cleanup_ownership_lost")
                self.expected_records[relative] = observed
            finally:
                os.close(descriptor)

    def _inventory(self) -> tuple[set[str], set[str], dict[str, tuple[int, ...]]]:
        directories = {""}
        files: set[str] = set()
        records: dict[str, tuple[int, ...]] = {}

        def visit(directory_fd: int, relative: str) -> None:
            for name in sorted(os.listdir(directory_fd)):
                child_rel = f"{relative}/{name}" if relative else name
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    _raise("internal_temp_cleanup_ownership_lost")
                if stat.S_ISDIR(info.st_mode):
                    flags = (
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                    )
                    child = os.open(name, flags, dir_fd=directory_fd)
                    directories.add(child_rel)
                    records[child_rel] = self._entry_token(info)
                    try:
                        visit(child, child_rel)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    files.add(child_rel)
                    records[child_rel] = self._entry_token(info)
                else:
                    _raise("internal_temp_cleanup_ownership_lost")
        visit(self.fd, "")
        return directories, files, records

    def cleanup(self) -> None:
        if self.closed:
            return
        self.revalidate()
        directories, files, records = self._inventory()
        if directories != self.allowed_dirs or files != self.allowed_files:
            _raise("internal_temp_cleanup_ownership_lost")
        if records != self.expected_records:
            _raise("internal_temp_cleanup_ownership_lost")

        def remove_dir(directory_fd: int, relative: str) -> None:
            for name in sorted(os.listdir(directory_fd)):
                child_rel = f"{relative}/{name}" if relative else name
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                observed = (
                    info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                )
                if records.get(child_rel) != observed:
                    _raise("internal_temp_cleanup_ownership_lost")
                if stat.S_ISDIR(info.st_mode):
                    flags = (
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                    )
                    child = os.open(name, flags, dir_fd=directory_fd)
                    try:
                        remove_dir(child, child_rel)
                    finally:
                        os.close(child)
                    quarantine = f".clu-remove-{uuid.uuid4().hex}"
                    _rename_quarantine_no_replace_at(directory_fd, name, quarantine)
                    moved = os.stat(quarantine, dir_fd=directory_fd, follow_symlinks=False)
                    moved_token = self._entry_token(moved)
                    expected_dir = records.get(child_rel)
                    if expected_dir is None or expected_dir[:3] != moved_token[:3]:
                        _raise("internal_temp_cleanup_ownership_lost")
                    os.rmdir(quarantine, dir_fd=directory_fd)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    quarantine = f".clu-remove-{uuid.uuid4().hex}"
                    _rename_quarantine_no_replace_at(directory_fd, name, quarantine)
                    moved = os.stat(quarantine, dir_fd=directory_fd, follow_symlinks=False)
                    moved_token = self._entry_token(moved)
                    expected_file = records.get(child_rel)
                    if expected_file is None or expected_file[:6] != moved_token[:6]:
                        _raise("internal_temp_cleanup_ownership_lost")
                    os.unlink(quarantine, dir_fd=directory_fd)
                else:
                    _raise("internal_temp_cleanup_ownership_lost")
        remove_dir(self.fd, "")
        os.close(self.fd)
        quarantine = f".clu-remove-{uuid.uuid4().hex}"
        _rename_quarantine_no_replace_at(self.root.fd, self.name, quarantine)
        moved = os.stat(quarantine, dir_fd=self.root.fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(moved.st_mode)
            or (moved.st_dev, moved.st_ino) != (self.device, self.inode)
        ):
            _raise("internal_temp_cleanup_ownership_lost")
        os.rmdir(quarantine, dir_fd=self.root.fd)
        self.closed = True

    def __enter__(self) -> "InternalTempWorkspace":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        try:
            self.cleanup()
        except GitAdapterError:
            if _type is None:
                raise
            # Preserve the primary governance/snapshot blocker. The scratch
            # root remains owned and is reported by final disposition.


def _validate_output_path(
    output: Path, repo: Path, protected_sources: tuple[Path, ...]
) -> tuple[Path, OutputParentLease]:
    raw = absolute_raw_path(output)
    if raw == Path(raw.anchor) or raw.resolve(strict=False) in {Path.home().resolve(), Path.cwd().resolve()}:
        _raise("output_special_directory_denied")
    if raw.exists() or raw.is_symlink():
        _raise("output_path_must_not_exist")
    if any(component.is_symlink() for component in existing_components(raw.parent)):
        _raise("output_parent_symlink_denied")
    if not raw.parent.exists() or not raw.parent.is_dir() or raw.parent.is_symlink():
        _raise("output_parent_missing_or_invalid")
    final = raw.resolve(strict=False)
    if _paths_overlap(final, repo):
        _raise("output_repository_overlap_denied")
    if any(_paths_overlap(final, protected) for protected in protected_sources):
        _raise("output_candidate_source_overlap_denied")
    lease = OutputParentLease.acquire(raw.parent, raw.name)
    if not lease.final_absent():
        lease.close()
        _raise("output_path_must_not_exist")
    return raw, lease


def _normalize_selected_path(path: str) -> str:
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        _raise("git_path_control_character_denied")
    if "\\" in path:
        _raise("git_path_backslash_denied")
    try:
        normalized = gate.normalize_relative_path(path)
    except gate.PolicyGateError as exc:
        _raise(str(exc))
    if normalized != path or normalized == ".git" or normalized.startswith(".git/"):
        _raise("git_path_not_normalized_or_metadata_denied")
    return normalized


def parse_porcelain_v2_z(data: bytes) -> list[dict[str, str]]:
    """Parse bounded porcelain-v2 NUL records without selecting a first path."""

    if len(data) > MAX_GIT_STATUS_BYTES:
        _raise("git_status_output_limit_exceeded")
    records = data.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    if len(records) > MAX_STATUS_RECORDS:
        _raise("git_status_record_limit_exceeded")
    parsed: list[dict[str, str]] = []
    for record in records:
        if not record:
            continue
        kind = record[:1]
        if kind != b"1":
            if kind == b"?":
                _raise("untracked_files_unsupported")
            if kind == b"!":
                _raise("ignored_untracked_files_unsupported")
            label = {
                b"2": "rename_or_copy",
                b"u": "conflict",
                b"?": "untracked",
                b"!": "ignored",
                b"#": "header",
            }.get(kind, "unknown")
            _raise(f"unsupported_porcelain_record:{label}")
        fields = record.split(b" ", 8)
        if len(fields) != 9:
            _raise("porcelain_v2_record_malformed")
        try:
            xy = fields[1].decode("ascii")
            sub = fields[2].decode("ascii")
            modes = [field.decode("ascii") for field in fields[3:6]]
            oids = [field.decode("ascii") for field in fields[6:8]]
            path = fields[8].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            _raise("git_path_not_utf8")
        parsed.append(
            {
                "xy": xy,
                "sub": sub,
                "head_mode": modes[0],
                "index_mode": modes[1],
                "worktree_mode": modes[2],
                "head_oid": oids[0],
                "index_oid": oids[1],
                "path": _normalize_selected_path(path),
            }
        )
    return parsed


def select_supported_status_record(records: list[dict[str, str]]) -> dict[str, str]:
    """Require the one and only supported v0.1 porcelain state."""

    if len(records) != 1:
        _raise("exactly_one_changed_path_required")
    record = records[0]
    if record["xy"] != ".M":
        if record["xy"][0] != ".":
            _raise("staged_changes_unsupported")
        _raise("working_tree_change_mode_unsupported")
    if record["sub"] != "N...":
        _raise("submodule_change_unsupported")
    return record


def _supported_record_from_snapshot(snapshot: dict[str, Any]) -> dict[str, str]:
    raw = bytes.fromhex(snapshot["porcelain_v2_status_bytes_hex"])
    return select_supported_status_record(parse_porcelain_v2_z(raw))


def _acceptance_inventory(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        key: value for key, value in _proof_inventory(snapshot).items()
        if not key.startswith("worktree:")
    }


def _git_metadata_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "file_type": stat.S_IFMT(info.st_mode),
        "mode": stat.S_IMODE(info.st_mode),
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "link_count": info.st_nlink,
    }


def _git_metadata_directory_flags() -> int:
    if (
        not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
    ):
        _raise("git_metadata_descriptor_boundary_unsupported")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _read_git_metadata_file_at(
    parent_fd: int, name: str, *, limit: int
) -> tuple[bytes, dict[str, int]]:
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd
        )
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            _raise("git_metadata_symlink_denied")
        _raise("git_metadata_open_failed")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _raise("git_metadata_non_regular_denied")
        if before.st_nlink != 1:
            _raise("git_metadata_hardlink_denied")
        if before.st_size < 0 or before.st_size > limit:
            _raise("git_metadata_file_size_limit_exceeded")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(data) > limit or len(data) != after.st_size:
            _raise("git_metadata_file_size_limit_exceeded")
        if _git_metadata_identity(before) != _git_metadata_identity(after):
            _raise("git_metadata_identity_changed")
        return data, _git_metadata_identity(before)
    finally:
        os.close(descriptor)


@dataclass
class GitMetadataLease:
    """Descriptor-bound proof that Git metadata remains local and unchanged."""

    repo: Path
    git_dir: Path
    repo_fd: int
    git_fd: int
    root_fds: dict[str, int]
    repo_identity: dict[str, int]
    git_identity: dict[str, int]
    root_identities: dict[str, dict[str, int]]
    initial_inventory: dict[str, dict[str, Any]]
    closed: bool = False

    REQUIRED_ROOTS = ("objects", "objects/pack", "objects/info", "refs", "info")
    DIRECT_CONTROL_FILES = (
        "HEAD", "index", "config", "config.worktree", "packed-refs", "shallow"
    )
    REQUIRED_CONTROL_FILES = ("HEAD", "index", "config")
    FORBIDDEN_DIRECT_FILES = ("commondir", "gitdir")

    @staticmethod
    def _reject_reftable_at(git_fd: int) -> None:
        """Fail closed on every object type at the unsupported backend path.

        The files backend cannot be inferred from the mere presence of
        ``refs``. Reftable may coexist with that directory, so the backend
        path is forbidden before the first repository-aware Git command and
        at every descriptor-bound lease revalidation.
        """

        try:
            os.stat("reftable", dir_fd=git_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            _raise("git_ref_storage_backend_unsupported")
        _raise("git_ref_storage_backend_unsupported")

    @classmethod
    def acquire(cls, repo: Path, git_dir: Path) -> "GitMetadataLease":
        if git_dir != repo / ".git":
            _raise("non_direct_git_metadata_unsupported")
        flags = _git_metadata_directory_flags()
        repo_fd = os.open(repo, flags)
        git_fd: int | None = None
        root_fds: dict[str, int] = {}
        try:
            repo_info = os.fstat(repo_fd)
            try:
                git_fd = os.open(".git", flags, dir_fd=repo_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.EMLINK}:
                    _raise("git_metadata_root_symlink_denied")
                _raise("git_metadata_root_invalid")
            git_info = os.fstat(git_fd)
            if git_info.st_dev != repo_info.st_dev:
                _raise("git_metadata_cross_device_denied")
            cls._reject_reftable_at(git_fd)
            for forbidden in cls.FORBIDDEN_DIRECT_FILES:
                try:
                    os.stat(forbidden, dir_fd=git_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                _raise("non_direct_git_metadata_unsupported")
            for relative in cls.REQUIRED_ROOTS:
                current = os.dup(git_fd)
                try:
                    for component in relative.split("/"):
                        try:
                            child = os.open(component, flags, dir_fd=current)
                        except OSError as exc:
                            if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.EMLINK}:
                                root_blockers = {
                                    "objects": "git_object_root_symlink_denied",
                                    "objects/pack": "git_object_pack_root_symlink_denied",
                                    "objects/info": "git_object_info_root_symlink_denied",
                                    "refs": "git_refs_root_symlink_denied",
                                    "info": "git_info_root_symlink_denied",
                                }
                                _raise(root_blockers[relative])
                            _raise("git_metadata_required_root_missing")
                        os.close(current)
                        current = child
                    root_fds[relative] = current
                except Exception:
                    os.close(current)
                    raise
            lease = cls(
                repo=repo,
                git_dir=git_dir,
                repo_fd=repo_fd,
                git_fd=git_fd,
                root_fds=root_fds,
                repo_identity=_git_metadata_identity(repo_info),
                git_identity=_git_metadata_identity(git_info),
                root_identities={
                    name: _git_metadata_identity(os.fstat(descriptor))
                    for name, descriptor in root_fds.items()
                },
                initial_inventory={},
            )
            if any(
                identity["device"] != lease.git_identity["device"]
                for identity in lease.root_identities.values()
            ):
                _raise("git_metadata_cross_device_denied")
            lease._reject_external_object_routes()
            lease.initial_inventory = lease._inventory()
            for required in cls.REQUIRED_CONTROL_FILES:
                if required not in lease.initial_inventory:
                    _raise("git_metadata_required_control_missing")
            lease.revalidate("acquire")
            return lease
        except Exception:
            for descriptor in root_fds.values():
                os.close(descriptor)
            if git_fd is not None:
                os.close(git_fd)
            os.close(repo_fd)
            raise

    def _stat_relative(self, relative: str) -> os.stat_result | None:
        components = relative.split("/")
        current = os.dup(self.git_fd)
        try:
            for component in components[:-1]:
                child = os.open(component, _git_metadata_directory_flags(), dir_fd=current)
                os.close(current)
                current = child
            try:
                return os.stat(components[-1], dir_fd=current, follow_symlinks=False)
            except FileNotFoundError:
                return None
        finally:
            os.close(current)

    def _reject_external_object_routes(self) -> None:
        forbidden = {
            "objects/info/alternates": "external_object_database_unsupported",
            "objects/info/http-alternates": "external_object_database_unsupported",
            "info/grafts": "git_grafts_unsupported",
            "info/attributes": "git_info_attributes_unsupported",
            "refs/replace": "git_replace_refs_unsupported",
        }
        for relative, blocker in forbidden.items():
            try:
                observed = self._stat_relative(relative)
            except OSError:
                _raise("git_metadata_symlink_denied")
            if observed is not None:
                _raise(blocker)

    def _scan_tree(
        self,
        descriptor: int,
        relative_root: str,
        entries: dict[str, dict[str, Any]],
        counter: list[int],
    ) -> None:
        try:
            names = sorted(os.listdir(descriptor))
        except OSError:
            _raise("git_metadata_inventory_failed")
        for name in names:
            counter[0] += 1
            if counter[0] > MAX_GIT_METADATA_INVENTORY_ENTRIES:
                _raise("git_metadata_inventory_limit_exceeded")
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                _raise("git_metadata_entry_name_invalid")
            try:
                observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError:
                _raise("git_metadata_inventory_failed")
            relative = f"{relative_root}/{name}"
            if stat.S_ISLNK(observed.st_mode):
                _raise("git_metadata_symlink_denied")
            identity = _git_metadata_identity(observed)
            if identity["device"] != self.git_identity["device"]:
                _raise("git_metadata_cross_device_denied")
            if stat.S_ISDIR(observed.st_mode):
                child = os.open(name, _git_metadata_directory_flags(), dir_fd=descriptor)
                try:
                    entries[relative] = {"kind": "directory", **identity}
                    self._scan_tree(child, relative, entries, counter)
                finally:
                    os.close(child)
            elif stat.S_ISREG(observed.st_mode):
                if observed.st_nlink != 1:
                    _raise("git_metadata_hardlink_denied")
                entry: dict[str, Any] = {"kind": "file", **identity}
                if not relative.startswith("objects/"):
                    data, read_identity = _read_git_metadata_file_at(
                        descriptor, name, limit=MAX_GIT_INDEX_BYTES
                    )
                    if read_identity != identity:
                        _raise("git_metadata_identity_changed")
                    entry["sha256"] = sha256_bytes(data)
                entries[relative] = entry
            else:
                _raise("git_metadata_non_regular_denied")

    def _inventory(self) -> dict[str, dict[str, Any]]:
        if self.closed:
            _raise("git_metadata_identity_changed")
        self._reject_reftable_at(self.git_fd)
        entries: dict[str, dict[str, Any]] = {}
        counter = [0]
        try:
            direct_names = set(os.listdir(self.git_fd))
        except OSError:
            _raise("git_metadata_inventory_failed")
        control_names = set(self.DIRECT_CONTROL_FILES) | {
            name for name in direct_names if name.endswith(".lock")
        }
        for name in sorted(control_names):
            try:
                observed = os.stat(name, dir_fd=self.git_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(observed.st_mode):
                _raise("git_metadata_symlink_denied")
            if not stat.S_ISREG(observed.st_mode):
                _raise("git_metadata_non_regular_denied")
            data, identity = _read_git_metadata_file_at(
                self.git_fd, name, limit=MAX_GIT_INDEX_BYTES
            )
            entries[name] = {"kind": "file", **identity, "sha256": sha256_bytes(data)}
            counter[0] += 1
        for root in ("objects", "refs", "info"):
            descriptor = self.root_fds[root]
            entries[root] = {
                "kind": "directory", **_git_metadata_identity(os.fstat(descriptor))
            }
            self._scan_tree(descriptor, root, entries, counter)
        packed_refs = entries.get("packed-refs")
        if packed_refs is not None:
            data, _identity = _read_git_metadata_file_at(
                self.git_fd, "packed-refs", limit=MAX_GIT_INDEX_BYTES
            )
            for line in data.splitlines():
                if line.startswith((b"#", b"^")) or b" " not in line:
                    continue
                if line.split(b" ", 1)[1].startswith(b"refs/replace/"):
                    _raise("git_replace_refs_unsupported")
        return entries

    def revalidate(self, phase: str) -> None:
        del phase
        if self.closed:
            _raise("git_metadata_identity_changed")
        self._reject_reftable_at(self.git_fd)
        if _git_metadata_identity(os.fstat(self.repo_fd)) != self.repo_identity:
            _raise("git_metadata_identity_changed")
        if _git_metadata_identity(os.fstat(self.git_fd)) != self.git_identity:
            _raise("git_metadata_identity_changed")
        try:
            current_git = os.stat(".git", dir_fd=self.repo_fd, follow_symlinks=False)
        except OSError:
            _raise("git_metadata_identity_changed")
        if stat.S_ISLNK(current_git.st_mode) or _git_metadata_identity(current_git) != self.git_identity:
            _raise("git_metadata_identity_changed")
        for name, descriptor in self.root_fds.items():
            if _git_metadata_identity(os.fstat(descriptor)) != self.root_identities[name]:
                _raise("git_metadata_identity_changed")
            try:
                fresh = self._stat_relative(name)
            except OSError:
                _raise("git_metadata_identity_changed")
            if fresh is None or stat.S_ISLNK(fresh.st_mode):
                _raise("git_metadata_identity_changed")
            if _git_metadata_identity(fresh) != self.root_identities[name]:
                _raise("git_metadata_identity_changed")
        self._reject_external_object_routes()
        current = self._inventory()
        if self.initial_inventory and current != self.initial_inventory:
            _raise("git_metadata_identity_changed")

    def inventory(self) -> dict[str, dict[str, Any]]:
        self.revalidate("inventory")
        return {key: dict(value) for key, value in self.initial_inventory.items()}

    def read_control(self, name: str, *, limit: int) -> tuple[bytes, dict[str, Any]]:
        if name not in self.DIRECT_CONTROL_FILES:
            _raise("git_metadata_control_name_denied")
        expected = self.initial_inventory.get(name)
        if expected is None:
            if name in self.REQUIRED_CONTROL_FILES:
                _raise("git_metadata_required_control_missing")
            return b"", {"present": False}
        data, identity = _read_git_metadata_file_at(self.git_fd, name, limit=limit)
        observed = {"kind": "file", **identity, "sha256": sha256_bytes(data)}
        if observed != expected:
            _raise("git_metadata_identity_changed")
        return data, {"present": True, **identity, "sha256": sha256_bytes(data)}

    def read_info_file(self, name: str, *, limit: int) -> tuple[bytes, dict[str, Any]]:
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            _raise("git_metadata_control_name_denied")
        expected = self.initial_inventory.get(f"info/{name}")
        if expected is None:
            return b"", {"present": False}
        if expected.get("kind") != "file":
            _raise("git_metadata_non_regular_denied")
        data, identity = _read_git_metadata_file_at(
            self.root_fds["info"], name, limit=limit
        )
        observed = {"kind": "file", **identity, "sha256": sha256_bytes(data)}
        if observed != expected:
            _raise("git_metadata_identity_changed")
        return data, {"present": True, **identity, "sha256": sha256_bytes(data)}

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        # Publication may already have completed before final descriptor
        # release. Cleanup is idempotent and non-throwing so a close error
        # cannot replace the prepared result after the final rename.
        for descriptor in (*self.root_fds.values(), self.git_fd, self.repo_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


@dataclass
class GitRunner:
    executable: str
    repo: Path
    commands: list[list[str]]
    last_head_oid: str | None = None
    last_object_format: str | None = None
    sandboxed_content_sensitive_commands: int = 0
    metadata_lease: GitMetadataLease | None = None
    internal_temp: InternalTempRootLease | None = None

    def _run_status_in_sanitized_view(
        self, arguments: list[str], *, max_stdout: int
    ) -> tuple[int, bytes, bytes]:
        """Run status against a config-free metadata view of the same worktree.

        Repository-local configuration is deliberately not reachable from this
        Git child.  The copied index and detached HEAD bind the status read to
        the state being sampled, while the original object database is exposed
        read-only through Git's alternate-object lookup.  Consequently a
        transient filter configuration cannot become an executable surface.
        """

        if self.last_head_oid is None or self.last_object_format not in {"sha1", "sha256"}:
            _raise("git_status_sanitized_view_state_missing")
        if self.metadata_lease is None:
            _raise("git_metadata_descriptor_boundary_missing")
        git_dir = self.repo / ".git"
        index_bytes, index_identity = self.metadata_lease.read_control(
            "index", limit=MAX_GIT_INDEX_BYTES
        )
        if not index_identity.get("present"):
            _raise("git_index_missing")
        repo_text = str(self.repo)
        objects_text = str(git_dir / "objects")
        if any(ord(char) < 32 or ord(char) == 127 for char in repo_text + objects_text):
            _raise("repository_path_control_character_denied")
        if self.internal_temp is None:
            _raise("internal_temp_root_not_established")
        exclude_bytes, exclude_identity = self.metadata_lease.read_info_file(
            "exclude", limit=MAX_LOCAL_CONFIG_BYTES
        )
        allowed_dirs = {"", "objects", "objects/info", "refs", "refs/heads", "info"}
        allowed_files = {"HEAD", "index", "config", "objects/info/alternates"}
        if exclude_identity.get("present"):
            allowed_files.add("info/exclude")
        with self.internal_temp.workspace(
            "clu-git-status-view-", allowed_dirs=allowed_dirs, allowed_files=allowed_files
        ) as workspace:
            shadow = workspace.path
            workspace.mkdir("objects/info")
            workspace.mkdir("refs/heads")
            workspace.mkdir("info")
            workspace.write_text("HEAD", self.last_head_oid + "\n", encoding="ascii")
            workspace.write_bytes("index", index_bytes)
            config_lines = [
                "[core]",
                "\trepositoryformatversion = " + ("1" if self.last_object_format == "sha256" else "0"),
                "\tbare = false",
                # The adapter contract is stricter than repositories that
                # choose to ignore executable-bit changes. Force mode
                # sensitivity so a second mode-only path cannot be hidden.
                "\tfilemode = true",
            ]
            if self.last_object_format == "sha256":
                config_lines.extend(["[extensions]", "\tobjectFormat = sha256"])
            workspace.write_text("config", "\n".join(config_lines) + "\n", encoding="ascii")
            workspace.write_text("objects/info/alternates", objects_text + "\n")
            if exclude_identity.get("present"):
                workspace.write_bytes("info/exclude", exclude_bytes)
            command = [
                self.executable,
                f"--git-dir={shadow}",
                f"--work-tree={self.repo}",
                "--no-optional-locks",
                "-c", "core.fsmonitor=false",
                "-c", "diff.external=",
                "-c", "maintenance.auto=false",
                "-c", "pager.status=false",
                *arguments,
            ]
            self.commands.append(
                ["status-sanitized-local-config-view", *arguments[1:]]
            )
            command = _sandbox_content_sensitive_git_command(command, self.executable)
            self.sandboxed_content_sensitive_commands += 1
            workspace.revalidate()
            process_result = _run_bounded_process(command, cwd=self.repo, max_stdout=max_stdout)
            workspace.revalidate()
            return process_result

    def _run_unchecked(
        self,
        arguments: list[str],
        *,
        input_bytes: bytes | None = None,
        max_stdout: int = MAX_GIT_STDOUT_BYTES,
    ) -> bytes:
        if not arguments or arguments[0] in FORBIDDEN_GIT_COMMANDS or arguments[0] not in ALLOWED_GIT_COMMANDS:
            _raise("git_command_not_allowlisted")
        if arguments[0] == "ls-files" and arguments != [
            "ls-files", "-v", "--stage", "--sparse", "--full-name", "--no-abbrev", "-z"
        ]:
            _raise("git_ls_files_arguments_not_allowlisted")
        if arguments[0] == "status":
            returncode, stdout, stderr = self._run_status_in_sanitized_view(
                arguments, max_stdout=max_stdout
            )
            if stderr:
                _raise("git_status_diagnostic_denied")
            if returncode != 0:
                _raise("git_command_failed:status")
            return stdout
        command = [
            self.executable,
            "--no-optional-locks",
            "-c", "core.fsmonitor=false",
            "-c", "diff.external=",
            "-c", "maintenance.auto=false",
            "-c", "pager.status=false",
            *arguments,
        ]
        self.commands.append(command[1:])
        if arguments[0] in SANDBOXED_GIT_COMMANDS:
            command = _sandbox_content_sensitive_git_command(command, self.executable)
            self.sandboxed_content_sensitive_commands += 1
        returncode, stdout, stderr = _run_bounded_process(
            command, cwd=self.repo, max_stdout=max_stdout, input_bytes=input_bytes
        )
        if returncode != 0:
            if arguments[0] == "cat-file":
                _raise("git_object_missing_or_lazy_fetch_denied")
            detail = stderr.decode("utf-8", errors="replace").strip().replace("\n", " ")[:200]
            _raise(f"git_command_failed:{arguments[0]}:{detail or returncode}")
        if arguments == ["rev-parse", "HEAD"]:
            self.last_head_oid = stdout.decode("ascii", errors="strict").strip()
        elif arguments == ["rev-parse", "--show-object-format"]:
            self.last_object_format = stdout.decode("ascii", errors="strict").strip()
        return stdout

    def run(
        self,
        arguments: list[str],
        *,
        input_bytes: bytes | None = None,
        max_stdout: int = MAX_GIT_STDOUT_BYTES,
    ) -> bytes:
        command_name = arguments[0] if arguments else "missing"
        lease = self.metadata_lease
        if lease is not None:
            lease.revalidate(f"before:{command_name}")
            if GIT_METADATA_TEST_HOOK is not None:
                GIT_METADATA_TEST_HOOK(f"after_pre:{command_name}", lease)
        try:
            return self._run_unchecked(
                arguments, input_bytes=input_bytes, max_stdout=max_stdout
            )
        finally:
            if lease is not None:
                if GIT_METADATA_TEST_HOOK is not None:
                    GIT_METADATA_TEST_HOOK(f"before_post:{command_name}", lease)
                lease.revalidate(f"after:{command_name}")


def _git_version(executable: str, metadata_lease: GitMetadataLease | None = None) -> str:
    if metadata_lease is not None:
        metadata_lease.revalidate("before:git-version")
    try:
        returncode, stdout, _stderr = _run_bounded_process(
            [executable, "--version"], cwd=Path.cwd(), max_stdout=4096
        )
    finally:
        if metadata_lease is not None:
            metadata_lease.revalidate("after:git-version")
    if returncode != 0:
        _raise("git_version_failed")
    return stdout.decode("utf-8", errors="strict").strip()


def _one_line(runner: GitRunner, args: list[str]) -> str:
    value = runner.run(args).decode("utf-8", errors="strict").strip()
    if not value or "\n" in value or "\r" in value:
        _raise(f"git_{args[0]}_unexpected_output")
    return value


def _parse_ls_tree(raw: bytes, expected_path: str) -> tuple[str, str, str]:
    if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
        _raise("ls_tree_record_count_invalid")
    record = raw[:-1]
    try:
        metadata, path_bytes = record.split(b"\t", 1)
        mode_b, type_b, oid_b = metadata.split(b" ", 2)
        path = path_bytes.decode("utf-8", errors="strict")
        mode, object_type, oid = mode_b.decode(), type_b.decode(), oid_b.decode()
    except (ValueError, UnicodeDecodeError):
        _raise("ls_tree_record_malformed")
    if path != expected_path:
        _raise("ls_tree_path_mismatch")
    if object_type != "blob":
        _raise("selected_path_not_blob")
    if mode == "120000":
        _raise("symlink_change_unsupported")
    if mode == "160000":
        _raise("submodule_change_unsupported")
    if mode not in {"100644", "100755"}:
        _raise("git_file_mode_unsupported")
    return mode, object_type, oid


def _bounded_regular_file_read(
    path: Path,
    *,
    limit: int,
    expected_snapshot: dict[str, Any] | None = None,
    repo_root: Path | None = None,
    relative_path: str | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Read one regular file through a no-follow descriptor chain and bind it."""

    global WORKTREE_CONTENT_READ_CALLS
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if repo_root is not None and relative_path is not None and (not nofollow or not directory):
        _raise("selected_path_no_follow_traversal_unsupported")
    descriptor: int
    opened_directories: list[int] = []
    parent_identities: list[dict[str, Any]] = []
    final_name: str | None = None
    try:
        if repo_root is not None and relative_path is not None:
            parts = _normalize_selected_path(relative_path).split("/")
            current = os.open(repo_root, flags | nofollow | directory)
            opened_directories.append(current)
            root_info = os.fstat(current)
            parent_identities.append(
                {"component": ".", "device": root_info.st_dev, "inode": root_info.st_ino,
                 "mode_bits": stat.S_IMODE(root_info.st_mode)}
            )
            for component in parts[:-1]:
                try:
                    child = os.open(component, flags | nofollow | directory, dir_fd=current)
                except OSError as exc:
                    if exc.errno in {errno.ELOOP, errno.EMLINK, errno.ENOTDIR}:
                        _raise("worktree_parent_symlink_race_detected")
                    _raise("worktree_parent_identity_changed")
                info = os.fstat(child)
                if not stat.S_ISDIR(info.st_mode):
                    os.close(child)
                    _raise("worktree_parent_identity_changed")
                opened_directories.append(child)
                current = child
                parent_identities.append(
                    {"component": component, "device": info.st_dev, "inode": info.st_ino,
                     "mode_bits": stat.S_IMODE(info.st_mode)}
                )
            if WORKTREE_READ_TEST_HOOK is not None:
                WORKTREE_READ_TEST_HOOK("after_parent_traversal", path, current)
            final_name = parts[-1]
            descriptor = os.open(final_name, flags | nofollow, dir_fd=current)
        else:
            descriptor = os.open(path, flags | nofollow)
    except GitAdapterError:
        for opened in reversed(opened_directories):
            os.close(opened)
        raise
    except OSError as exc:
        for opened in reversed(opened_directories):
            os.close(opened)
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            _raise("worktree_file_symlink_race_detected")
        _raise("worktree_file_identity_changed")
    try:
        before = os.fstat(descriptor)
        if WORKTREE_READ_TEST_HOOK is not None:
            WORKTREE_READ_TEST_HOOK("after_pre_fstat", path, descriptor)
        if not stat.S_ISREG(before.st_mode):
            _raise("worktree_file_identity_changed")
        if before.st_size < 0 or before.st_size > limit:
            _raise("worktree_file_size_limit_exceeded")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            WORKTREE_CONTENT_READ_CALLS += 1
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            _raise("worktree_file_size_limit_exceeded")
        if WORKTREE_READ_TEST_HOOK is not None:
            WORKTREE_READ_TEST_HOOK("after_read", path, descriptor)
        after = os.fstat(descriptor)
        stable_fields = (
            before.st_dev == after.st_dev,
            before.st_ino == after.st_ino,
            stat.S_IFMT(before.st_mode) == stat.S_IFMT(after.st_mode),
            stat.S_IMODE(before.st_mode) == stat.S_IMODE(after.st_mode),
            before.st_size == after.st_size,
        )
        if not all(stable_fields) or len(data) != after.st_size:
            _raise("worktree_content_changed_during_read")
        identity = {
            "device": before.st_dev,
            "inode": before.st_ino,
            "mode_bits": stat.S_IMODE(before.st_mode),
            "file_type": stat.S_IFMT(before.st_mode),
            "size": before.st_size,
            "sha256": sha256_bytes(data),
            "git_mode": "100755" if before.st_mode & 0o111 else "100644",
            "parent_chain": parent_identities,
        }
    except GitAdapterError:
        for opened in reversed(opened_directories):
            os.close(opened)
        opened_directories.clear()
        raise
    finally:
        os.close(descriptor)
    try:
        if repo_root is not None and relative_path is not None:
            fresh = os.open(repo_root, flags | nofollow | directory)
            fresh_fds = [fresh]
            fresh_info = os.fstat(fresh)
            observed = [{"component": ".", "device": fresh_info.st_dev, "inode": fresh_info.st_ino,
                         "mode_bits": stat.S_IMODE(fresh_info.st_mode)}]
            try:
                parts = relative_path.split("/")
                for component in parts[:-1]:
                    try:
                        child = os.open(component, flags | nofollow | directory, dir_fd=fresh)
                    except OSError as exc:
                        if exc.errno in {errno.ELOOP, errno.EMLINK, errno.ENOTDIR}:
                            _raise("worktree_parent_symlink_race_detected")
                        _raise("worktree_parent_identity_changed")
                    fresh_fds.append(child)
                    fresh = child
                    info = os.fstat(child)
                    observed.append({"component": component, "device": info.st_dev, "inode": info.st_ino,
                                     "mode_bits": stat.S_IMODE(info.st_mode)})
                if observed != parent_identities:
                    _raise("worktree_parent_identity_changed")
                assert final_name is not None
                path_state = os.stat(final_name, dir_fd=fresh, follow_symlinks=False)
            finally:
                for opened in reversed(fresh_fds):
                    os.close(opened)
        else:
            path_state = path.lstat()
    except GitAdapterError:
        raise
    except OSError:
        _raise("worktree_file_identity_changed")
    finally:
        for opened in reversed(opened_directories):
            os.close(opened)
    if stat.S_ISLNK(path_state.st_mode):
        _raise("worktree_file_symlink_race_detected")
    if (
        not stat.S_ISREG(path_state.st_mode)
        or path_state.st_dev != identity["device"]
        or path_state.st_ino != identity["inode"]
        or stat.S_IMODE(path_state.st_mode) != identity["mode_bits"]
        or path_state.st_size != identity["size"]
    ):
        _raise("worktree_file_identity_changed")
    if expected_snapshot is not None:
        if any(
            identity[key] != expected_snapshot.get(key)
            for key in ("device", "inode", "mode_bits", "file_type", "size", "parent_chain")
        ):
            _raise("worktree_file_identity_changed")
        if identity["sha256"] != expected_snapshot.get("sha256"):
            _raise("worktree_snapshot_hash_mismatch")
    return data, identity


def _bounded_inventory_files(git_dir: Path) -> dict[str, dict[str, Any]]:
    """Inventory the documented Git metadata scope without following links."""

    candidates: list[Path] = []
    fixed = ("HEAD", "index", "config", "config.worktree", "packed-refs", "shallow")
    candidates.extend(git_dir / name for name in fixed)
    for relative_root in ("refs", "objects/pack"):
        root = git_dir / relative_root
        if root.exists():
            for path in root.rglob("*"):
                if path.is_symlink():
                    _raise("git_metadata_symlink_denied")
                if path.is_file():
                    candidates.append(path)
                if len(candidates) > MAX_GIT_METADATA_INVENTORY_ENTRIES:
                    _raise("git_metadata_inventory_limit_exceeded")
    for path in git_dir.rglob("*.lock"):
        if path.is_file():
            candidates.append(path)
        if len(candidates) > MAX_GIT_METADATA_INVENTORY_ENTRIES:
            _raise("git_metadata_inventory_limit_exceeded")
    inventory: dict[str, dict[str, Any]] = {}
    for path in sorted(set(candidates)):
        if not path.exists():
            continue
        info = path.lstat()
        relative = path.relative_to(git_dir).as_posix()
        entry = {
            "size": info.st_size,
            "mode": stat.S_IMODE(info.st_mode),
            "mtime_ns": info.st_mtime_ns,
        }
        # Hash mutable control files. Pack content is represented by bounded
        # path/stat inventory so very large object databases are not allocated.
        if not relative.startswith("objects/pack/"):
            entry["sha256"] = _sha256_optional_file(path)
        inventory[relative] = entry
    return inventory


def _bounded_nofollow_file(path: Path, *, limit: int, prefix: str) -> tuple[bytes, dict[str, Any]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return b"", {"present": False}
    except OSError:
        _raise(f"{prefix}_symlink_or_open_denied")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _raise(f"{prefix}_non_regular_denied")
        if before.st_size < 0 or before.st_size > limit:
            _raise(f"{prefix}_size_limit_exceeded")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(data) > limit or len(data) != after.st_size:
            _raise(f"{prefix}_size_limit_exceeded")
        if (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            _raise(f"{prefix}_changed_during_read")
    finally:
        os.close(descriptor)
    current = path.lstat()
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
        _raise(f"{prefix}_symlink_or_open_denied")
    if (current.st_dev, current.st_ino, current.st_mode, current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
        before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns
    ):
        _raise(f"{prefix}_changed_during_read")
    return data, {
        "present": True,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mode": stat.S_IMODE(before.st_mode),
        "size": before.st_size,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
        "sha256": sha256_bytes(data),
    }


_CONFIG_BOOLEAN_PATTERN = (
    r"^(remote\..*\.promisor|core\.sparsecheckout|"
    r"core\.sparsecheckoutcone|index\.sparse)$"
)


def _run_exact_config_parser(
    git_executable: str,
    repo: Path,
    raw_config: bytes,
    *,
    typed_booleans: bool,
    command_log: list[list[str]],
) -> tuple[int, bytes]:
    """Parse captured local config bytes without reopening repository config.

    This is intentionally separate from GitRunner: no caller-controlled config
    arguments or writable Git config form can reach this helper.
    """

    arguments = ["config", "--file", "-", "--no-includes", "--null"]
    if typed_booleans:
        arguments.extend(["--type=bool", "--get-regexp", _CONFIG_BOOLEAN_PATTERN])
    else:
        arguments.extend(["--name-only", "--list"])
    command = [git_executable, *arguments]
    command_log.append(
        [
            "config-audit",
            "typed-booleans" if typed_booleans else "key-list",
            f"input_bytes={len(raw_config)}",
            f"input_sha256={sha256_bytes(raw_config)}",
        ]
    )
    # Do not let Git discover or validate the repository whose captured bytes
    # are being audited. An unsupported extension in that repository must be
    # classified from stdin rather than preempting this parser command.
    parser_cwd = Path(os.path.abspath(os.sep))
    returncode, stdout, _stderr = _run_bounded_process(
        command, cwd=parser_cwd, max_stdout=MAX_LOCAL_CONFIG_BYTES, input_bytes=raw_config
    )
    if typed_booleans:
        if returncode not in {0, 1}:
            _raise("git_local_config_parse_unsupported")
    elif returncode != 0:
        _raise("git_local_config_parse_unsupported")
    return returncode, stdout


def _run_exact_extension_parser(
    git_executable: str,
    repo: Path,
    raw_config: bytes,
    *,
    command_log: list[list[str]],
) -> tuple[int, bytes]:
    """Return captured ``extensions.*`` names and values without includes."""

    arguments = [
        "config", "--file", "-", "--no-includes", "--null",
        "--get-regexp", r"^extensions\.",
    ]
    command_log.append(
        [
            "config-audit", "extension-values",
            f"input_bytes={len(raw_config)}",
            f"input_sha256={sha256_bytes(raw_config)}",
        ]
    )
    parser_cwd = Path(os.path.abspath(os.sep))
    returncode, stdout, _stderr = _run_bounded_process(
        [git_executable, *arguments],
        cwd=parser_cwd,
        max_stdout=MAX_LOCAL_CONFIG_BYTES,
        input_bytes=raw_config,
    )
    if returncode not in {0, 1}:
        _raise("git_local_config_parse_unsupported")
    return returncode, stdout


def _classify_captured_local_config(
    git_executable: str,
    repo: Path,
    raw_config: bytes,
    *,
    command_log: list[list[str]],
) -> dict[str, Any]:
    key_returncode, key_output = _run_exact_config_parser(
        git_executable, repo, raw_config, typed_booleans=False, command_log=command_log
    )
    assert key_returncode == 0
    key_records = [record for record in key_output.split(b"\0") if record]
    if len(key_records) > MAX_LOCAL_CONFIG_KEYS:
        _raise("git_local_config_parse_unsupported")
    try:
        keys = [record.decode("ascii", errors="strict").lower() for record in key_records]
    except UnicodeDecodeError:
        _raise("git_local_config_parse_unsupported")
    if any("\n" in key or "\r" in key for key in keys):
        _raise("git_local_config_parse_unsupported")

    extension_returncode, extension_output = _run_exact_extension_parser(
        git_executable, repo, raw_config, command_log=command_log
    )
    extension_records: list[tuple[str, str]] = []
    if extension_returncode == 0:
        records = [record for record in extension_output.split(b"\0") if record]
        if len(records) > MAX_LOCAL_CONFIG_KEYS:
            _raise("git_local_config_parse_unsupported")
        for record in records:
            try:
                key_raw, value_raw = record.split(b"\n", 1)
                key = key_raw.decode("ascii", errors="strict").lower()
                value_text = value_raw.decode("ascii", errors="strict")
            except (ValueError, UnicodeDecodeError):
                _raise("git_local_config_parse_unsupported")
            if not key.startswith("extensions.") or any(
                character in value_text for character in ("\x00", "\n", "\r")
            ):
                _raise("git_local_config_parse_unsupported")
            if value_text != value_text.strip():
                _raise("repository_extension_unsupported")
            extension_records.append((key, value_text.lower()))

    extension_counts: dict[str, int] = {}
    for key, _value in extension_records:
        extension_counts[key] = extension_counts.get(key, 0) + 1
    duplicate_extension_keys = sorted(
        key for key, count in extension_counts.items() if count != 1
    )

    boolean_returncode, boolean_output = _run_exact_config_parser(
        git_executable, repo, raw_config, typed_booleans=True, command_log=command_log
    )
    boolean_records: list[tuple[str, bool]] = []
    if boolean_returncode == 0:
        records = [record for record in boolean_output.split(b"\0") if record]
        if len(records) > MAX_LOCAL_CONFIG_KEYS:
            _raise("git_local_config_parse_unsupported")
        for record in records:
            try:
                key_raw, value_raw = record.rsplit(b"\n", 1)
                key = key_raw.decode("ascii", errors="strict").lower()
                value = value_raw.decode("ascii", errors="strict").lower()
            except (ValueError, UnicodeDecodeError):
                _raise("git_local_config_parse_unsupported")
            if value not in {"true", "false"}:
                _raise("git_local_config_parse_unsupported")
            boolean_records.append((key, value == "true"))

    include_present = any(
        key == "include.path" or (key.startswith("includeif.") and key.endswith(".path"))
        for key in keys
    )
    filter_present = any(
        key.startswith("filter.") and key.rsplit(".", 1)[-1] in {"clean", "process", "required"}
        for key in keys
    )
    worktree_config_extension_present = "extensions.worktreeconfig" in keys
    partial_present = "extensions.partialclone" in keys or any(
        key.startswith("remote.") and key.endswith(".promisor") and value
        for key, value in boolean_records
    )
    sparse_true = any(
        key in {"core.sparsecheckout", "core.sparsecheckoutcone", "index.sparse"} and value
        for key, value in boolean_records
    )
    return {
        "key_count": len(keys),
        "key_list_sha256": sha256_bytes(key_output),
        "typed_boolean_count": len(boolean_records),
        "typed_boolean_result_sha256": sha256_bytes(boolean_output),
        "extension_count": len(extension_records),
        "extension_entries": [
            {"key": key, "value": value} for key, value in extension_records
        ],
        "extension_result_sha256": sha256_bytes(extension_output),
        "duplicate_extension_keys": duplicate_extension_keys,
        "include_key_present": include_present,
        "filter_driver_key_present": filter_present,
        "worktree_config_extension_present": worktree_config_extension_present,
        "partial_or_promisor_true": partial_present,
        "sparse_setting_true": sparse_true,
    }


def _git_config_boundary_snapshot(
    git_executable: str,
    repo: Path,
    metadata_lease: GitMetadataLease,
    command_log: list[list[str]],
    *,
    expected_object_format: str | None = None,
) -> dict[str, Any]:
    """Audit only captured repository-local config with Git's typed semantics."""

    files: dict[str, Any] = {}
    parsed: dict[str, Any] = {}
    blockers: list[str] = []
    inventory = metadata_lease.inventory()
    if "info/sparse-checkout" in inventory:
        blockers.append("sparse_checkout_or_sparse_index_unsupported")
    for name in ("config", "config.worktree"):
        raw, identity = metadata_lease.read_control(
            name, limit=MAX_LOCAL_CONFIG_BYTES
        )
        files[name] = identity
        if not identity.get("present"):
            parsed[name] = {"present": False}
            continue
        classification = _classify_captured_local_config(
            git_executable, repo, raw, command_log=command_log
        )
        parsed[name] = classification
        if classification["duplicate_extension_keys"]:
            blockers.append("repository_extension_unsupported")
        for extension in classification["extension_entries"]:
            key = extension["key"]
            value = extension["value"]
            if key == "extensions.objectformat":
                if value not in {"sha1", "sha256"}:
                    blockers.append("repository_extension_unsupported")
                elif expected_object_format is not None and value != expected_object_format:
                    blockers.append("repository_extension_unsupported")
            elif key == "extensions.partialclone":
                blockers.append("partial_or_promisor_repository_unsupported")
            elif key == "extensions.worktreeconfig":
                blockers.append("repository_worktree_config_extension_unsupported")
            elif key == "extensions.refstorage":
                blockers.append("git_ref_storage_backend_unsupported")
            else:
                blockers.append("repository_extension_unsupported")
        if classification["include_key_present"]:
            blockers.append("repository_config_include_unsupported")
        if classification["filter_driver_key_present"]:
            blockers.append("repository_filter_driver_unsupported")
        if classification["worktree_config_extension_present"]:
            blockers.append("repository_worktree_config_extension_unsupported")
        if classification["partial_or_promisor_true"]:
            blockers.append("partial_or_promisor_repository_unsupported")
        if classification["sparse_setting_true"]:
            blockers.append("sparse_checkout_or_sparse_index_unsupported")

    promisor_entries = sorted(
        name.rsplit("/", 1)[-1]
        for name in inventory
        if name.startswith("objects/pack/") and name.endswith(".promisor")
    )
    if promisor_entries:
        blockers.append("partial_or_promisor_repository_unsupported")
    precedence = (
        "repository_config_include_unsupported",
        "repository_filter_driver_unsupported",
        "git_ref_storage_backend_unsupported",
        "partial_or_promisor_repository_unsupported",
        "alternate_object_database_unsupported",
        "sparse_checkout_or_sparse_index_unsupported",
        "repository_worktree_config_extension_unsupported",
        "repository_extension_unsupported",
        "git_local_config_parse_unsupported",
    )
    blocker = next((item for item in precedence if item in blockers), None)
    return {
        "files": files,
        "parsed": parsed,
        "promisor_entries": sorted(promisor_entries),
        "boundary_blocker": blocker,
        "typed_git_semantics_used": True,
        "includes_resolved": False,
        "extension_allowlist_enforced": True,
        "expected_object_format": expected_object_format,
        "ref_storage_extension_absent": all(
            entry["key"] != "extensions.refstorage"
            for classification in parsed.values()
            if classification.get("present", True)
            for entry in classification.get("extension_entries", [])
        ),
    }


def _git_ref_storage_backend_snapshot(
    runner: GitRunner, config_boundary: dict[str, Any]
) -> dict[str, Any]:
    """Prove that the repository uses the traditional files ref backend."""

    if not config_boundary.get("ref_storage_extension_absent", False):
        _raise("git_ref_storage_backend_unsupported")
    observed = _one_line(runner, ["rev-parse", "--show-ref-format"])
    if observed.lower() == SUPPORTED_GIT_REF_STORAGE_BACKEND:
        return {
            "backend": SUPPORTED_GIT_REF_STORAGE_BACKEND,
            "verified": True,
            "evidence_source": "git_rev_parse_show_ref_format",
            "probe_output": observed,
            "probe_supported": True,
        }
    if observed == "--show-ref-format":
        return {
            "backend": SUPPORTED_GIT_REF_STORAGE_BACKEND,
            "verified": True,
            "evidence_source": "captured_config_and_absent_reftable_fallback",
            "probe_output": observed,
            "probe_supported": False,
        }
    _raise("git_ref_storage_backend_unsupported")


def _index_state_snapshot(runner: GitRunner, object_format: str) -> dict[str, Any]:
    args = ["ls-files", "-v", "--stage", "--sparse", "--full-name", "--no-abbrev", "-z"]
    try:
        raw = runner.run(args, max_stdout=MAX_INDEX_STATE_OUTPUT_BYTES)
    except GitAdapterError as exc:
        if str(exc) == "git_stdout_limit_exceeded":
            _raise("index_state_output_limit_exceeded")
        raise
    records = raw.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    if len(records) > MAX_INDEX_STATE_RECORDS:
        _raise("index_state_output_limit_exceeded")
    entries: dict[str, dict[str, Any]] = {}
    blocker: str | None = None
    expected_oid_length = 40 if object_format == "sha1" else 64
    for record in records:
        try:
            metadata, path_bytes = record.split(b"\t", 1)
            tag_b, mode_b, oid_b, stage_b = metadata.split(b" ", 3)
            tag = tag_b.decode("ascii")
            mode = mode_b.decode("ascii")
            oid = oid_b.decode("ascii")
            stage = int(stage_b.decode("ascii"), 10)
            path = _normalize_selected_path(path_bytes.decode("utf-8", errors="strict"))
        except (ValueError, UnicodeDecodeError):
            _raise("index_state_record_malformed")
        if len(tag) != 1 or not re.fullmatch(r"[0-7]{6}", mode):
            _raise("index_state_record_malformed")
        if not re.fullmatch(rf"[0-9a-f]{{{expected_oid_length}}}", oid):
            _raise("index_state_record_malformed")
        entry_key = path
        if path in entries:
            if stage == 0:
                _raise("index_state_duplicate_path")
            entry_key = f"{path}#stage={stage}"
        assume = tag.isascii() and tag.islower()
        skip = tag.upper() == "S"
        entries[entry_key] = {
            "path": path,
            "tag": tag, "mode": mode, "oid": oid, "stage": stage,
            "assume_unchanged": assume, "skip_worktree": skip,
        }
        if mode == "040000":
            blocker = blocker or "sparse_checkout_or_sparse_index_unsupported"
        elif assume:
            blocker = blocker or "assume_unchanged_index_entry_unsupported"
        elif skip:
            blocker = blocker or "skip_worktree_index_entry_unsupported"
        elif stage != 0:
            blocker = blocker or "nonzero_index_stage_unsupported"
        elif mode == "160000":
            blocker = blocker or "submodule_change_unsupported"
    return {
        "raw_sha256": sha256_bytes(raw),
        "tracked_path_count": len(entries),
        "entries": entries,
        "boundary_blocker": blocker,
    }


def _validate_snapshot_boundaries(snapshot: dict[str, Any]) -> None:
    config_blocker = snapshot["config_boundary"].get("boundary_blocker")
    if config_blocker:
        _raise(config_blocker)
    index_blocker = snapshot["index_state"].get("boundary_blocker")
    if index_blocker:
        _raise(index_blocker)


def _derive_inventory_changes(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> tuple[list[str], list[str], list[str]]:
    created = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(key for key in set(before) & set(after) if before[key] != after[key])
    return created, removed, changed


@dataclass
class OwnedOutputTree:
    """Descriptor-bound output tree with a constant-derived artifact allowlist."""

    parent: OutputParentLease
    current_name: str
    final_name: str
    root_fd: int
    ownership_id: str
    root_device: int
    root_inode: int
    root_mode: int
    selected_path: str
    allowed_dirs: set[str]
    payload_files: set[str]
    allowed_files: set[str]
    expected_dirs: dict[str, dict[str, int]] = field(default_factory=dict)
    expected_files: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_seal_report: dict[str, list[str]] = field(default_factory=dict)
    completion_written: bool = False
    sealed: bool = False
    closed: bool = False

    @classmethod
    def create(
        cls,
        parent: OutputParentLease,
        staging_name: str,
        selected_path: str,
    ) -> "OwnedOutputTree":
        parent.revalidate("before_staging_create")
        if parent.lstat_name(staging_name) is not None:
            _raise("adapter_output_staging_creation_failed")
        try:
            os.mkdir(staging_name, mode=0o700, dir_fd=parent.fd)
        except OSError:
            _raise("adapter_output_staging_creation_failed")
        created_info = parent.lstat_name(staging_name)
        if (
            created_info is None or not stat.S_ISDIR(created_info.st_mode)
            or stat.S_ISLNK(created_info.st_mode)
        ):
            _raise("adapter_output_staging_creation_failed")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            root_fd = os.open(staging_name, flags, dir_fd=parent.fd)
        except OSError:
            _raise("adapter_output_staging_creation_failed")
        info = os.fstat(root_fd)
        rebound = parent.lstat_name(staging_name)
        if (
            not stat.S_ISDIR(info.st_mode)
            or (info.st_dev, info.st_ino) != (created_info.st_dev, created_info.st_ino)
            or rebound is None
            or (rebound.st_dev, rebound.st_ino) != (info.st_dev, info.st_ino)
        ):
            os.close(root_fd)
            _raise("adapter_output_staging_creation_failed")
        selected = _normalize_selected_path(selected_path)
        allowed_dirs = {"", "baseline_source"}
        current = "baseline_source"
        for component in Path(selected).parts[:-1]:
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
        owned = cls(
            parent=parent,
            current_name=staging_name,
            final_name=parent.final_name,
            root_fd=root_fd,
            ownership_id=uuid.uuid4().hex,
            root_device=info.st_dev,
            root_inode=info.st_ino,
            root_mode=stat.S_IMODE(info.st_mode),
            selected_path=selected,
            allowed_dirs=allowed_dirs,
            payload_files=payload_files,
            allowed_files=allowed_files,
        )
        owned.expected_dirs[""] = {
            "device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode)
        }
        return owned

    @property
    def path(self) -> Path:
        return self.parent.raw_parent / self.current_name

    @property
    def intended_final(self) -> Path:
        return self.parent.raw_parent / self.final_name

    def _marker_payload(self) -> dict[str, Any]:
        return {
            "schema_name": "clu_governance_git_adapter_output_ownership.v1",
            "ownership_id": self.ownership_id,
            "created_staging_name": self.current_name,
            "intended_final_name": self.final_name,
            "intended_output_path": str(self.intended_final),
            "parent_device": self.parent.identity["device"],
            "parent_inode": self.parent.identity["inode"],
            "root_device": self.root_device,
            "root_inode": self.root_inode,
            "creation_mode": self.root_mode,
        }

    def _write_marker(self) -> None:
        self.write_json_once(OWNERSHIP_MARKER_NAME, self._marker_payload(), mode=0o600)

    def _root_identity_valid(self) -> bool:
        try:
            info = os.fstat(self.root_fd)
        except OSError:
            return False
        return (
            stat.S_ISDIR(info.st_mode)
            and (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode))
            == (self.root_device, self.root_inode, self.root_mode)
        )

    def _binding_valid(self) -> bool:
        try:
            info = self.parent.lstat_name(self.current_name)
        except (OSError, GitAdapterError):
            return False
        return bool(
            info is not None
            and stat.S_ISDIR(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and (info.st_dev, info.st_ino) == (self.root_device, self.root_inode)
        )

    def barrier(self, phase: str) -> None:
        self.parent.revalidate(f"{phase}:before")
        if not self._root_identity_valid() or not self._binding_valid():
            _raise("adapter_output_ownership_lost")
        self.parent.revalidate(f"{phase}:after")
        if not self._root_identity_valid() or not self._binding_valid():
            _raise("adapter_output_ownership_lost")
        self.parent.revalidate(f"{phase}:closed")

    @staticmethod
    def _parts(relative: str) -> tuple[str, ...]:
        if not isinstance(relative, str) or not relative:
            _raise("adapter_output_relative_path_invalid")
        parts = tuple(relative.split("/"))
        if any(part in {"", ".", ".."} or "\x00" in part for part in parts):
            _raise("adapter_output_relative_path_invalid")
        return parts

    def _open_directory(self, relative: str = "") -> int:
        descriptor = os.dup(self.root_fd)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            root_info = os.fstat(descriptor)
            root_expected = self.expected_dirs.get("")
            root_current = {
                "device": root_info.st_dev, "inode": root_info.st_ino,
                "mode": stat.S_IMODE(root_info.st_mode),
            }
            if not stat.S_ISDIR(root_info.st_mode) or root_current != root_expected:
                _raise("adapter_output_directory_binding_changed")
            if relative:
                traversed: list[str] = []
                for component in self._parts(relative):
                    before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                    child = os.open(component, flags, dir_fd=descriptor)
                    opened = os.fstat(child)
                    after = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                    traversed.append(component)
                    expected = self.expected_dirs.get("/".join(traversed))
                    current = {
                        "device": opened.st_dev, "inode": opened.st_ino,
                        "mode": stat.S_IMODE(opened.st_mode),
                    }
                    if (
                        not stat.S_ISDIR(opened.st_mode) or current != expected
                        or (before.st_dev, before.st_ino, before.st_mode)
                        != (opened.st_dev, opened.st_ino, opened.st_mode)
                        or (after.st_dev, after.st_ino, after.st_mode)
                        != (opened.st_dev, opened.st_ino, opened.st_mode)
                    ):
                        os.close(child)
                        _raise("adapter_output_directory_binding_changed")
                    os.close(descriptor)
                    descriptor = child
            return descriptor
        except OSError:
            os.close(descriptor)
            _raise("adapter_output_directory_binding_changed")
        except Exception:
            os.close(descriptor)
            raise

    def mkdir_relative(self, relative: str) -> None:
        if relative not in self.allowed_dirs or relative == "":
            _raise("adapter_output_directory_not_allowlisted")
        parts = self._parts(relative)
        parent_relative = "/".join(parts[:-1])
        parent_fd = self._open_directory(parent_relative)
        try:
            os.mkdir(parts[-1], mode=0o700, dir_fd=parent_fd)
            created_info = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(created_info.st_mode) or stat.S_ISLNK(created_info.st_mode):
                _raise("adapter_output_directory_type_invalid")
            child_fd = os.open(
                parts[-1],
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            try:
                info = os.fstat(child_fd)
                rebound = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                if (
                    (info.st_dev, info.st_ino, info.st_mode)
                    != (created_info.st_dev, created_info.st_ino, created_info.st_mode)
                    or (rebound.st_dev, rebound.st_ino, rebound.st_mode)
                    != (info.st_dev, info.st_ino, info.st_mode)
                ):
                    _raise("adapter_output_directory_binding_changed")
            finally:
                os.close(child_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self.expected_dirs[relative] = {
            "device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode)
        }

    def write_bytes_once(self, relative: str, data: bytes, *, mode: int = 0o644) -> None:
        if relative not in self.allowed_files:
            _raise("adapter_output_file_not_allowlisted")
        parts = self._parts(relative)
        parent_relative = "/".join(parts[:-1])
        parent_fd = self._open_directory(parent_relative)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(parts[-1], flags, mode, dir_fd=parent_fd)
            view = memoryview(data)
            total = 0
            while total < len(data):
                written = os.write(descriptor, view[total:])
                if written <= 0:
                    _raise("adapter_output_write_failed")
                total += written
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != len(data):
                _raise("adapter_output_file_type_or_link_invalid")
            rebound = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(rebound.st_mode) or rebound.st_nlink != 1
                or (rebound.st_dev, rebound.st_ino, rebound.st_mode, rebound.st_size)
                != (info.st_dev, info.st_ino, info.st_mode, info.st_size)
            ):
                _raise("adapter_output_file_binding_changed")
            os.fsync(parent_fd)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent_fd)
        self.expected_files[relative] = {
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": stat.S_IMODE(info.st_mode),
            "size": info.st_size,
            "sha256": sha256_bytes(data),
        }

    def write_json_once(self, relative: str, payload: Any, *, mode: int = 0o644) -> None:
        data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        self.write_bytes_once(relative, data, mode=mode)

    def read_expected_file(self, relative: str) -> bytes:
        expected = self.expected_files.get(relative)
        if expected is None:
            _raise("output_bundle_expected_file_missing")
        parts = self._parts(relative)
        parent_fd = self._open_directory("/".join(parts[:-1]))
        descriptor: int | None = None
        try:
            descriptor = os.open(
                parts[-1], os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                _raise("output_bundle_file_type_or_link_mismatch")
            remaining = expected["size"] + 1
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(descriptor)
            try:
                bound_name = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                _raise("output_bundle_expected_file_changed")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent_fd)
        current = {
            "device": before.st_dev, "inode": before.st_ino,
            "mode": stat.S_IMODE(before.st_mode), "size": before.st_size,
            "sha256": sha256_bytes(data),
        }
        stable = (
            before.st_dev == after.st_dev
            and before.st_ino == after.st_ino
            and before.st_mode == after.st_mode
            and before.st_nlink == after.st_nlink
            and before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns
            and stat.S_ISREG(bound_name.st_mode)
            and bound_name.st_dev == after.st_dev
            and bound_name.st_ino == after.st_ino
            and bound_name.st_mode == after.st_mode
            and bound_name.st_nlink == after.st_nlink
            and bound_name.st_size == after.st_size
            and bound_name.st_mtime_ns == after.st_mtime_ns
            and bound_name.st_ctime_ns == after.st_ctime_ns
        )
        if not stable or len(data) != before.st_size or current != expected:
            _raise("output_bundle_expected_file_changed")
        return data

    def verify_exact(self, expected_file_paths: set[str]) -> dict[str, list[str]]:
        if not expected_file_paths.issubset(self.allowed_files):
            _raise("output_bundle_allowlist_internal_error")
        def signature(info: os.stat_result) -> tuple[int, ...]:
            return (
                info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            )

        def one_closed_inventory() -> tuple[dict[str, list[str]], dict[str, dict[str, Any]]]:
            report = {
                "unknown_entries": [], "missing_entries": [], "type_mismatches": [],
                "symlink_entries": [], "hardlink_entries": [], "changed_entries": [],
            }
            inventory: dict[str, dict[str, Any]] = {}
            actual_files: set[str] = set()
            actual_dirs: set[str] = {""}
            count = 0

            def visit(directory_fd: int, relative_root: str) -> None:
                nonlocal count
                directory_before = os.fstat(directory_fd)
                expected_dir = self.expected_dirs.get(relative_root)
                current_dir = {
                    "device": directory_before.st_dev,
                    "inode": directory_before.st_ino,
                    "mode": stat.S_IMODE(directory_before.st_mode),
                }
                if not stat.S_ISDIR(directory_before.st_mode) or current_dir != expected_dir:
                    report["changed_entries"].append(relative_root or ".")
                    return
                names_before = sorted(os.listdir(directory_fd))
                inventory[relative_root or "."] = {
                    "type": "directory", "device": directory_before.st_dev,
                    "inode": directory_before.st_ino,
                    "mode": stat.S_IMODE(directory_before.st_mode),
                    "entries": names_before,
                }
                for name in names_before:
                    count += 1
                    if count > MAX_OWNED_OUTPUT_ENTRIES:
                        _raise("output_bundle_inventory_limit_exceeded")
                    relative = f"{relative_root}/{name}" if relative_root else name
                    try:
                        named_before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError:
                        report["changed_entries"].append(relative)
                        continue
                    if EXACT_SEAL_TEST_HOOK is not None:
                        EXACT_SEAL_TEST_HOOK(
                            "before_entry_open",
                            {"owned": self, "relative": relative, "directory_fd": directory_fd},
                        )
                    if stat.S_ISLNK(named_before.st_mode):
                        report["symlink_entries"].append(relative)
                        if relative not in expected_file_paths and relative not in self.allowed_dirs:
                            report["unknown_entries"].append(relative)
                        inventory[relative] = {"type": "symlink"}
                        continue
                    if stat.S_ISDIR(named_before.st_mode):
                        actual_dirs.add(relative)
                        if relative not in self.allowed_dirs:
                            report["unknown_entries"].append(relative)
                            inventory[relative] = {
                                "type": "unknown_directory", "device": named_before.st_dev,
                                "inode": named_before.st_ino,
                            }
                            continue
                        try:
                            child_fd = os.open(
                                name,
                                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                                | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=directory_fd,
                            )
                        except OSError:
                            report["changed_entries"].append(relative)
                            continue
                        try:
                            opened = os.fstat(child_fd)
                            expected_child = self.expected_dirs.get(relative)
                            opened_identity = {
                                "device": opened.st_dev, "inode": opened.st_ino,
                                "mode": stat.S_IMODE(opened.st_mode),
                            }
                            if (
                                not stat.S_ISDIR(opened.st_mode)
                                or signature(named_before) != signature(opened)
                                or opened_identity != expected_child
                            ):
                                report["changed_entries"].append(relative)
                                continue
                            visit(child_fd, relative)
                            opened_after = os.fstat(child_fd)
                            named_after = os.stat(
                                name, dir_fd=directory_fd, follow_symlinks=False
                            )
                            if (
                                signature(opened_after) != signature(opened)
                                or signature(named_after) != signature(opened)
                            ):
                                report["changed_entries"].append(relative)
                        except OSError:
                            report["changed_entries"].append(relative)
                        finally:
                            os.close(child_fd)
                        continue
                    if stat.S_ISREG(named_before.st_mode):
                        actual_files.add(relative)
                        if named_before.st_nlink != 1:
                            report["hardlink_entries"].append(relative)
                        if relative not in expected_file_paths:
                            report["unknown_entries"].append(relative)
                            inventory[relative] = {
                                "type": "unknown_file", "device": named_before.st_dev,
                                "inode": named_before.st_ino, "size": named_before.st_size,
                            }
                            continue
                        expected = self.expected_files.get(relative)
                        if expected is None:
                            report["missing_entries"].append(relative)
                            continue
                        descriptor: int | None = None
                        try:
                            descriptor = os.open(
                                name,
                                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                                | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=directory_fd,
                            )
                            opened = os.fstat(descriptor)
                            if (
                                not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                                or signature(named_before) != signature(opened)
                            ):
                                report["changed_entries"].append(relative)
                                continue
                            remaining = expected["size"] + 1
                            chunks: list[bytes] = []
                            while remaining:
                                chunk = os.read(descriptor, min(65536, remaining))
                                if not chunk:
                                    break
                                chunks.append(chunk)
                                remaining -= len(chunk)
                            data = b"".join(chunks)
                            opened_after = os.fstat(descriptor)
                            named_after = os.stat(
                                name, dir_fd=directory_fd, follow_symlinks=False
                            )
                            observed = {
                                "device": opened.st_dev, "inode": opened.st_ino,
                                "mode": stat.S_IMODE(opened.st_mode), "size": opened.st_size,
                                "sha256": sha256_bytes(data),
                            }
                            if (
                                signature(opened_after) != signature(opened)
                                or signature(named_after) != signature(opened)
                                or len(data) != opened.st_size
                                or observed != expected
                            ):
                                report["changed_entries"].append(relative)
                            inventory[relative] = {"type": "file", **observed}
                        except OSError:
                            report["changed_entries"].append(relative)
                        finally:
                            if descriptor is not None:
                                os.close(descriptor)
                        continue
                    report["type_mismatches"].append(relative)
                    if relative not in expected_file_paths and relative not in self.allowed_dirs:
                        report["unknown_entries"].append(relative)
                    inventory[relative] = {"type": "unsupported"}
                names_after = sorted(os.listdir(directory_fd))
                directory_after = os.fstat(directory_fd)
                if names_after != names_before or signature(directory_after) != signature(directory_before):
                    report["changed_entries"].append(relative_root or ".")

            root_copy = os.dup(self.root_fd)
            try:
                visit(root_copy, "")
            finally:
                os.close(root_copy)
            report["missing_entries"].extend(sorted(expected_file_paths - actual_files))
            report["missing_entries"].extend(sorted(self.allowed_dirs - actual_dirs))
            for key in report:
                report[key] = sorted(set(report[key]))
            return report, inventory

        self.barrier("exact_inventory_before_first_pass")
        first_report, first_inventory = one_closed_inventory()
        if EXACT_SEAL_TEST_HOOK is not None:
            EXACT_SEAL_TEST_HOOK("between_inventory_passes", {"owned": self})
        self.barrier("exact_inventory_before_second_pass")
        second_report, second_inventory = one_closed_inventory()
        report = second_report
        if first_report != second_report or first_inventory != second_inventory:
            report["changed_entries"] = sorted(
                set(report["changed_entries"]) | {"snapshot_closure"}
            )
        self.last_seal_report = report
        blocker = next(
            (
                blocker_name
                for field_name, blocker_name in (
                    ("symlink_entries", "output_bundle_symlink_entry_detected"),
                    ("hardlink_entries", "output_bundle_hardlink_entry_detected"),
                    ("unknown_entries", "output_bundle_unknown_entry_detected"),
                    ("missing_entries", "output_bundle_missing_entry_detected"),
                    ("type_mismatches", "output_bundle_type_mismatch_detected"),
                    ("changed_entries", "output_bundle_registered_entry_changed"),
                )
                if report[field_name]
            ),
            None,
        )
        if blocker:
            _raise(blocker)
        return report

    def relocate(self) -> None:
        """Disabled legacy transition; publication uses publish_final_action."""

        _raise("legacy_relocate_disabled")

    def publish_final_action(self) -> None:
        """Publish by one no-replace rename after all fallible preparation."""

        _rename_directory_no_replace_at(
            self.parent.fd, self.current_name, self.final_name
        )
        self.parent.refresh_after_owned_parent_mutation()
        self.current_name = self.final_name

    def preserve_failure(self, blocker: str | None) -> dict[str, Any]:
        """Preserve nonempty output; never unlink, rmdir, or recursively delete it."""

        binding_preserved = self._binding_valid()
        parent_visible = True
        try:
            self.parent.revalidate("failure_disposition")
        except GitAdapterError:
            parent_visible = False
        # Never rename, remove, or write into a failed nonempty tree. The
        # caller-visible result is the sole failure marker.
        marker_written = False
        visible_path = None
        if parent_visible and self._binding_valid():
            visible_path = str(self.parent.raw_parent / self.current_name)
        requested_present = False
        requested_owned = False
        if parent_visible:
            requested = self.parent.lstat_name(self.final_name)
            requested_present = requested is not None
            requested_owned = bool(
                requested is not None and stat.S_ISDIR(requested.st_mode)
                and not stat.S_ISLNK(requested.st_mode)
                and (requested.st_dev, requested.st_ino)
                == (self.root_device, self.root_inode)
            )
        hidden_completion_present = False
        expected_completion = self.expected_files.get("BUNDLE_COMPLETE.json")
        if (
            self.current_name != self.final_name
            and expected_completion is not None
            and self._root_identity_valid()
        ):
            try:
                observed_completion = os.stat(
                    "BUNDLE_COMPLETE.json", dir_fd=self.root_fd, follow_symlinks=False
                )
            except OSError:
                observed_completion = None
            if observed_completion is not None:
                hidden_completion_present = bool(
                    stat.S_ISREG(observed_completion.st_mode)
                    and not stat.S_ISLNK(observed_completion.st_mode)
                    and observed_completion.st_nlink == 1
                    and (
                        observed_completion.st_dev,
                        observed_completion.st_ino,
                        stat.S_IMODE(observed_completion.st_mode),
                        observed_completion.st_size,
                    )
                    == (
                        expected_completion["device"],
                        expected_completion["inode"],
                        expected_completion["mode"],
                        expected_completion["size"],
                    )
                )
        return {
            "automatic_nonempty_failure_cleanup_performed": False,
            "cleanup_intentionally_not_attempted": True,
            "incomplete_staging_reported_when_preserved": True,
            "incomplete_staging_path": visible_path,
            "incomplete_output_ownership_id": self.ownership_id,
            "incomplete_marker_written": marker_written,
            "incomplete_marker_suppressed_due_completion_record": bool(
                self.completion_written
            ),
            "hidden_sealed_bundle_preserved": bool(
                self.sealed and self.current_name != self.final_name
            ),
            "hidden_completion_record_present": hidden_completion_present,
            "output_tree_binding_preserved": binding_preserved,
            "output_parent_identity_preserved": parent_visible,
            "adapter_owned_output_may_be_orphaned": visible_path is None,
            "requested_final_output_present_after_failed_seal": requested_owned,
            "requested_final_output_is_adapter_owned": requested_owned,
            "unowned_replacement_detected": bool(requested_present and not requested_owned),
            "unowned_replacement_path": (
                str(self.parent.raw_parent / self.final_name)
                if requested_present and not requested_owned else None
            ),
            "output_entries_deleted": [],
            "unowned_output_content_deleted": False,
        }

    def close(self) -> None:
        if not self.closed:
            try:
                os.close(self.root_fd)
            except OSError:
                pass
            self.closed = True


def _rename_no_replace_at(
    parent_fd: int, source: str, destination: str, *, collision_blocker: str
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(
            ctypes.c_int(parent_fd), ctypes.c_char_p(source_bytes),
            ctypes.c_int(parent_fd), ctypes.c_char_p(destination_bytes), ctypes.c_uint(0x00000004)
        )
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        result = libc.renameat2(
            ctypes.c_int(parent_fd), ctypes.c_char_p(source_bytes),
            ctypes.c_int(parent_fd), ctypes.c_char_p(destination_bytes), ctypes.c_uint(1)
        )
    else:
        _raise("atomic_no_replace_directory_rename_unsupported")
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            _raise(collision_blocker)
        _raise("adapter_output_atomic_rename_failed")


def _rename_directory_no_replace_at(parent_fd: int, source: str, destination: str) -> None:
    """Atomically publish within the retained parent descriptor, without replace."""

    _rename_no_replace_at(
        parent_fd, source, destination, collision_blocker="output_path_must_not_exist"
    )


def _rename_quarantine_no_replace_at(parent_fd: int, source: str, destination: str) -> None:
    _rename_no_replace_at(
        parent_fd, source, destination,
        collision_blocker="internal_temp_cleanup_ownership_lost",
    )


def _git_metadata_snapshot(
    repo: Path,
    git_dir: Path,
    runner: GitRunner,
    selected_path: str | None,
    *,
    max_file_size: int = MAX_PROPOSED_FILE_SIZE,
) -> dict[str, Any]:
    metadata_lease = runner.metadata_lease
    if metadata_lease is None:
        _raise("git_metadata_descriptor_boundary_missing")
    head_oid = _one_line(runner, ["rev-parse", "HEAD"])
    object_format = _one_line(runner, ["rev-parse", "--show-object-format"])
    if object_format not in {"sha1", "sha256"}:
        _raise("git_object_format_unsupported")
    config_boundary = _git_config_boundary_snapshot(
        runner.executable,
        repo,
        metadata_lease,
        runner.commands,
        expected_object_format=object_format,
    )
    if config_boundary.get("boundary_blocker"):
        _raise(config_boundary["boundary_blocker"])
    ref_storage = _git_ref_storage_backend_snapshot(runner, config_boundary)
    index_state = _index_state_snapshot(runner, object_format)
    if index_state.get("boundary_blocker"):
        _raise(index_state["boundary_blocker"])
    branch = _one_line(runner, ["rev-parse", "--abbrev-ref", "HEAD"])
    status_bytes = runner.run(
        [
            "status", "--porcelain=v2", "-z", "--untracked-files=all",
            "--ignored=matching", "--ignore-submodules=all",
        ],
        max_stdout=MAX_GIT_STATUS_BYTES,
    )
    index_raw = _one_line(runner, ["rev-parse", "--git-path", "index"])
    index_path = Path(index_raw)
    if not index_path.is_absolute():
        index_path = repo / index_path
    index_path = index_path.resolve(strict=False)
    if not is_relative_to(index_path, git_dir):
        _raise("git_index_outside_git_dir_denied")
    metadata_inventory = metadata_lease.inventory()
    config_hashes = {
        name: metadata_inventory[name]["sha256"]
        for name in ("config", "config.worktree")
        if name in metadata_inventory
    }
    refs_hashes = {
        name: entry["sha256"]
        for name, entry in metadata_inventory.items()
        if "sha256" in entry and (name in {"HEAD", "packed-refs"} or name.startswith("refs/"))
    }
    locks = sorted(name for name in metadata_inventory if name.endswith(".lock"))
    index_hash = metadata_inventory.get("index", {}).get("sha256")
    snapshot: dict[str, Any] = {
        "head_oid": head_oid,
        "object_format": object_format,
        "git_ref_storage_backend": ref_storage["backend"],
        "git_ref_storage_backend_proof": ref_storage,
        "branch_name": None if branch == "HEAD" else branch,
        "detached_head": branch == "HEAD",
        "porcelain_v2_status_sha256": sha256_bytes(status_bytes),
        "porcelain_v2_status_bytes_hex": status_bytes.hex(),
        "index_path": str(index_path),
        "index_sha256": index_hash,
        "config_sha256": config_hashes,
        "refs_sha256": refs_hashes,
        "lock_files": locks,
        "metadata_inventory": metadata_inventory,
        "config_boundary": config_boundary,
        "index_state": index_state,
    }
    if selected_path is not None:
        mode, _kind, blob_oid = _parse_ls_tree(
            runner.run(["ls-tree", "-z", "HEAD", "--", selected_path]), selected_path
        )
        _ignored_bytes, worktree_identity = _bounded_regular_file_read(
            repo / selected_path,
            limit=max_file_size,
            repo_root=repo,
            relative_path=selected_path,
        )
        snapshot.update(
            {
                "selected_path": selected_path,
                "head_file_mode": mode,
                "baseline_blob_oid": blob_oid,
                "working_tree_sha256": worktree_identity["sha256"],
                "working_tree_size": worktree_identity["size"],
                "working_tree_mode": worktree_identity["git_mode"],
                "working_tree_identity": worktree_identity,
            }
        )
    # Close the snapshot over every state surface used by acceptance. A change
    # during this capture is not an accepted proof snapshot.
    head_after = _one_line(runner, ["rev-parse", "HEAD"])
    status_after = runner.run(
        [
            "status", "--porcelain=v2", "-z", "--untracked-files=all",
            "--ignored=matching", "--ignore-submodules=all",
        ],
        max_stdout=MAX_GIT_STATUS_BYTES,
    )
    index_after = _index_state_snapshot(runner, object_format)
    config_after = _git_config_boundary_snapshot(
        runner.executable,
        repo,
        metadata_lease,
        runner.commands,
        expected_object_format=object_format,
    )
    ref_storage_after = _git_ref_storage_backend_snapshot(runner, config_after)
    metadata_after = metadata_lease.inventory()
    index_hash_after = metadata_after.get("index", {}).get("sha256")
    if selected_path is not None:
        _again_bytes, again_identity = _bounded_regular_file_read(
            repo / selected_path,
            limit=max_file_size,
            expected_snapshot=snapshot["working_tree_identity"],
            repo_root=repo,
            relative_path=selected_path,
        )
    else:
        again_identity = None
    if (
        head_after != head_oid
        or status_after != status_bytes
        or index_after != index_state
        or config_after != config_boundary
        or ref_storage_after != ref_storage
        or metadata_after != metadata_inventory
        or index_hash_after != snapshot["index_sha256"]
        or (selected_path is not None and again_identity != snapshot["working_tree_identity"])
    ):
        _raise("repository_snapshot_not_closed")
    return snapshot


def _snapshot_equal(before: dict[str, Any], after: dict[str, Any]) -> bool:
    keys = {
        "head_oid", "object_format", "git_ref_storage_backend",
        "git_ref_storage_backend_proof", "branch_name", "detached_head",
        "porcelain_v2_status_sha256", "index_sha256", "config_sha256",
        "refs_sha256", "lock_files", "selected_path", "head_file_mode",
        "baseline_blob_oid", "working_tree_sha256", "working_tree_size",
        "working_tree_mode", "working_tree_identity", "metadata_inventory",
        "config_boundary", "index_state",
    }
    return all(before.get(key) == after.get(key) for key in keys)


def _proof_inventory(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    inventory = {
        f"git:{path}": value for path, value in snapshot.get("metadata_inventory", {}).items()
    }
    inventory["repository:ignored_aware_porcelain_v2"] = {
        "sha256": snapshot.get("porcelain_v2_status_sha256")
    }
    inventory["repository:index_state"] = {
        "sha256": snapshot.get("index_state", {}).get("raw_sha256"),
        "tracked_path_count": snapshot.get("index_state", {}).get("tracked_path_count"),
    }
    for path, entry in snapshot.get("index_state", {}).get("entries", {}).items():
        inventory[f"index:{path}"] = dict(entry)
    inventory["repository:config_boundary"] = {
        "sha256": gate.canonical_sha256(snapshot.get("config_boundary", {}))
    }
    inventory["repository:git_ref_storage_backend"] = {
        "backend": snapshot.get("git_ref_storage_backend"),
        "sha256": gate.canonical_sha256(
            snapshot.get("git_ref_storage_backend_proof", {})
        ),
    }
    raw_status = bytes.fromhex(snapshot.get("porcelain_v2_status_bytes_hex", ""))
    for raw_record in raw_status.split(b"\0"):
        if not raw_record:
            continue
        kind = raw_record[:1].decode("ascii", errors="replace")
        if kind in {"?", "!"}:
            path_bytes = raw_record[2:]
        elif kind == "1":
            fields = raw_record.split(b" ", 8)
            path_bytes = fields[8] if len(fields) == 9 else b"<malformed>"
        else:
            path_bytes = raw_record
        path_text = path_bytes.decode("utf-8", errors="backslashreplace")
        inventory[f"status:{kind}:{path_text}"] = {"record_sha256": sha256_bytes(raw_record)}
    if snapshot.get("selected_path"):
        inventory[f"worktree:{snapshot['selected_path']}"] = dict(snapshot["working_tree_identity"])
    return inventory


def _artifact_checksums(owned: OwnedOutputTree) -> bytes:
    """Render checksums only from the immutable payload allowlist."""

    owned.verify_exact(set(owned.payload_files))
    records = [
        f"{owned.expected_files[relative]['sha256']}  {relative}"
        for relative in sorted(owned.payload_files)
    ]
    return ("\n".join(records) + "\n").encode("utf-8")


def _verify_artifact_checksums(owned: OwnedOutputTree) -> bool:
    try:
        raw = owned.read_expected_file("CHECKSUMS.sha256")
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except (GitAdapterError, UnicodeDecodeError):
        return False
    expected_paths = sorted(owned.payload_files)
    if len(lines) != len(expected_paths):
        return False
    observed_paths: list[str] = []
    for line, expected_path in zip(lines, expected_paths):
        try:
            digest, relative = line.split("  ", 1)
        except ValueError:
            return False
        if relative != expected_path or not re.fullmatch(r"[0-9a-f]{64}", digest):
            return False
        if digest != owned.expected_files.get(relative, {}).get("sha256"):
            return False
        try:
            if sha256_bytes(owned.read_expected_file(relative)) != digest:
                return False
        except GitAdapterError:
            return False
        observed_paths.append(relative)
    return observed_paths == expected_paths and len(set(observed_paths)) == len(expected_paths)


def _single_file_descriptor_source_hash(selected_path: str, baseline_bytes: bytes) -> str:
    """Reproduce the gate source-tree hash for the exact one-file surface."""

    digest = hashlib.sha256()
    digest.update(selected_path.encode("utf-8"))
    digest.update(b"\0")
    digest.update(sha256_bytes(baseline_bytes).encode("ascii"))
    digest.update(b"\0")
    return digest.hexdigest()


def _read_owned_json(owned: OwnedOutputTree, relative: str) -> dict[str, Any]:
    try:
        value = strict_json.loads(
            owned.read_expected_file(relative).decode("utf-8", errors="strict")
        )
    except (UnicodeDecodeError, json.JSONDecodeError, GitAdapterError):
        _raise("generated_policy_decision_genuine_artifact_binding_failed")
    if not isinstance(value, dict):
        _raise("generated_policy_decision_genuine_artifact_binding_failed")
    return value


def _read_owned_completion_json(owned: OwnedOutputTree) -> dict[str, Any]:
    try:
        value = strict_json.loads(
            owned.read_expected_file("BUNDLE_COMPLETE.json").decode(
                "utf-8", errors="strict"
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError, GitAdapterError):
        _raise("output_bundle_completion_record_invalid")
    if not isinstance(value, dict):
        _raise("output_bundle_completion_record_invalid")
    return value


def _validate_bound_policy_decision(
    *,
    owned: OwnedOutputTree,
    decision: dict[str, Any],
    selected_path: str,
    expected_request: dict[str, Any],
    expected_rollback: dict[str, Any],
    expected_policy_hash: str | None,
) -> None:
    """Require the decision to derive from descriptor-read genuine artifacts."""

    blocker = "generated_policy_decision_genuine_artifact_binding_failed"
    request = _read_owned_json(owned, "source_mutation_request.json")
    rollback = _read_owned_json(owned, "rollback_snapshot.json")
    baseline = owned.read_expected_file(f"baseline_source/{selected_path}")
    if request != expected_request or rollback != expected_rollback:
        _raise(blocker)
    try:
        baseline_text = baseline.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _raise(blocker)
    baseline_hash = sha256_bytes(baseline)
    source_hash = _single_file_descriptor_source_hash(selected_path, baseline)
    operation = {"operation": "modify", "path": selected_path, "before_sha256": baseline_hash}
    operations = request.get("operations")
    readiness = request.get("rollback_readiness")
    rollback_files = rollback.get("files")
    expected_final_rollback = str(owned.intended_final / "rollback_snapshot.json")
    if (
        operations != [operation]
        or request.get("source_tree_hash") != source_hash
        or request.get("proposal_hash") != gate.canonical_sha256(request.get("proposal_body"))
        or not isinstance(readiness, dict)
        or readiness.get("artifact_path") != expected_final_rollback
        or readiness.get("artifact_sha256")
        != owned.expected_files["rollback_snapshot.json"]["sha256"]
        or readiness.get("files") != {selected_path: {"before_sha256": baseline_hash}}
        or not isinstance(rollback_files, dict)
        or set(rollback_files) != {selected_path}
        or rollback_files[selected_path].get("path") != selected_path
        or rollback_files[selected_path].get("before_sha256") != baseline_hash
        or rollback_files[selected_path].get("original_content") != baseline_text
        or rollback_files[selected_path].get("content_encoding") != "utf-8"
    ):
        _raise(blocker)
    common = {
        "request_id": request.get("request_id"),
        "proposal_id": request.get("proposal_id"),
        "canonical_request_hash": gate.canonical_sha256(request),
        "declared_actor_id": request.get("declared_actor_id"),
        "requested_scope": request.get("requested_scope"),
        "proposal_hash_supplied": request.get("proposal_hash"),
        "proposal_hash_verified": gate.canonical_sha256(request.get("proposal_body")),
        "source_hash_supplied": source_hash,
        "source_hash_verified": source_hash,
        "policy_hash": expected_policy_hash,
    }
    if any(decision.get(key) != value for key, value in common.items()):
        _raise(blocker)
    if (
        decision.get("mutation_authorized") is not False
        or decision.get("mutation_applied") is not False
        or decision.get("audit_event_hash")
        != gate.canonical_sha256(
            {key: value for key, value in decision.items() if key != "audit_event_hash"}
        )
    ):
        _raise(blocker)
    checked = decision.get("checked_paths_and_operations")
    if not isinstance(checked, list) or any(item != operation for item in checked):
        _raise(blocker)
    if decision.get("decision") == "allow":
        if (
            checked != [operation]
            or decision.get("rollback_readiness_verified") is not True
            or decision.get("eligible_for_human_approval") is not True
            or decision.get("exact_blocker") is not None
        ):
            _raise(blocker)
        expected_binding = gate.execution_binding_for(
            request=request,
            policy_hash=expected_policy_hash,
            checked_operations=checked,
            matched_rule_id=decision.get("matched_rule_id"),
        )
        if (
            decision.get("execution_binding") != expected_binding
            or decision.get("execution_binding_hash")
            != expected_binding["execution_binding_hash"]
        ):
            _raise(blocker)
    elif decision.get("decision") == "deny":
        if (
            decision.get("eligible_for_human_approval") is not False
            or decision.get("execution_binding") is not None
            or decision.get("execution_binding_hash") is not None
        ):
            _raise(blocker)
    else:
        _raise(blocker)


def _check_adapter_operation_policy_in_memory(
    policy: dict[str, Any],
    request: dict[str, Any],
    *,
    selected_path: str,
    baseline_hash: str,
) -> tuple[list[dict[str, Any]], str | None, str | None, str | None]:
    """Recheck the gate's one-file rule semantics without reopening a path."""

    operations = request.get("operations", [])
    if len(operations) > int(policy.get("maximum_file_count", 0)):
        return [], None, None, "maximum_file_count_exceeded"
    if operations != [
        {"operation": "modify", "path": selected_path, "before_sha256": baseline_hash}
    ]:
        return [], None, None, "adapter_generated_operation_binding_mismatch"
    operation = operations[0]
    if "modify" not in set(policy.get("allowed_operations") or []):
        return [], None, None, "unknown_or_disallowed_operation_denied"
    if gate.path_has_sensitive_name(selected_path):
        return [], None, None, "sensitive_path_denied"
    deny_rule = gate.first_matching_rule(policy, operation, "deny")
    if deny_rule is not None:
        return [], None, str(deny_rule["rule_id"]), "explicit_deny_rule_matched"
    denied_paths = gate.normalize_pattern_list(policy.get("denied_paths"))
    denied_prefixes = gate.normalize_pattern_list(policy.get("denied_path_prefixes"))
    denied_globs = [
        str(item).replace("\\", "/")
        for item in (policy.get("denied_path_globs") or [])
        if isinstance(item, str)
    ]
    if gate.match_path(
        selected_path, exact=denied_paths, prefixes=denied_prefixes, globs=denied_globs
    ):
        return [], None, None, "explicit_denied_path_matched"
    allowed_paths = gate.normalize_pattern_list(policy.get("allowed_paths"))
    allowed_prefixes = gate.normalize_pattern_list(policy.get("allowed_path_prefixes"))
    allowed_globs = [
        str(item).replace("\\", "/")
        for item in (policy.get("allowed_path_globs") or [])
        if isinstance(item, str)
    ]
    if not gate.match_path(
        selected_path, exact=allowed_paths, prefixes=allowed_prefixes, globs=allowed_globs
    ):
        return [], None, None, "path_not_explicitly_allowed"
    allow_rule = gate.first_matching_rule(policy, operation, "allow")
    if allow_rule is None:
        return [], None, None, "allow_rule_missing"
    checked = [{"operation": "modify", "path": selected_path, "before_sha256": baseline_hash}]
    return checked, str(allow_rule["rule_id"]), None, None


def _check_adapter_rollback_in_memory(
    *,
    policy: dict[str, Any],
    request: dict[str, Any],
    rollback: dict[str, Any],
    rollback_bytes: bytes,
    selected_path: str,
    baseline_hash: str,
    baseline_text: str,
) -> tuple[bool, str | None]:
    """Validate the exact generated rollback artifact without a pathname read."""

    if not policy.get("rollback_readiness_required", True):
        return True, None
    readiness = request.get("rollback_readiness")
    if not isinstance(readiness, dict):
        return False, "rollback_readiness_missing"
    if (
        readiness.get("schema_name") != gate.ROLLBACK_SCHEMA_NAME
        or readiness.get("schema_version") != "1"
    ):
        return False, "rollback_readiness_wrong_schema"
    artifact_path_raw = readiness.get("artifact_path")
    if not isinstance(artifact_path_raw, str) or not artifact_path_raw:
        return False, "rollback_artifact_path_missing"
    artifact_path = Path(artifact_path_raw)
    if not artifact_path.is_absolute():
        return False, "rollback_artifact_path_must_be_absolute"
    if gate.artifact_path_has_unsafe_part(artifact_path):
        return False, "rollback_artifact_unsafe_path_denied"
    artifact_hash = readiness.get("artifact_sha256")
    if not isinstance(artifact_hash, str) or not artifact_hash:
        return False, "rollback_artifact_hash_missing"
    if artifact_hash != sha256_bytes(rollback_bytes):
        return False, "rollback_artifact_hash_mismatch"
    if (
        rollback.get("schema_name") != gate.ROLLBACK_SCHEMA_NAME
        or rollback.get("schema_version") != "1"
    ):
        return False, "rollback_artifact_wrong_schema"
    if not (rollback.get("snapshot_id") or rollback.get("rollback_manifest_id")):
        return False, "rollback_artifact_id_missing"
    expected_file = {
        "path": selected_path,
        "before_sha256": baseline_hash,
        "original_content": baseline_text,
        "content_encoding": "utf-8",
    }
    if rollback.get("files") != {selected_path: expected_file}:
        return False, "rollback_artifact_file_entry_missing"
    if readiness.get("files") != {selected_path: {"before_sha256": baseline_hash}}:
        return False, "rollback_wrapper_artifact_mismatch"
    return True, None


def _evaluate_bound_adapter_request(
    *,
    owned: OwnedOutputTree,
    final_request: dict[str, Any],
    rollback: dict[str, Any],
    selected_path: str,
    policy_bytes: bytes,
    event_time: str | None,
    internal_temp: InternalTempRootLease,
) -> dict[str, Any]:
    """Evaluate a private copy, then rebuild a decision for the final request.

    The final request names the not-yet-published final rollback path.  A
    private evaluation request points to an exact temporary copy of the same
    rollback bytes.  The gate supplies policy/operation semantics; the rebuilt
    decision is then bound to the genuine descriptor-read final request.
    """

    baseline = owned.read_expected_file(f"baseline_source/{selected_path}")
    rollback_bytes = owned.read_expected_file("rollback_snapshot.json")
    genuine_source_hash = _single_file_descriptor_source_hash(selected_path, baseline)
    try:
        baseline_text = baseline.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _raise("generated_policy_decision_genuine_artifact_binding_failed")
    baseline_hash = sha256_bytes(baseline)
    try:
        genuine_policy_object = strict_json.loads(
            policy_bytes.decode("utf-8", errors="strict")
        )
        genuine_policy_hash = gate.canonical_sha256(genuine_policy_object)
        genuine_policy_load_error: str | None = None
    except (UnicodeDecodeError, json.JSONDecodeError):
        genuine_policy_object = None
        genuine_policy_hash = sha256_bytes(policy_bytes)
        genuine_policy_load_error = "policy_malformed_json"
    selected_parts = selected_path.split("/")
    allowed_dirs = {"", "baseline_source"}
    current = "baseline_source"
    for component in selected_parts[:-1]:
        current = f"{current}/{component}"
        allowed_dirs.add(current)
    allowed_files = {
        f"baseline_source/{selected_path}", "policy.json",
        "rollback_snapshot.json", "request.json",
    }
    with internal_temp.workspace(
        "clu-git-gate-evaluation-", allowed_dirs=allowed_dirs, allowed_files=allowed_files
    ) as workspace:
        root = workspace.path
        baseline_root = root / "baseline_source"
        target = baseline_root / selected_path
        for directory in sorted(allowed_dirs - {""}, key=lambda item: (item.count("/"), item)):
            workspace.mkdir(directory)
        workspace.write_bytes(f"baseline_source/{selected_path}", baseline)
        policy_copy = root / "policy.json"
        workspace.write_bytes("policy.json", policy_bytes)
        rollback_copy = root / "rollback_snapshot.json"
        workspace.write_bytes("rollback_snapshot.json", rollback_bytes)
        evaluation_request = strict_json.loads(json.dumps(final_request))
        evaluation_request["rollback_readiness"]["artifact_path"] = str(rollback_copy)
        request_copy = root / "request.json"
        workspace.write_text(
            "request.json", json.dumps(evaluation_request, indent=2, sort_keys=True) + "\n"
        )
        workspace.revalidate()
        evaluated = gate.evaluate_source_mutation_request(
            policy_path=policy_copy,
            request_path=request_copy,
            source_root=baseline_root,
            event_timestamp=event_time,
        )
        workspace.revalidate()
        expected_eval_binding = {
            "canonical_request_hash": gate.canonical_sha256(evaluation_request),
            "request_id": evaluation_request.get("request_id"),
            "proposal_id": evaluation_request.get("proposal_id"),
            "proposal_hash_supplied": evaluation_request.get("proposal_hash"),
            "proposal_hash_verified": gate.canonical_sha256(evaluation_request.get("proposal_body")),
            "source_hash_supplied": genuine_source_hash,
            "source_hash_verified": genuine_source_hash,
            "policy_hash": genuine_policy_hash,
        }
        if any(evaluated.get(key) != value for key, value in expected_eval_binding.items()):
            _raise("generated_policy_decision_genuine_artifact_binding_failed")
        if evaluated.get("audit_event_hash") != gate.canonical_sha256(
            {key: value for key, value in evaluated.items() if key != "audit_event_hash"}
        ):
            _raise("generated_policy_decision_genuine_artifact_binding_failed")
        checked = evaluated.get("checked_paths_and_operations")
        if not isinstance(checked, list):
            _raise("generated_policy_decision_genuine_artifact_binding_failed")
        if evaluated.get("decision") == "allow":
            expected_eval_execution = gate.execution_binding_for(
                request=evaluation_request,
                policy_hash=genuine_policy_hash,
                checked_operations=checked,
                matched_rule_id=evaluated.get("matched_rule_id"),
            )
            if evaluated.get("execution_binding") != expected_eval_execution:
                _raise("generated_policy_decision_genuine_artifact_binding_failed")
        elif evaluated.get("decision") != "deny":
            _raise("generated_policy_decision_genuine_artifact_binding_failed")

        # Re-run the evaluator's ordered gate checks through its existing
        # reusable validators after the private files have returned to their
        # genuine bytes. This prevents a transient rollback/source replacement
        # from driving a false allow *or* a false policy denial.
        expected_decision = "deny"
        expected_reason: str | None = genuine_policy_load_error
        expected_matched: str | None = None
        expected_checked: list[dict[str, Any]] = []
        expected_rollback_verified = False
        if expected_reason is None:
            expected_reason = gate.validate_policy(genuine_policy_object)
        if expected_reason is None:
            expected_reason = gate.validate_request_shape(final_request)
        if expected_reason is None:
            assert isinstance(genuine_policy_object, dict)
            expected_reason = gate.validate_actor_and_scope(
                genuine_policy_object, final_request
            )
        if expected_reason is None:
            if final_request.get("proposal_hash") != gate.canonical_sha256(
                final_request.get("proposal_body")
            ):
                expected_reason = "proposal_hash_mismatch"
            elif final_request.get("source_tree_hash") != genuine_source_hash:
                expected_reason = "source_hash_mismatch"
        if expected_reason is None:
            expected_checked_raw, allow_rule, deny_rule, operation_error = (
                _check_adapter_operation_policy_in_memory(
                    genuine_policy_object,
                    final_request,
                    selected_path=selected_path,
                    baseline_hash=baseline_hash,
                )
            )
            if operation_error is not None:
                expected_reason = operation_error
                expected_matched = deny_rule or allow_rule
            else:
                expected_matched = allow_rule
                rollback_verified, rollback_error = _check_adapter_rollback_in_memory(
                    policy=genuine_policy_object,
                    request=final_request,
                    rollback=rollback,
                    rollback_bytes=rollback_bytes,
                    selected_path=selected_path,
                    baseline_hash=baseline_hash,
                    baseline_text=baseline_text,
                )
                if rollback_error is not None:
                    expected_reason = rollback_error
                else:
                    expected_decision = "allow"
                    expected_reason = "eligible_for_human_approval"
                    expected_checked = expected_checked_raw
                    expected_rollback_verified = rollback_verified
        if (
            evaluated.get("decision") != expected_decision
            or evaluated.get("reason_code") != expected_reason
            or evaluated.get("exact_blocker")
            != (None if expected_decision == "allow" else expected_reason)
            or evaluated.get("matched_rule_id") != expected_matched
            or checked != expected_checked
            or (evaluated.get("rollback_readiness_verified") is True)
            != expected_rollback_verified
        ):
            _raise("generated_policy_decision_genuine_artifact_binding_failed")
        decision = gate.build_decision(
            request=final_request,
            policy=genuine_policy_object,
            policy_hash=genuine_policy_hash,
            source_root=baseline_root,
            decision=evaluated["decision"],
            reason_code=evaluated.get("reason_code") or "policy_denied",
            reason_text=evaluated.get("reason_text") or "policy denied",
            exact_blocker=evaluated.get("exact_blocker"),
            checked_operations=expected_checked,
            matched_rule_id=expected_matched,
            rollback_readiness_verified=expected_rollback_verified,
            event_timestamp=evaluated.get("event_timestamp"),
            sequence_index=int(evaluated.get("sequence_index", 1)),
            verified_source_hash=genuine_source_hash,
        )
    _validate_bound_policy_decision(
        owned=owned,
        decision=decision,
        selected_path=selected_path,
        expected_request=final_request,
        expected_rollback=rollback,
        expected_policy_hash=decision.get("policy_hash"),
    )
    return decision


def _base_result() -> dict[str, Any]:
    return {
        "schema_name": RESULT_SCHEMA_NAME,
        "result": "blocked",
        "exact_blocker": None,
        "policy_decision": None,
        "eligible_for_separate_approval": False,
        "repository_root": None,
        "selected_path": None,
        "head_oid": None,
        "object_format": None,
        "supported_git_ref_storage_backend": SUPPORTED_GIT_REF_STORAGE_BACKEND,
        "git_ref_storage_backend": None,
        "git_ref_storage_backend_verified": False,
        "git_ref_storage_backend_evidence_source": None,
        "git_reftable_supported": False,
        "git_reftable_path_absent_required": True,
        "git_reftable_symlink_blocked": True,
        "external_reftable_storage_used": False,
        "external_ref_storage_content_packaged": False,
        "unknown_repository_extensions_supported": False,
        "baseline_blob_oid": None,
        "baseline_content_sha256": None,
        "proposed_content_sha256": None,
        "source_surface_mode": SOURCE_SURFACE_MODE,
        "full_repository_hash_verified": False,
        "full_repository_governance_claim_allowed": False,
        "request_path": None,
        "rollback_artifact_path": None,
        "provenance_path": None,
        "preview_path": None,
        "decision_path": None,
        "output_checksum_path": None,
        "completion_path": None,
        "cleanup_succeeded": None,
        "cleanup_ownership_lost": False,
        "adapter_owned_output_may_be_orphaned": False,
        "primary_blocker": None,
        "automatic_nonempty_failure_cleanup_performed": False,
        "cleanup_intentionally_not_attempted": False,
        "incomplete_staging_reported_when_preserved": False,
        "incomplete_staging_path": None,
        "incomplete_output_ownership_id": None,
        "incomplete_marker_written": False,
        "incomplete_marker_suppressed_due_completion_record": False,
        "hidden_sealed_bundle_preserved": False,
        "requested_final_output_present_after_failed_seal": False,
        "requested_final_output_is_adapter_owned": False,
        "requested_final_output_present_at_return": False,
        "requested_final_output_presence_known_at_return": False,
        "requested_final_output_is_adapter_owned_at_return": False,
        "requested_final_output_ownership_verified_at_return": False,
        "requested_final_output_root_identity": None,
        "unowned_replacement_detected": False,
        "unowned_replacement_path": None,
        "output_entries_deleted": [],
        "unowned_output_content_deleted": False,
        "output_parent_identity_preserved": False,
        "output_tree_binding_preserved": False,
        "output_bundle_exact_file_set_verified": False,
        "output_bundle_unknown_entries": [],
        "output_bundle_missing_entries": [],
        "output_bundle_type_mismatches": [],
        "output_bundle_symlink_entries": [],
        "output_bundle_hardlink_entries": [],
        "output_bundle_checksum_coverage_exact": False,
        "output_bundle_sealed": False,
        "hidden_bundle_exact_set_verified_before_publication": False,
        "publication_operation_completed": False,
        "published_bundle_exact_set_verified": False,
        "published_bundle_checksum_coverage_exact": False,
        "caller_visible_bundle_path_bound_at_return": False,
        "output_bundle_valid_at_return": False,
        "output_bundle_unknown_entries_at_return": [],
        "output_bundle_missing_entries_at_return": [],
        "output_bundle_type_mismatches_at_return": [],
        "output_bundle_symlink_entries_at_return": [],
        "output_bundle_hardlink_entries_at_return": [],
        "bundle_verification_location_binding": "same_location_instance",
        "bundle_portable_across_copy_or_rename": False,
        "bundle_contains_local_absolute_paths": True,
        "output_bundle_sealed_meaning": None,
        "bundle_exact_set_verified_at_return": False,
        "bundle_verification_required_at_consumption": True,
        "bundle_immutable_after_return_claim_allowed": False,
        "concurrent_same_user_tamper_prevention_claim_allowed": False,
        "tamper_evident_storage_claim_allowed": False,
        "completion_record_present": False,
        "completion_record_authoritative_at_return": False,
        "hidden_completion_record_present": False,
        "completion_requires_intended_final_binding": True,
        "publication_transition_attempted": False,
        "publication_transition_succeeded": False,
        "publication_final_action": None,
        "post_publication_hook_calls": 0,
        "post_publication_bundle_accesses": 0,
        "bundle_consumer_verifiable": True,
        "bundle_verification_contract_version": 1,
        "bundle_valid_only_when_strict_verifier_currently_passes": True,
        "bundle_immutable": False,
        "bundle_tamper_prevention_provided": False,
        "future_bundle_mutation_prevented": False,
        "post_publication_verification_performed": False,
        "post_publication_bundle_verified": False,
        "post_publication_cleanup_performed": False,
        "repository_worktree_unchanged": False,
        "git_index_unchanged": False,
        "head_unchanged": False,
        "refs_unchanged_where_checked": False,
        "config_unchanged_where_checked": False,
        "no_git_locks_created": False,
        "repository_files_created": [],
        "repository_files_removed": [],
        "repository_files_changed": [],
        "approval_artifact_created": False,
        "mutation_applied": False,
        "commit_created": False,
        "push_performed": False,
        "repository_identity_authenticated": False,
        "remote_identity_verified": False,
        "head_signature_verified": False,
        "declared_actor_identity_authenticated": False,
        "provider_calls": 0,
        "advisor_calls": 0,
        "mem0_runs": 0,
        "benchmark_runs": 0,
        "network_calls": None,
        "git_network_commands": 0,
        "repository_configured_external_helpers_executed": 0,
        "runtime_network_access_observed": 0,
        "external_process_execution_blocked_by_configuration_policy": True,
        "content_sensitive_git_exec_sandbox_enforced": False,
        "content_sensitive_git_sandbox_backend": None,
        "content_sensitive_git_sandboxed_command_count": 0,
        "status_uses_sanitized_local_config_view": False,
        "git_metadata_descriptor_boundary_enforced": False,
        "git_metadata_direct_dot_git_only": True,
        "git_external_object_database_supported": False,
        "git_replace_objects_disabled": True,
        "git_metadata_roots_bound": [],
        "git_object_root_inside_repository": False,
        "git_object_root_symlink_detected": False,
        "git_metadata_root_symlink_detected": False,
        "external_object_database_used": False,
        "external_baseline_content_packaged": False,
    }


def _adapt_git_diff_core(
    *,
    repo_path: Path,
    policy_path: Path,
    declared_actor_id: str,
    requested_scope: str,
    output_dir: Path,
    event_time: str | None = None,
    max_proposed_file_size: int = MAX_PROPOSED_FILE_SIZE,
) -> dict[str, Any]:
    """Create a governed one-file baseline bundle without mutating the repo."""

    result = _base_result()
    owned_output: OwnedOutputTree | None = None
    output_parent: OutputParentLease | None = None
    internal_temp: InternalTempRootLease | None = None
    metadata_lease: GitMetadataLease | None = None
    preserve_final = False
    try:
        if not isinstance(declared_actor_id, str) or not declared_actor_id.strip():
            _raise("declared_actor_id_missing")
        if not isinstance(requested_scope, str) or not requested_scope.strip():
            _raise("requested_scope_missing")
        if max_proposed_file_size <= 0 or max_proposed_file_size > MAX_PROPOSED_FILE_SIZE:
            _raise("proposed_file_size_limit_invalid")
        repo = _validate_raw_existing_directory(repo_path, prefix="repository")
        from .protected_source_manifest import protected_source_roots

        protected_sources = protected_source_roots()
        if any(_paths_overlap(repo, protected) for protected in protected_sources):
            _raise("repository_candidate_source_overlap_denied")
        policy = _validate_policy_path(policy_path)
        policy_bytes, policy_identity = _bounded_nofollow_file(
            policy, limit=MAX_POLICY_BYTES, prefix="policy"
        )
        if not policy_identity.get("present"):
            _raise("policy_file_missing")
        final_output, output_parent = _validate_output_path(output_dir, repo, protected_sources)
        repository_before_temp = _repository_root_mutation_snapshot(repo)
        internal_temp = InternalTempRootLease.create(
            output_parent,
            repo=repo,
            protected_sources=protected_sources,
            final_output=final_output,
        )
        result.update(
            {
                "internal_temp_root_policy": "descriptor_bound_output_parent_random_owned_child",
                "internal_temp_root_environment_derived": False,
                "ambient_tmpdir_trusted": False,
                "internal_temp_root_outside_repository": True,
                "internal_temp_root_outside_git_metadata": True,
                "internal_temp_root_outside_candidate_source": True,
                "internal_temp_root_outside_requested_output": True,
                "repository_temp_entries_created": None,
                "repository_root_metadata_changed_by_temp_workspace": None,
            }
        )
        git_candidate = shutil.which("git")
        if git_candidate is None:
            _raise("git_executable_not_found")
        git = _resolve_git_executable(git_candidate)
        result["output_parent_identity_preserved"] = True
        if OUTPUT_PARENT_TEST_HOOK is not None:
            OUTPUT_PARENT_TEST_HOOK("after_parent_acquired", output_parent)
        result["repository_root"] = str(repo)

        commands: list[list[str]] = []
        runner = GitRunner(git, repo, commands, internal_temp=internal_temp)
        expected_git_dir = repo / ".git"
        metadata_lease = GitMetadataLease.acquire(repo, expected_git_dir)
        runner.metadata_lease = metadata_lease
        result["git_metadata_descriptor_boundary_enforced"] = True
        result["git_metadata_roots_bound"] = list(GitMetadataLease.REQUIRED_ROOTS)
        result["git_object_root_inside_repository"] = True
        preflight_config = _git_config_boundary_snapshot(
            git, repo, metadata_lease, commands, expected_object_format=None
        )
        if preflight_config.get("boundary_blocker"):
            _raise(preflight_config["boundary_blocker"])
        top = Path(_one_line(runner, ["rev-parse", "--show-toplevel"])).resolve(strict=True)
        if top != repo:
            _raise("repository_top_level_mismatch")
        if _one_line(runner, ["rev-parse", "--is-bare-repository"]) != "false":
            _raise("bare_repository_unsupported")
        git_dir = Path(_one_line(runner, ["rev-parse", "--absolute-git-dir"])).resolve(strict=True)
        if not expected_git_dir.exists() or expected_git_dir.is_symlink() or not expected_git_dir.is_dir():
            _raise("linked_worktree_or_submodule_unsupported")
        if git_dir != expected_git_dir.resolve(strict=True):
            _raise("linked_worktree_or_submodule_unsupported")
        probe = _git_metadata_snapshot(repo, git_dir, runner, None, max_file_size=max_proposed_file_size)
        probe_record = _supported_record_from_snapshot(probe)
        selected_path = probe_record["path"]
        candidate = _git_metadata_snapshot(
            repo, git_dir, runner, selected_path, max_file_size=max_proposed_file_size
        )
        candidate_record = _supported_record_from_snapshot(candidate)
        probe_created, probe_removed, probe_changed = _derive_inventory_changes(
            _acceptance_inventory(probe), _acceptance_inventory(candidate)
        )
        if probe_record != candidate_record or probe_created or probe_removed or probe_changed:
            result["repository_files_created"] = probe_created
            result["repository_files_removed"] = probe_removed
            result["repository_files_changed"] = probe_changed or ["repository:candidate_status_record"]
            _raise("repository_state_changed_before_acceptance")
        if STATUS_SNAPSHOT_TEST_HOOK is not None:
            STATUS_SNAPSHOT_TEST_HOOK(repo)
        try:
            before = _git_metadata_snapshot(
                repo, git_dir, runner, selected_path, max_file_size=max_proposed_file_size
            )
            accepted_record = _supported_record_from_snapshot(before)
        except GitAdapterError as exc:
            result["pre_acceptance_detail"] = str(exc)
            if "before" in locals():
                caught_created, caught_removed, caught_changed = _derive_inventory_changes(
                    _acceptance_inventory(candidate), _acceptance_inventory(before)
                )
                result["repository_files_created"] = caught_created
                result["repository_files_removed"] = caught_removed
                result["repository_files_changed"] = caught_changed or ["repository:accepted_snapshot_capture"]
            else:
                result["repository_files_changed"] = ["repository:accepted_snapshot_capture"]
            _raise("repository_state_changed_before_acceptance")
        candidate_inventory = _acceptance_inventory(candidate)
        accepted_inventory = _acceptance_inventory(before)
        pre_created, pre_removed, pre_changed = _derive_inventory_changes(
            candidate_inventory, accepted_inventory
        )
        if candidate_record != accepted_record or pre_created or pre_removed or pre_changed:
            result["repository_files_created"] = pre_created
            result["repository_files_removed"] = pre_removed
            result["repository_files_changed"] = pre_changed or ["repository:accepted_status_record"]
            _raise("repository_state_changed_before_acceptance")
        record = accepted_record
        result.update(
            {
                "selected_path": selected_path,
                "head_oid": before["head_oid"],
                "object_format": before["object_format"],
                "git_ref_storage_backend": before["git_ref_storage_backend"],
                "git_ref_storage_backend_verified": before[
                    "git_ref_storage_backend_proof"
                ]["verified"],
                "git_ref_storage_backend_evidence_source": before[
                    "git_ref_storage_backend_proof"
                ]["evidence_source"],
                "baseline_blob_oid": before["baseline_blob_oid"],
            }
        )
        if before["head_file_mode"] != record["head_mode"] or record["head_mode"] != record["index_mode"]:
            _raise("git_mode_or_index_state_mismatch")
        if before["head_file_mode"] != before["working_tree_mode"] or record["worktree_mode"] != before["working_tree_mode"]:
            _raise("executable_or_file_mode_change_unsupported")
        if before["baseline_blob_oid"] != record["head_oid"] or record["head_oid"] != record["index_oid"]:
            _raise("index_or_blob_identity_mismatch")
        selected_index = before["index_state"]["entries"].get(selected_path)
        if selected_index is None:
            _raise("selected_path_missing_from_index_state")
        if selected_index["stage"] != 0:
            _raise("nonzero_index_stage_unsupported")
        if selected_index["mode"] != record["index_mode"] or selected_index["oid"] != record["index_oid"]:
            _raise("index_state_porcelain_mismatch")
        proof_before = _proof_inventory(before)

        blob_size_text = _one_line(runner, ["cat-file", "-s", before["baseline_blob_oid"]])
        try:
            blob_size = int(blob_size_text, 10)
        except ValueError:
            _raise("baseline_blob_size_invalid")
        if blob_size < 0:
            _raise("baseline_blob_size_invalid")
        if blob_size > max_proposed_file_size:
            _raise("baseline_blob_size_limit_exceeded")
        baseline_bytes = runner.run(
            ["cat-file", "blob", before["baseline_blob_oid"]],
            max_stdout=max_proposed_file_size + 1,
        )
        if len(baseline_bytes) != blob_size:
            _raise("baseline_blob_size_mismatch")
        git_blob_hasher = hashlib.new(before["object_format"])
        git_blob_hasher.update(f"blob {len(baseline_bytes)}\0".encode("ascii"))
        git_blob_hasher.update(baseline_bytes)
        if git_blob_hasher.hexdigest() != before["baseline_blob_oid"]:
            _raise("baseline_blob_oid_content_mismatch")
        target = repo / selected_path
        proposed_bytes, proposed_identity = _bounded_regular_file_read(
            target,
            limit=max_proposed_file_size,
            expected_snapshot=before["working_tree_identity"],
            repo_root=repo,
            relative_path=selected_path,
        )
        if b"\0" in baseline_bytes or b"\0" in proposed_bytes:
            _raise("binary_content_unsupported")
        try:
            baseline_text = baseline_bytes.decode("utf-8", errors="strict")
            proposed_text = proposed_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            _raise("utf8_text_required")
        if baseline_bytes == proposed_bytes:
            _raise("working_tree_content_not_modified")
        baseline_hash = sha256_bytes(baseline_bytes)
        proposed_hash = sha256_bytes(proposed_bytes)
        result["baseline_content_sha256"] = baseline_hash
        result["proposed_content_sha256"] = proposed_hash

        assert output_parent is not None
        if OUTPUT_PARENT_TEST_HOOK is not None:
            OUTPUT_PARENT_TEST_HOOK("before_staging_creation", output_parent)
        output_parent.revalidate("immediately_before_staging_creation")
        staging_name = f".{final_output.name}.clu-git-adapt-{uuid.uuid4().hex}"
        owned_output = OwnedOutputTree.create(output_parent, staging_name, selected_path)
        output_parent.refresh_after_owned_parent_mutation()
        owned_output._write_marker()
        owned_output.barrier("after_staging_creation")
        if OUTPUT_OWNERSHIP_TEST_HOOK is not None:
            OUTPUT_OWNERSHIP_TEST_HOOK("after_staging_created", owned_output)
        owned_output.barrier("after_staging_created_hook")
        for directory in sorted(
            owned_output.allowed_dirs - {""}, key=lambda value: (value.count("/"), value)
        ):
            owned_output.mkdir_relative(directory)
        owned_output.write_bytes_once(
            f"baseline_source/{selected_path}", baseline_bytes, mode=0o644
        )
        baseline_root = owned_output.path / "baseline_source"
        snapshot_seed = gate.canonical_sha256(
            {"head_oid": before["head_oid"], "path": selected_path, "baseline_sha256": baseline_hash}
        )[:20]
        rollback = {
            "schema_name": gate.ROLLBACK_SCHEMA_NAME,
            "schema_version": "1",
            "snapshot_id": f"git-adapt-{snapshot_seed}",
            "files": {
                selected_path: {
                    "path": selected_path,
                    "before_sha256": baseline_hash,
                    "original_content": baseline_text,
                    "content_encoding": "utf-8",
                }
            },
        }
        owned_output.write_json_once("rollback_snapshot.json", rollback)
        proposal = {
            "description": "Adapt one tracked unstaged UTF-8 text modification for local governance evaluation.",
            "proposed_utf8_content": proposed_text,
            "selected_path": selected_path,
            "head_commit_oid": before["head_oid"],
            "baseline_blob_oid": before["baseline_blob_oid"],
            "baseline_content_sha256": baseline_hash,
            "proposed_content_sha256": proposed_hash,
            "source_surface_mode": SOURCE_SURFACE_MODE,
            "full_repository_hash_verified": False,
        }
        identity_seed = gate.canonical_sha256(
            {
                "head": before["head_oid"], "path": selected_path,
                "proposed": proposed_hash, "actor": declared_actor_id, "scope": requested_scope,
            }
        )[:20]

        def make_request(rollback_absolute: Path) -> dict[str, Any]:
            owned_output.barrier("request_source_hash")
            source_hash = gate.source_tree_hash(baseline_root)
            owned_output.barrier("request_source_hash_complete")
            return {
                "schema_name": gate.REQUEST_SCHEMA_NAME,
                "schema_version": "1",
                "request_id": f"git-adapt-request-{identity_seed}",
                "declared_actor_id": declared_actor_id,
                "actor_identity_source": "caller_declared",
                "requested_scope": requested_scope,
                "proposal_id": f"git-adapt-proposal-{identity_seed}",
                "proposal_body": proposal,
                "proposal_hash": gate.canonical_sha256(proposal),
                "source_tree_hash": source_hash,
                "operations": [{"operation": "modify", "path": selected_path, "before_sha256": baseline_hash}],
                "rollback_readiness": {
                    "schema_name": gate.ROLLBACK_SCHEMA_NAME,
                    "schema_version": "1",
                    "artifact_path": str(rollback_absolute),
                    "artifact_sha256": owned_output.expected_files["rollback_snapshot.json"]["sha256"],
                    "files": {selected_path: {"before_sha256": baseline_hash}},
                },
                "git_provenance": {
                    "head_oid": before["head_oid"],
                    "object_format": before["object_format"],
                    "baseline_blob_oid": before["baseline_blob_oid"],
                    "source_surface_mode": SOURCE_SURFACE_MODE,
                    "repository_identity_authenticated": False,
                    "remote_identity_verified": False,
                    "head_signature_verified": False,
                },
            }

        final_rollback = final_output / "rollback_snapshot.json"
        final_request = make_request(final_rollback)
        owned_output.write_json_once("source_mutation_request.json", final_request)
        preview = "".join(
            difflib.unified_diff(
                baseline_text.splitlines(keepends=True),
                proposed_text.splitlines(keepends=True),
                fromfile=f"a/{selected_path}@HEAD",
                tofile=f"b/{selected_path}@working-tree",
                lineterm="\n",
            )
        )
        owned_output.write_bytes_once("change_preview.diff", preview.encode("utf-8"), mode=0o644)

        if OUTPUT_OWNERSHIP_TEST_HOOK is not None:
            OUTPUT_OWNERSHIP_TEST_HOOK("before_repository_recheck", owned_output)
        owned_output.barrier("before_repository_recheck")
        if ADAPTER_TEST_HOOK is not None:
            ADAPTER_TEST_HOOK(repo)
        try:
            rechecked = _git_metadata_snapshot(
                repo, git_dir, runner, selected_path, max_file_size=max_proposed_file_size
            )
            rechecked_record = _supported_record_from_snapshot(rechecked)
        except GitAdapterError as exc:
            result["post_acceptance_detail"] = str(exc)
            if "rechecked" in locals():
                caught_created, caught_removed, caught_changed = _derive_inventory_changes(
                    proof_before, _proof_inventory(rechecked)
                )
                result["repository_files_created"] = caught_created
                result["repository_files_removed"] = caught_removed
                result["repository_files_changed"] = caught_changed or ["repository:post_acceptance_snapshot"]
            else:
                result["repository_files_changed"] = ["repository:post_acceptance_snapshot"]
            _raise("repository_state_changed_during_adaptation")
        created, removed, changed = _derive_inventory_changes(proof_before, _proof_inventory(rechecked))
        result["repository_files_created"] = created
        result["repository_files_removed"] = removed
        result["repository_files_changed"] = changed
        if created or removed or changed or rechecked_record != record or not _snapshot_equal(before, rechecked):
            result["network_calls"] = None
            _raise("repository_state_changed_during_adaptation")

        staging_expected = {
            OWNERSHIP_MARKER_NAME,
            f"baseline_source/{selected_path}",
            "rollback_snapshot.json",
            "source_mutation_request.json",
            "change_preview.diff",
        }
        owned_output.verify_exact(staging_expected)
        final_request_path = final_output / "source_mutation_request.json"
        final_decision_path = final_output / "policy_decision.json"
        owned_output.barrier("before_bound_policy_evaluation")
        final_decision = _evaluate_bound_adapter_request(
            owned=owned_output,
            final_request=final_request,
            rollback=rollback,
            selected_path=selected_path,
            policy_bytes=policy_bytes,
            event_time=event_time,
            internal_temp=internal_temp,
        )
        owned_output.barrier("after_bound_policy_evaluation")
        owned_output.write_json_once("policy_decision.json", final_decision)
        owned_output.barrier("after_policy_decision_write")
        observed_decision = _read_owned_json(owned_output, "policy_decision.json")
        if observed_decision != final_decision:
            _raise("generated_policy_decision_genuine_artifact_binding_failed")
        _validate_bound_policy_decision(
            owned=owned_output,
            decision=observed_decision,
            selected_path=selected_path,
            expected_request=final_request,
            expected_rollback=rollback,
            expected_policy_hash=final_decision.get("policy_hash"),
        )
        owned_output.barrier("after_policy_decision_verification")
        try:
            final_state = _git_metadata_snapshot(
                repo, git_dir, runner, selected_path, max_file_size=max_proposed_file_size
            )
            final_record = _supported_record_from_snapshot(final_state)
        except GitAdapterError as exc:
            result["finalization_state_detail"] = str(exc)
            if "final_state" in locals():
                caught_created, caught_removed, caught_changed = _derive_inventory_changes(
                    proof_before, _proof_inventory(final_state)
                )
                result["repository_files_created"] = caught_created
                result["repository_files_removed"] = caught_removed
                result["repository_files_changed"] = caught_changed or ["repository:finalization_snapshot"]
            else:
                result["repository_files_changed"] = ["repository:finalization_snapshot"]
            _raise("repository_state_changed_during_finalization")
        final_created, final_removed, final_changed = _derive_inventory_changes(
            proof_before, _proof_inventory(final_state)
        )
        result["repository_files_created"] = final_created
        result["repository_files_removed"] = final_removed
        result["repository_files_changed"] = final_changed
        if (
            final_created or final_removed or final_changed
            or final_record != record or not _snapshot_equal(before, final_state)
        ):
            _raise("repository_state_changed_during_finalization")
        no_new_locks = set(final_state["lock_files"]) == set(before["lock_files"])
        if not no_new_locks:
            _raise("git_lock_file_created")
        worktree_unchanged = (
            final_state["working_tree_identity"] == before["working_tree_identity"]
            and final_state["porcelain_v2_status_sha256"] == before["porcelain_v2_status_sha256"]
            and final_record == record
        )
        index_unchanged = (
            final_state["index_sha256"] == before["index_sha256"]
            and final_state["index_state"] == before["index_state"]
        )
        head_unchanged = final_state["head_oid"] == before["head_oid"]
        refs_unchanged = final_state["refs_sha256"] == before["refs_sha256"]
        config_unchanged = (
            final_state["config_sha256"] == before["config_sha256"]
            and final_state["config_boundary"] == before["config_boundary"]
        )
        policy_after_bytes, policy_after_identity = _bounded_nofollow_file(
            policy, limit=MAX_POLICY_BYTES, prefix="policy"
        )
        if policy_after_bytes != policy_bytes or policy_after_identity != policy_identity:
            _raise("policy_changed_during_adaptation")

        provenance = {
            "schema_name": PROVENANCE_SCHEMA_NAME,
            "schema_version": "1",
            "contract_version": CONTRACT_VERSION,
            "supported_change_mode": SUPPORTED_CHANGE_MODE,
            "repository_root": str(repo),
            "git_version": _git_version(git, metadata_lease),
            "object_format": before["object_format"],
            "supported_git_ref_storage_backend": SUPPORTED_GIT_REF_STORAGE_BACKEND,
            "git_ref_storage_backend": before["git_ref_storage_backend"],
            "git_ref_storage_backend_verified": before[
                "git_ref_storage_backend_proof"
            ]["verified"],
            "git_ref_storage_backend_evidence_source": before[
                "git_ref_storage_backend_proof"
            ]["evidence_source"],
            "git_reftable_supported": False,
            "git_reftable_path_absent_required": True,
            "external_reftable_storage_used": False,
            "external_ref_storage_content_packaged": False,
            "unknown_repository_extensions_supported": False,
            "head_oid": before["head_oid"],
            "branch_name": before["branch_name"],
            "detached_head": before["detached_head"],
            "selected_path": selected_path,
            "head_file_mode": before["head_file_mode"],
            "baseline_blob_oid": before["baseline_blob_oid"],
            "baseline_blob_size": blob_size,
            "baseline_content_sha256": baseline_hash,
            "working_tree_content_sha256": proposed_hash,
            "working_tree_mode": before["working_tree_mode"],
            "working_tree_size": before["working_tree_size"],
            "porcelain_v2_status_sha256": before["porcelain_v2_status_sha256"],
            "index_path": before["index_path"],
            "index_sha256_before": before["index_sha256"],
            "index_sha256_after": final_state["index_sha256"],
            "index_state_sha256_before": before["index_state"]["raw_sha256"],
            "index_state_sha256_after": final_state["index_state"]["raw_sha256"],
            "tracked_index_path_count": before["index_state"]["tracked_path_count"],
            "refs_sha256_before": before["refs_sha256"],
            "refs_sha256_after": final_state["refs_sha256"],
            "config_sha256_before": before["config_sha256"],
            "config_sha256_after": final_state["config_sha256"],
            "lock_files_before": before["lock_files"],
            "lock_files_after": final_state["lock_files"],
            "change_preview_sha256": owned_output.expected_files["change_preview.diff"]["sha256"],
            "git_commands": commands,
            "git_shell_execution_used": False,
            "git_hooks_executed": False,
            "git_external_diff_executed": False,
            "git_textconv_executed": False,
            "git_network_commands": 0,
            "repository_configured_external_helpers_executed": 0,
            "runtime_network_access_observed": 0,
            "external_process_execution_blocked_by_configuration_policy": True,
            "content_sensitive_git_exec_sandbox_enforced": runner.sandboxed_content_sensitive_commands > 0,
            "content_sensitive_git_sandbox_backend": "macos_sandbox_exec_network_and_non_git_descendant_exec_deny",
            "content_sensitive_git_sandboxed_command_count": runner.sandboxed_content_sensitive_commands,
            "status_uses_sanitized_local_config_view": True,
            "repository_config_read_with_typed_git_semantics": True,
            "repository_filter_driver_config_supported": False,
            "git_no_lazy_fetch_enforced": True,
            "git_environment_inheritance_bounded": True,
            "git_subprocess_output_capped_during_execution": True,
            "git_metadata_descriptor_boundary_enforced": True,
            "git_metadata_direct_dot_git_only": True,
            "git_external_object_database_supported": False,
            "git_replace_objects_disabled": True,
            "git_metadata_roots_bound": list(GitMetadataLease.REQUIRED_ROOTS),
            "git_object_root_inside_repository": True,
            "git_object_root_symlink_detected": False,
            "git_metadata_root_symlink_detected": False,
            "external_object_database_used": False,
            "external_baseline_content_packaged": False,
            "partial_or_promisor_repository_supported": False,
            "repository_config_includes_supported": False,
            "assume_unchanged_index_entries_supported": False,
            "skip_worktree_index_entries_supported": False,
            "sparse_checkout_or_sparse_index_supported": False,
            "accepted_snapshot_status_independently_parsed": True,
            "candidate_and_accepted_snapshot_records_match": True,
            "selected_path_parent_components_no_follow_verified": True,
            "output_parent_directory_descriptor_bound": True,
            "output_parent_device_inode_bound": True,
            "recursive_unverified_output_cleanup_used": False,
            "path_based_check_then_unlink_cleanup_used": False,
            "automatic_nonempty_failure_cleanup_performed": False,
            "output_ownership_marker_retained": True,
            "baseline_git_blob_oid_recomputed": True,
            "baseline_git_blob_oid_verified": True,
            "source_surface_mode": SOURCE_SURFACE_MODE,
            "full_repository_hash_verified": False,
            "full_repository_governance_claim_allowed": False,
            "repository_identity_authenticated": False,
            "remote_identity_verified": False,
            "head_signature_verified": False,
            "declared_actor_identity_authenticated": False,
            "policy_decision": final_decision.get("decision"),
            "policy_decision_verified": True,
            "repository_files_created": final_created,
            "repository_files_removed": final_removed,
            "repository_files_changed": final_changed,
            "metadata_inventory_before": before["metadata_inventory"],
            "metadata_inventory_after": final_state["metadata_inventory"],
            "git_index_mutated": False,
            "git_head_mutated": False,
            "git_refs_mutated": False,
            "git_config_mutated": False,
            "git_lock_files_created": False,
            "read_only_proof_scope": "Independently parsed ignored-aware accepted status; selected parent/file device/inode/type/mode/size/hash; exact bounded index state; and a descriptor-bound direct .git inventory covering control files, objects, packs, object info, files-backend refs, and info were compared. The active ref backend was proven as files; reftable, unknown repository extensions, alternates, http-alternates, grafts, info attributes, replace refs, metadata symlinks, and hard-linked metadata are unsupported. Repository-local config was parsed with Git's typed semantics; status used a sanitized detached metadata view and the executed macOS no-descendant-exec/no-network sandbox boundary. No universal hostile-filesystem, operating-system-administrator, malicious-Git-executable, or timestamp-invariance guarantee is claimed outside this inventory.",
        }
        owned_output.write_json_once("git_provenance.json", provenance)
        # All subprocess and private evaluator scratch use is complete. Exact,
        # ownership-bound scratch cleanup must succeed before publication.
        internal_temp.finalize()
        result["internal_temp_root_cleanup_verified"] = True
        result["internal_temp_cleanup_ownership_lost"] = False
        repository_after_temp = _repository_root_mutation_snapshot(repo)
        result["repository_temp_entries_created"] = sorted(
            set(repository_after_temp["entries"]) - set(repository_before_temp["entries"])
        )
        result["repository_root_metadata_changed_by_temp_workspace"] = (
            repository_after_temp != repository_before_temp
        )
        if repository_after_temp != repository_before_temp:
            _raise("repository_root_metadata_changed_by_temp_workspace")
        owned_output.barrier("before_checksums")
        if OUTPUT_OWNERSHIP_TEST_HOOK is not None:
            OUTPUT_OWNERSHIP_TEST_HOOK("before_checksums", owned_output)
        owned_output.barrier("after_before_checksums_hook")
        checksum_bytes = _artifact_checksums(owned_output)
        owned_output.write_bytes_once("CHECKSUMS.sha256", checksum_bytes, mode=0o644)
        owned_output.verify_exact(set(owned_output.payload_files) | {"CHECKSUMS.sha256"})
        if not _verify_artifact_checksums(owned_output):
            _raise("output_bundle_checksum_verification_failed")
        result["output_bundle_checksum_coverage_exact"] = True
        if OUTPUT_OWNERSHIP_TEST_HOOK is not None:
            OUTPUT_OWNERSHIP_TEST_HOOK("after_checksums_before_completion", owned_output)
        owned_output.barrier("after_checksums_before_completion_hook")
        owned_output.verify_exact(set(owned_output.payload_files) | {"CHECKSUMS.sha256"})
        if not _verify_artifact_checksums(owned_output):
            _raise("output_bundle_checksum_verification_failed")
        completion_path = final_output / "BUNDLE_COMPLETE.json"
        allowlist_descriptor = {
            "directories": sorted(owned_output.allowed_dirs),
            "files": sorted(owned_output.allowed_files),
            "checksum_payload_files": sorted(owned_output.payload_files),
        }
        completion_payload = {
            "schema_name": "clu_governance_git_adapter_bundle_completion.v4",
            "bundle_complete": True,
            "seal_version": 1,
            "bundle_verification_contract_version": 1,
            "bundle_valid_only_when_strict_verifier_currently_passes": True,
            "bundle_immutable": False,
            "bundle_tamper_prevention_provided": False,
            "ownership_id": owned_output.ownership_id,
            "selected_path": selected_path,
            "allowlist": allowlist_descriptor,
            "allowlist_sha256": gate.canonical_sha256(allowlist_descriptor),
            "checksum_record_count": len(owned_output.payload_files),
            "checksums_sha256": owned_output.expected_files["CHECKSUMS.sha256"]["sha256"],
            "policy_decision_verified": True,
            "completion_requires_intended_final_binding": True,
            "intended_final_name": owned_output.final_name,
            "intended_parent_device": owned_output.parent.identity["device"],
            "intended_parent_inode": owned_output.parent.identity["inode"],
            "owned_root_device": owned_output.root_device,
            "owned_root_inode": owned_output.root_inode,
            "hidden_staging_completion_claim_valid": False,
        }
        if OUTPUT_OWNERSHIP_TEST_HOOK is not None:
            OUTPUT_OWNERSHIP_TEST_HOOK("before_completion", owned_output)
        owned_output.barrier("immediately_before_completion")
        owned_output.write_json_once("BUNDLE_COMPLETE.json", completion_payload)
        owned_output.completion_written = True
        result["hidden_completion_record_present"] = True
        if not _verify_artifact_checksums(owned_output):
            _raise("output_bundle_checksum_verification_failed")
        observed_completion = _read_owned_completion_json(owned_output)
        if observed_completion != completion_payload:
            _raise("output_bundle_completion_record_invalid")
        owned_output.barrier("before_final_exact_seal")
        if OUTPUT_OWNERSHIP_TEST_HOOK is not None:
            OUTPUT_OWNERSHIP_TEST_HOOK("before_final_seal", owned_output)
        owned_output.barrier("after_before_final_seal_hook")
        if not owned_output.parent.final_absent():
            _raise("output_path_must_not_exist")
        try:
            publication_parent_chain = AbsoluteDirectoryChainLease.acquire(
                output_parent.raw_parent, phase="pre_publication"
            )
        except PathChainError:
            _raise("output_parent_identity_changed")
        if OUTPUT_OWNERSHIP_TEST_HOOK is not None:
            OUTPUT_OWNERSHIP_TEST_HOOK("before_publication_rename", owned_output)
        # A newly occupied destination is a precise namespace collision, not a
        # generic parent-identity race.  Check it before comparing the temporal
        # parent-chain snapshot, while the retained parent descriptor remains
        # authoritative for the lookup.
        if not owned_output.parent.final_absent():
            publication_parent_chain.close()
            _raise("output_path_must_not_exist")
        try:
            publication_rebind = publication_parent_chain.fresh_rebind(
                phase="post_publication_hook"
            )
            publication_rebind.close()
        except PathChainError:
            _raise("output_parent_identity_changed")
        finally:
            publication_parent_chain.close()
        owned_output.barrier("after_before_publication_rename_hook")
        if not owned_output.parent.final_absent():
            _raise("output_path_must_not_exist")
        allowed = final_decision.get("decision") == "allow"
        success_result = dict(result)
        success_result.update(
            {
                "result": "adapted" if allowed else "policy_denied",
                "exact_blocker": None if allowed else final_decision.get("exact_blocker", "policy_denied"),
                "policy_decision": final_decision.get("decision"),
                "eligible_for_separate_approval": allowed,
                "request_path": str(final_request_path),
                "rollback_artifact_path": str(final_output / "rollback_snapshot.json"),
                "provenance_path": str(final_output / "git_provenance.json"),
                "preview_path": str(final_output / "change_preview.diff"),
                "decision_path": str(final_decision_path),
                "output_checksum_path": str(final_output / "CHECKSUMS.sha256"),
                "completion_path": str(completion_path),
                "_adapter_owned_root_identity": {
                    "device": owned_output.root_device,
                    "inode": owned_output.root_inode,
                    "mode": stat.S_IMODE(os.fstat(owned_output.root_fd).st_mode),
                },
                "completion_record_present": True,
                "hidden_completion_record_present": False,
                "repository_worktree_unchanged": worktree_unchanged,
                "git_index_unchanged": index_unchanged,
                "head_unchanged": head_unchanged,
                "refs_unchanged_where_checked": refs_unchanged,
                "config_unchanged_where_checked": config_unchanged,
                "no_git_locks_created": no_new_locks,
                "repository_files_created": final_created,
                "repository_files_removed": final_removed,
                "repository_files_changed": final_changed,
                "network_calls": 0,
                "output_parent_identity_preserved": True,
                "output_tree_binding_preserved": True,
                "output_bundle_exact_file_set_verified": True,
                "output_bundle_unknown_entries": [],
                "output_bundle_missing_entries": [],
                "output_bundle_type_mismatches": [],
                "output_bundle_symlink_entries": [],
                "output_bundle_hardlink_entries": [],
                "output_bundle_checksum_coverage_exact": True,
                "output_bundle_sealed": True,
                "hidden_sealed_bundle_preserved": False,
                "cleanup_intentionally_not_attempted": True,
                "completion_requires_intended_final_binding": True,
                "publication_transition_attempted": True,
                "publication_transition_succeeded": True,
                "publication_final_action": "descriptor_relative_no_replace_directory_rename",
                "post_publication_hook_calls": 0,
                "post_publication_bundle_accesses": 1,
                "bundle_verification_contract_version": 1,
                "bundle_valid_only_when_strict_verifier_currently_passes": True,
                "bundle_immutable": False,
                "bundle_tamper_prevention_provided": False,
                "future_bundle_mutation_prevented": False,
                "content_sensitive_git_exec_sandbox_enforced": runner.sandboxed_content_sensitive_commands > 0,
                "content_sensitive_git_sandbox_backend": "macos_sandbox_exec_network_and_non_git_descendant_exec_deny",
                "content_sensitive_git_sandboxed_command_count": runner.sandboxed_content_sensitive_commands,
                "status_uses_sanitized_local_config_view": True,
            }
        )
        # All hooks, reads, checks, and result allocation precede the exact
        # seal. The descriptor-relative no-replace rename is the next and final
        # fallible filesystem action.
        owned_output.verify_exact(set(owned_output.allowed_files))
        # The hidden candidate has passed the exact seal, but the caller-visible
        # bundle is not sealed/published unless the next rename succeeds.
        owned_output.sealed = True
        result["publication_transition_attempted"] = True
        owned_output.publish_final_action()
        # The tree is now caller-visible, but publication does not make it
        # immutable. Preserve it on every later outcome: strict verification
        # observes the published name and never cleans questionable content.
        preserve_final = True
        from .bundle_verifier import verify_bundle

        verification = verify_bundle(final_output)
        success_result["post_publication_verification_performed"] = True
        success_result["post_publication_bundle_verified"] = (
            verification.get("verified") is True
        )
        success_result["post_publication_verification_result"] = verification
        success_result["publication_result_before_consumer_verification"] = (
            success_result["result"]
        )
        success_result["post_publication_cleanup_performed"] = False
        if verification.get("verified") is True:
            success_result["bundle_exact_set_verified_at_return"] = True
            success_result["output_bundle_sealed_meaning"] = (
                "strict verifier passed at return; self-verifiable integrity metadata; "
                "not immutability or tamper prevention"
            )
        else:
            defensive_failure = verification.get("result") == "failed"
            success_result["result"] = "failed" if defensive_failure else "blocked"
            success_result["exact_blocker"] = (
                "post_publication_bundle_verification_failed:"
                f"{verification.get('exact_blocker') or 'unknown'}"
            )
            success_result["primary_blocker"] = success_result["exact_blocker"]
            success_result["eligible_for_separate_approval"] = False
            success_result["output_bundle_sealed"] = False
            success_result["bundle_exact_set_verified_at_return"] = False
            success_result["output_bundle_sealed_meaning"] = None
            success_result["output_bundle_unknown_entries"] = list(
                verification.get("unknown_entries") or []
            )
            success_result["output_bundle_missing_entries"] = list(
                verification.get("missing_entries") or []
            )
            success_result["output_bundle_symlink_entries"] = list(
                verification.get("symlink_entries") or []
            )
            success_result["output_bundle_hardlink_entries"] = list(
                verification.get("hardlink_entries") or []
            )
            success_result["output_bundle_type_mismatches"] = list(
                verification.get("nonregular_entries") or []
            )
        return success_result
    except GitAdapterError as exc:
        if "runner" in locals():
            result["content_sensitive_git_exec_sandbox_enforced"] = (
                runner.sandboxed_content_sensitive_commands > 0
            )
            result["content_sensitive_git_sandbox_backend"] = (
                "macos_sandbox_exec_network_and_non_git_descendant_exec_deny"
            )
            result["content_sensitive_git_sandboxed_command_count"] = (
                runner.sandboxed_content_sensitive_commands
            )
            result["status_uses_sanitized_local_config_view"] = (
                runner.sandboxed_content_sensitive_commands > 0
            )
        result["exact_blocker"] = str(exc)
        result["primary_blocker"] = str(exc)
        root_symlink_blockers = {
            "git_metadata_root_symlink_denied",
            "git_object_root_symlink_denied",
            "git_object_pack_root_symlink_denied",
            "git_object_info_root_symlink_denied",
            "git_refs_root_symlink_denied",
            "git_info_root_symlink_denied",
        }
        if str(exc) in root_symlink_blockers:
            result["git_metadata_root_symlink_detected"] = True
        if str(exc) == "git_object_root_symlink_denied":
            result["git_object_root_symlink_detected"] = True
        if str(exc) == "output_parent_identity_changed":
            result["output_parent_identity_preserved"] = False
        if owned_output is not None and owned_output.last_seal_report:
            report = owned_output.last_seal_report
            result["output_bundle_unknown_entries"] = report.get("unknown_entries", [])
            result["output_bundle_missing_entries"] = report.get("missing_entries", [])
            result["output_bundle_type_mismatches"] = report.get("type_mismatches", []) + report.get("changed_entries", [])
            result["output_bundle_symlink_entries"] = report.get("symlink_entries", [])
            result["output_bundle_hardlink_entries"] = report.get("hardlink_entries", [])
        pack_change = any(
            "objects/pack/" in path
            for key in ("repository_files_created", "repository_files_removed", "repository_files_changed")
            for path in result.get(key, [])
        )
        if result.get("network_calls") is None and not pack_change:
            result["network_calls"] = 0
        return result
    except Exception as exc:  # Defensive library boundary; never expose paths or traceback.
        parent_changed = False
        if output_parent is not None:
            try:
                output_parent.revalidate("defensive_failure_classification")
            except GitAdapterError:
                parent_changed = True
        result["exact_blocker"] = (
            "output_parent_identity_changed"
            if parent_changed
            else f"adapter_runtime_failure:{type(exc).__name__}"
        )
        result["primary_blocker"] = result["exact_blocker"]
        if parent_changed:
            result["output_parent_identity_preserved"] = False
        if result.get("network_calls") is None:
            result["network_calls"] = 0
        return result
    finally:
        if internal_temp is not None:
            if not internal_temp.finalized:
                try:
                    internal_temp.finalize()
                    result["internal_temp_root_cleanup_verified"] = True
                    result["internal_temp_cleanup_ownership_lost"] = False
                    result["internal_temp_orphaned_path"] = None
                except (GitAdapterError, OSError):
                    result["internal_temp_root_cleanup_verified"] = False
                    result["internal_temp_cleanup_ownership_lost"] = True
                    result["internal_temp_orphaned_path"] = str(internal_temp.path)
            internal_temp.close()
        if "repository_before_temp" in locals():
            try:
                final_repo_temp = _repository_root_mutation_snapshot(repo)
                result["repository_temp_entries_created"] = sorted(
                    set(final_repo_temp["entries"])
                    - set(repository_before_temp["entries"])
                )
                result["repository_root_metadata_changed_by_temp_workspace"] = (
                    final_repo_temp != repository_before_temp
                )
            except OSError:
                result["repository_temp_entries_created"] = None
                result["repository_root_metadata_changed_by_temp_workspace"] = None
        if owned_output is not None and not preserve_final:
            if OUTPUT_OWNERSHIP_TEST_HOOK is not None:
                try:
                    OUTPUT_OWNERSHIP_TEST_HOOK("on_failure_before_disposition", owned_output)
                except Exception:
                    pass
            disposition = owned_output.preserve_failure(result.get("primary_blocker"))
            result.update(disposition)
            result["cleanup_succeeded"] = False
            result["cleanup_ownership_lost"] = not disposition.get("output_tree_binding_preserved", False)
        if owned_output is not None:
            owned_output.close()
        if output_parent is not None:
            output_parent.close()
        if metadata_lease is not None:
            metadata_lease.close()


def adapt_git_diff(
    *,
    repo_path: Path,
    policy_path: Path,
    declared_actor_id: str,
    requested_scope: str,
    output_dir: Path,
    event_time: str | None = None,
    max_proposed_file_size: int = MAX_PROPOSED_FILE_SIZE,
) -> dict[str, Any]:
    """Run the adapter and derive one final caller-visible result observation."""

    result = _adapt_git_diff_core(
        repo_path=repo_path,
        policy_path=policy_path,
        declared_actor_id=declared_actor_id,
        requested_scope=requested_scope,
        output_dir=output_dir,
        event_time=event_time,
        max_proposed_file_size=max_proposed_file_size,
    )
    expected_root = result.pop("_adapter_owned_root_identity", None)
    raw_output = absolute_raw_path(output_dir)
    presence_known = False
    present = False
    result["publication_operation_completed"] = bool(
        result.get("publication_transition_succeeded")
    )
    result["hidden_bundle_exact_set_verified_before_publication"] = bool(
        result.get("publication_transition_attempted")
    )
    if result.get("publication_transition_succeeded"):
        result["post_publication_bundle_accesses"] = 2
        result["post_publication_hook_calls"] = 1 if POST_PUBLICATION_PATH_TEST_HOOK else 0

    verification: dict[str, Any] | None = None
    lease: AbsoluteDirectoryChainLease | None = None
    chain_bound = False
    identity_matches = False
    if result.get("publication_transition_succeeded"):
        try:
            lease = AbsoluteDirectoryChainLease.acquire(raw_output, phase="adapter_return_initial")
            observed_root = dict(lease.root_identity)
            result["requested_final_output_root_identity"] = observed_root
            identity_matches = bool(
                isinstance(expected_root, dict)
                and observed_root.get("device") == expected_root.get("device")
                and observed_root.get("inode") == expected_root.get("inode")
                and observed_root.get("mode") == expected_root.get("mode")
            )
            if POST_PUBLICATION_PATH_TEST_HOOK is not None:
                POST_PUBLICATION_PATH_TEST_HOOK(
                    "after_first_verifier_before_final_result", {"path": raw_output, "lease": lease}
                )
            pre_verifier_chain_bound = True
            try:
                fresh = lease.fresh_rebind(phase="adapter_return_pre_verifier")
                fresh.close()
            except PathChainError as exc:
                result["caller_visible_path_probe_blocker"] = str(exc)
                pre_verifier_chain_bound = False
            from .bundle_verifier import verify_bundle

            # This strict verifier is the final filesystem observation on the
            # success path. Result construction below is in-memory only.
            verification = verify_bundle(raw_output)
            verified_root = verification.get("caller_visible_bundle_root_identity")
            identity_matches = bool(
                isinstance(expected_root, dict)
                and isinstance(verified_root, dict)
                and verified_root.get("device") == expected_root.get("device")
                and verified_root.get("inode") == expected_root.get("inode")
                and verified_root.get("mode") == expected_root.get("mode")
            )
            present = verified_root is not None
            presence_known = True
            result["requested_final_output_root_identity"] = verified_root
            chain_bound = bool(
                pre_verifier_chain_bound
                and verification.get("caller_visible_bundle_path_bound_at_return") is True
            )
            if verification.get("verified") is not True:
                identity_matches = False
                try:
                    os.lstat(raw_output)
                    present = True
                    presence_known = True
                except FileNotFoundError:
                    present = False
                    presence_known = True
                except OSError:
                    presence_known = False
        except (PathChainError, OSError) as exc:
            result["caller_visible_path_probe_blocker"] = str(exc)
            chain_bound = False
            identity_matches = False
            try:
                os.lstat(raw_output)
                present = True
                presence_known = True
            except FileNotFoundError:
                present = False
                presence_known = True
            except OSError:
                presence_known = False
    else:
        # Failure paths make one bounded literal observation; it cannot grant
        # integrity success and does not inspect an unowned tree.
        try:
            observed_literal = os.lstat(raw_output)
            present = True
            presence_known = True
            identity_matches = False
        except FileNotFoundError:
            present = False
            presence_known = True
            identity_matches = False
        except OSError:
            presence_known = False
            identity_matches = False
    result["requested_final_output_present_at_return"] = present if presence_known else None
    result["requested_final_output_presence_known_at_return"] = presence_known
    result["requested_final_output_is_adapter_owned_at_return"] = bool(identity_matches)
    result["requested_final_output_ownership_verified_at_return"] = bool(
        present and presence_known and identity_matches and chain_bound
    )
    result["requested_final_output_present_after_failed_seal"] = (
        present if presence_known else False
    )
    result["requested_final_output_is_adapter_owned"] = bool(identity_matches)

    if verification is not None:
        result["post_publication_verification_result"] = verification
        result["output_bundle_unknown_entries_at_return"] = list(
            verification.get("unknown_entries") or []
        )
        result["output_bundle_missing_entries_at_return"] = list(
            verification.get("missing_entries") or []
        )
        result["output_bundle_type_mismatches_at_return"] = list(
            verification.get("nonregular_entries") or []
        )
        result["output_bundle_symlink_entries_at_return"] = list(
            verification.get("symlink_entries") or []
        )
        result["output_bundle_hardlink_entries_at_return"] = list(
            verification.get("hardlink_entries") or []
        )
    verified_now = bool(
        verification is not None
        and verification.get("verified") is True
        and chain_bound
        and identity_matches
    )
    originally_successful = result.get("result") in {"adapted", "policy_denied"}
    final_valid = verified_now and originally_successful
    if originally_successful and not final_valid:
        result["result"] = "blocked"
        result["exact_blocker"] = (
            "caller_visible_bundle_final_verification_failed:"
            + str((verification or {}).get("exact_blocker") or "path_binding_failed")
        )
        result["primary_blocker"] = result["exact_blocker"]
        result["eligible_for_separate_approval"] = False
    result["published_bundle_exact_set_verified"] = final_valid
    result["published_bundle_checksum_coverage_exact"] = final_valid
    result["post_publication_bundle_verified"] = final_valid
    result["caller_visible_bundle_path_bound_at_return"] = final_valid
    result["output_bundle_valid_at_return"] = final_valid
    result["bundle_exact_set_verified_at_return"] = final_valid
    result["output_bundle_exact_file_set_verified"] = final_valid
    result["output_bundle_checksum_coverage_exact"] = final_valid
    result["output_bundle_sealed"] = final_valid
    result["completion_record_authoritative_at_return"] = final_valid
    result["output_bundle_unknown_entries"] = list(
        result["output_bundle_unknown_entries_at_return"]
    )
    result["output_bundle_missing_entries"] = list(
        result["output_bundle_missing_entries_at_return"]
    )
    result["output_bundle_type_mismatches"] = list(
        result["output_bundle_type_mismatches_at_return"]
    )
    result["output_bundle_symlink_entries"] = list(
        result["output_bundle_symlink_entries_at_return"]
    )
    result["output_bundle_hardlink_entries"] = list(
        result["output_bundle_hardlink_entries_at_return"]
    )
    if lease is not None:
        lease.close()
    try:
        validate_adapter_result(result)
    except ResultContractError as exc:
        result["result"] = "blocked"
        result["exact_blocker"] = f"result_contract_inconsistent:{exc}"
        result["primary_blocker"] = result["exact_blocker"]
        for name in (
            "published_bundle_exact_set_verified",
            "published_bundle_checksum_coverage_exact",
            "post_publication_bundle_verified",
            "caller_visible_bundle_path_bound_at_return",
            "output_bundle_valid_at_return",
            "bundle_exact_set_verified_at_return",
            "output_bundle_exact_file_set_verified",
            "output_bundle_checksum_coverage_exact",
            "output_bundle_sealed",
            "completion_record_authoritative_at_return",
        ):
            result[name] = False
        result["requested_final_output_ownership_verified_at_return"] = False
        validate_adapter_result(result)
    return result


def exit_code_for_result(result: dict[str, Any]) -> int:
    if result.get("result") == "adapted" and result.get("policy_decision") == "allow":
        return 0
    if result.get("result") == "failed":
        return 1
    return 2
