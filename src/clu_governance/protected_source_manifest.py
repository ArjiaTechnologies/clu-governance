"""Exact protected-source ownership manifest for CLU Governance.

The manifest deliberately protects only the imported ``clu_governance``
package and, for installed distributions, its own ``.dist-info`` metadata.
It never widens protection to the directory containing those roots.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.metadata as metadata
import json
import os
import posixpath
import re
import stat
import tomllib
from dataclasses import dataclass
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence
from urllib.parse import unquote, urlparse

from . import __version__
from . import strict_json


SCHEMA_NAME = "clu_governance_protected_source_manifest.v1"
SCHEMA_VERSION = "1"
GENERATION_METHOD = "import_surface_plus_distribution_metadata_record_v1"
DIST_NAME = "clu-governance"


class ProtectedSourceManifestError(ValueError):
    """Raised when exact distribution ownership cannot be established."""


def _raise(blocker: str) -> None:
    raise ProtectedSourceManifestError(blocker)


def _normalized_name(value: str) -> str:
    return "-".join(filter(None, re.split(r"[-_.]+", value.lower())))


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _regular_nonsymlink(path: Path, blocker: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        _raise(blocker)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        _raise(blocker)
    return info


def _real_directory(path: Path, blocker: str) -> Path:
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError:
        _raise(blocker)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _raise(blocker)
    return resolved


def _canonical_parent_preserving_leaf(path: Path) -> Path:
    """Canonicalize parents while retaining the final component for lstat."""

    try:
        return path.absolute().parent.resolve(strict=True) / path.name
    except OSError:
        _raise("protected_source_path_invalid")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for parent, dirs, names in os.walk(root, topdown=True, followlinks=False):
        parent_path = Path(parent)
        dirs[:] = sorted(name for name in dirs if name != "__pycache__")
        for directory in dirs:
            child = parent_path / directory
            if child.is_symlink():
                _raise("protected_source_symlink_denied")
        for name in sorted(names):
            if name.endswith((".pyc", ".pyo")):
                continue
            child = parent_path / name
            _regular_nonsymlink(child, "protected_source_file_not_regular")
            files.append(child.resolve(strict=True))
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def _source_package_files(package_root: Path) -> list[Path]:
    files = _tree_files(package_root)
    if not files or package_root / "__init__.py" not in files:
        _raise("protected_source_package_incomplete")
    return files


def _project_metadata(package_root: Path) -> tuple[Path, dict[str, Any]] | None:
    if package_root.parent.name != "src":
        return None
    project_root = package_root.parent.parent
    pyproject = project_root / "pyproject.toml"
    if not pyproject.exists() or pyproject.is_symlink():
        return None
    _regular_nonsymlink(pyproject, "protected_source_pyproject_invalid")
    try:
        parsed = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        project = parsed["project"]
    except Exception:
        _raise("protected_source_pyproject_malformed")
    if not isinstance(project, dict):
        _raise("protected_source_pyproject_malformed")
    if _normalized_name(str(project.get("name", ""))) != DIST_NAME:
        _raise("protected_source_project_name_mismatch")
    return project_root.resolve(strict=True), project


@dataclass(frozen=True)
class _MetadataCandidate:
    """One visible metadata record that might claim this distribution."""

    distribution: Any
    declared_name: str | None
    raw_root: Path | None


def _raw_metadata_root(distribution: Any) -> Path | None:
    raw_root = getattr(distribution, "_path", None)
    if raw_root is None:
        return None
    try:
        return Path(raw_root)
    except (TypeError, ValueError):
        return None


def _matching_distributions(
    distributions: Iterable[Any] | None,
) -> list[_MetadataCandidate]:
    """Collect, but do not yet accept, all CLU metadata candidates.

    A standard setuptools editable install exposes both the active installed
    ``.dist-info`` and the source-adjacent generated ``.egg-info`` through
    ``importlib.metadata``.  The previous implementation treated that normal
    pair as a generic duplicate before either record could be examined.

    A malformed record with a CLU-shaped metadata root is also retained.  It
    must fail closed during classification instead of disappearing merely
    because its headers cannot be parsed.
    """

    visible = metadata.distributions() if distributions is None else distributions
    matches: list[_MetadataCandidate] = []
    for distribution in visible:
        declared_name: str | None = None
        try:
            name = distribution.metadata.get("Name", "")
            if isinstance(name, str):
                declared_name = name
        except Exception:
            pass
        raw_root = _raw_metadata_root(distribution)
        root_name = raw_root.name if raw_root is not None else ""
        shaped_like_clu = (
            root_name == "clu_governance.egg-info"
            or (
                root_name.startswith("clu_governance-")
                and root_name.endswith(".dist-info")
            )
        )
        if (
            isinstance(declared_name, str)
            and _normalized_name(declared_name) == DIST_NAME
        ) or shaped_like_clu:
            matches.append(
                _MetadataCandidate(
                    distribution=distribution,
                    declared_name=declared_name,
                    raw_root=raw_root,
                )
            )
    return matches


def _candidate_root(candidate: _MetadataCandidate) -> Path:
    if candidate.raw_root is None:
        _raise("protected_source_distribution_metadata_ambiguous")
    return _real_directory(
        candidate.raw_root, "protected_source_distribution_metadata_invalid"
    )


def _validate_candidate_identity(candidate: _MetadataCandidate, version: str) -> None:
    """Bind a discovered candidate to this exact normalized name and version."""

    if (
        not isinstance(candidate.declared_name, str)
        or _normalized_name(candidate.declared_name) != DIST_NAME
    ):
        _raise("protected_source_distribution_metadata_malformed")
    try:
        declared_version = candidate.distribution.metadata.get("Version", "")
    except Exception:
        _raise("protected_source_distribution_metadata_malformed")
    if not isinstance(declared_version, str) or not declared_version:
        _raise("protected_source_distribution_metadata_malformed")
    if declared_version != version:
        _raise("protected_source_version_mismatch")


def _distribution_metadata_root(distribution: Any, version: str) -> Path:
    raw_root = getattr(distribution, "_path", None)
    if raw_root is None:
        _raise("protected_source_distribution_metadata_ambiguous")
    root = _real_directory(
        Path(raw_root), "protected_source_distribution_metadata_invalid"
    )
    if root.name != _expected_dist_info_name(version):
        _raise("protected_source_distribution_metadata_invalid")
    try:
        distribution_files = list(distribution.files or [])
    except Exception:
        _raise("protected_source_record_malformed")
    metadata_hits = 0
    record_hits = 0
    for entry in distribution_files:
        entry_name = PurePosixPath(str(entry)).name
        if entry_name not in {"METADATA", "RECORD"}:
            continue
        located = _record_path_for(distribution, str(entry))
        metadata_hits += located == root / "METADATA"
        record_hits += located == root / "RECORD"
    if metadata_hits != 1 or record_hits != 1:
        _raise("protected_source_distribution_metadata_ambiguous")
    return root


def _record_rows(distribution: Any, metadata_root: Path) -> dict[str, tuple[str, str]]:
    record = metadata_root / "RECORD"
    _regular_nonsymlink(record, "protected_source_record_missing_or_invalid")
    rows: dict[str, tuple[str, str]] = {}
    try:
        with record.open("r", encoding="utf-8", newline="") as stream:
            for row in csv.reader(stream):
                if len(row) != 3:
                    _raise("protected_source_record_malformed")
                raw, hash_value, size_value = row
                posix = PurePosixPath(raw)
                if not raw or posix.is_absolute() or "" in posix.parts or "." in posix.parts:
                    _raise("protected_source_record_malformed")
                # Parent traversal is valid for console scripts in wheels, but
                # those paths are outside the protected package/metadata roots.
                if raw in rows:
                    _raise("protected_source_record_duplicate_path")
                if hash_value:
                    if not hash_value.startswith("sha256="):
                        _raise("protected_source_record_hash_unsupported")
                    encoded = hash_value.split("=", 1)[1]
                    try:
                        decoded = base64.b64decode(
                            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
                        )
                    except Exception:
                        _raise("protected_source_record_hash_malformed")
                    if len(decoded) != 32:
                        _raise("protected_source_record_hash_malformed")
                if size_value and (not size_value.isascii() or not size_value.isdecimal()):
                    _raise("protected_source_record_size_malformed")
                rows[raw] = (hash_value, size_value)
    except ProtectedSourceManifestError:
        raise
    except Exception:
        _raise("protected_source_record_malformed")
    if not rows:
        _raise("protected_source_record_malformed")
    return rows


def _record_path_for(distribution: Any, raw: str) -> Path:
    try:
        return _canonical_parent_preserving_leaf(Path(distribution.locate_file(raw)))
    except Exception:
        _raise("protected_source_record_path_invalid")


def _verify_record_file(path: Path, hash_value: str, size_value: str) -> None:
    info = _regular_nonsymlink(path, "protected_source_record_file_invalid")
    if size_value and info.st_size != int(size_value):
        _raise("protected_source_record_size_mismatch")
    if hash_value:
        expected = base64.urlsafe_b64decode(hash_value.split("=", 1)[1] + "=" * (-len(hash_value.split("=", 1)[1]) % 4)).hex()
        if _sha256(path) != expected:
            _raise("protected_source_record_hash_mismatch")


def _editable_project_root(distribution: Any) -> Path | None:
    try:
        raw = distribution.read_text("direct_url.json")
    except Exception:
        _raise("protected_source_direct_url_malformed")
    if raw is None:
        return None
    try:
        payload = strict_json.loads(raw)
    except Exception:
        _raise("protected_source_direct_url_malformed")
    if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
        _raise("protected_source_direct_url_malformed")
    kind_keys = {"dir_info", "archive_info", "vcs_info"} & set(payload)
    if len(kind_keys) != 1:
        _raise("protected_source_direct_url_malformed")
    kind = next(iter(kind_keys))
    if set(payload) != {"url", kind} or not isinstance(payload[kind], dict):
        _raise("protected_source_direct_url_malformed")
    if kind != "dir_info":
        return None
    directory_info = payload["dir_info"]
    if not directory_info:
        return None
    if set(directory_info) != {"editable"} or directory_info.get("editable") is not True:
        _raise("protected_source_direct_url_malformed")
    url = payload.get("url")
    if not isinstance(url, str):
        _raise("protected_source_direct_url_malformed")
    parsed = urlparse(url)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        _raise("protected_source_editable_root_invalid")
    try:
        return Path(unquote(parsed.path)).resolve(strict=True)
    except (OSError, ValueError):
        _raise("protected_source_editable_root_invalid")


def _validate_metadata_headers(metadata_file: Path, version: str) -> None:
    info = _regular_nonsymlink(metadata_file, "protected_source_distribution_metadata_invalid")
    if info.st_size > 1024 * 1024:
        _raise("protected_source_distribution_metadata_too_large")
    try:
        parsed = Parser().parsestr(metadata_file.read_text(encoding="utf-8"))
        names = parsed.get_all("Name", [])
        versions = parsed.get_all("Version", [])
    except Exception:
        _raise("protected_source_distribution_metadata_malformed")
    if (
        len(names) != 1
        or len(versions) != 1
        or _normalized_name(names[0]) != DIST_NAME
        or versions[0] != version
    ):
        _raise("protected_source_distribution_metadata_malformed")


def _validate_metadata_file(metadata_root: Path, version: str) -> None:
    _validate_metadata_headers(metadata_root / "METADATA", version)


def _expected_dist_info_name(version: str) -> str:
    normalized_version = re.sub(r"[^A-Za-z0-9.]+", "_", version)
    return f"clu_governance-{normalized_version}.dist-info"


def _candidate_report(root: Path, role: str) -> dict[str, str]:
    """Return a privacy-bounded account of one accepted metadata candidate."""

    if root.name.endswith(".dist-info"):
        kind = "dist_info"
    elif root.name.endswith(".egg-info"):
        kind = "egg_info"
    else:  # Defensive: only reachable after structural validation.
        kind = "unknown"
    return {
        "metadata_basename": root.name,
        "metadata_kind": kind,
        "classified_role": role,
    }


def _active_distribution_root() -> Path:
    """Resolve the metadata root selected by importlib for the live process."""

    try:
        active = metadata.distribution(DIST_NAME)
    except Exception:
        _raise("protected_source_active_distribution_missing")
    return _candidate_root(
        _MetadataCandidate(
            distribution=active,
            declared_name=None,
            raw_root=_raw_metadata_root(active),
        )
    )


def _classify_source_candidates(
    candidates: Sequence[_MetadataCandidate],
    *,
    package: Path,
    project_root: Path,
    version: str,
    require_active_process_root: bool,
) -> tuple[str, Any | None, Path | None, list[dict[str, str]], str, bool]:
    """Accept only the documented source or editable metadata shapes.

    The two supported source-layout shapes are intentionally narrow:

    * no CLU metadata, or one exact local generated egg-info, for source mode;
    * one exact active editable dist-info plus that one local egg-info for
      editable mode.

    Every other visible CLU candidate set is ambiguous or structurally invalid.
    """

    if not candidates:
        return (
            "source_tree",
            None,
            None,
            [],
            "source_tree_without_distribution_metadata",
            False,
        )
    # The only accepted maximum is two, but three candidates are inspected so
    # that an editable pair plus a second active dist-info receives the stable
    # duplicate-active-install blocker instead of a generic count failure.
    if len(candidates) > 3:
        _raise("protected_source_distribution_ambiguous")

    classified: list[tuple[_MetadataCandidate, Path, str, Path | None]] = []
    for candidate in candidates:
        # Retain the legacy generic ambiguity blocker for candidates whose
        # metadata location cannot be established at all.
        if candidate.raw_root is None:
            _raise("protected_source_distribution_ambiguous")
        root = _candidate_root(candidate)
        _validate_candidate_identity(candidate, version)
        if root.name.endswith(".dist-info"):
            if root.name != _expected_dist_info_name(version):
                _raise("protected_source_distribution_metadata_invalid")
            editable_root = _editable_project_root(candidate.distribution)
            if editable_root is not None and editable_root != project_root:
                _raise("protected_source_editable_root_mismatch")
            role = (
                "active_editable_dist_info"
                if editable_root == project_root
                else "installed_dist_info"
            )
            classified.append((candidate, root, role, editable_root))
            continue
        if root.name.endswith(".egg-info"):
            classified.append((candidate, root, "source_egg_info", None))
            continue
        _raise("protected_source_distribution_metadata_invalid")

    egg_candidates = [entry for entry in classified if entry[2] == "source_egg_info"]
    dist_candidates = [entry for entry in classified if entry[2] != "source_egg_info"]
    if len(egg_candidates) > 1:
        _raise("protected_source_source_egg_info_ambiguous")

    source_egg_info_present = bool(egg_candidates)
    if egg_candidates:
        _candidate, egg_root, _role, _editable = egg_candidates[0]
        if egg_root.name != "clu_governance.egg-info":
            _raise("protected_source_source_egg_info_invalid")
        expected_egg_root = package.parent / "clu_governance.egg-info"
        if egg_root != expected_egg_root:
            _raise("protected_source_source_egg_info_project_root_mismatch")
        if project_root != package.parent.parent:
            _raise("protected_source_source_egg_info_project_root_mismatch")
        _validate_metadata_headers(egg_root / "PKG-INFO", version)

    if not dist_candidates:
        reports = [_candidate_report(root, role) for _, root, role, _ in classified]
        return (
            "source_tree",
            None,
            None,
            reports,
            (
                "source_tree_with_source_adjacent_egg_info"
                if source_egg_info_present
                else "source_tree_without_distribution_metadata"
            ),
            source_egg_info_present,
        )

    if len(dist_candidates) > 1:
        if all(role == "active_editable_dist_info" for _, _, role, _ in dist_candidates):
            _raise("protected_source_editable_distribution_ambiguous")
        _raise("protected_source_distribution_ambiguous")

    distribution, metadata_root, role, _editable_root = dist_candidates[0]
    if role != "active_editable_dist_info":
        _raise("protected_source_distribution_ambiguous")
    if not source_egg_info_present:
        _raise("protected_source_editable_source_egg_info_missing")
    if require_active_process_root and _active_distribution_root() != metadata_root:
        _raise("protected_source_active_distribution_mismatch")
    reports = [_candidate_report(root, candidate_role) for _, root, candidate_role, _ in classified]
    return (
        "editable_install",
        distribution.distribution,
        metadata_root,
        reports,
        "editable_active_dist_info_plus_source_adjacent_egg_info",
        True,
    )


def _classify_wheel_candidates(
    candidates: Sequence[_MetadataCandidate], *, version: str
) -> tuple[Any, Path, list[dict[str, str]], str]:
    """Accept exactly one non-editable active dist-info for wheel execution."""

    if not candidates:
        _raise("protected_source_installed_distribution_missing")
    if len(candidates) != 1:
        _raise("protected_source_distribution_ambiguous")
    candidate = candidates[0]
    root = _candidate_root(candidate)
    _validate_candidate_identity(candidate, version)
    if not root.name.endswith(".dist-info") or root.name != _expected_dist_info_name(version):
        _raise("protected_source_distribution_metadata_invalid")
    if _editable_project_root(candidate.distribution) is not None:
        _raise("protected_source_editable_import_surface_mismatch")
    return (
        candidate.distribution,
        root,
        [_candidate_report(root, "active_wheel_dist_info")],
        "wheel_active_dist_info",
    )


def _editable_bridge_basenames(version: str) -> set[str]:
    """Return the exact setuptools-owned bridge names for this distribution."""

    dist_version = re.sub(r"[^A-Za-z0-9.]+", "_", version)
    finder_version = re.sub(r"[^A-Za-z0-9]+", "_", version)
    return {
        f"__editable__.clu_governance-{dist_version}.pth",
        f"__editable___clu_governance_{finder_version}_finder.py",
    }


def _relative_record(root_name: str, root: Path, path: Path) -> dict[str, Any]:
    if not _inside(path, root):
        _raise("protected_source_path_escape")
    relative = path.relative_to(root).as_posix()
    return {
        "root": root_name,
        "relative_path": relative,
        "sha256": _sha256(path),
        "size": path.stat().st_size,
    }


def build_protected_source_manifest(
    *,
    package_root: Path | None = None,
    expected_version: str | None = None,
    distributions: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Build and verify the exact manifest for the active import surface."""

    version = __version__ if expected_version is None else expected_version
    imported_root = Path(__file__).absolute().parent if package_root is None else package_root
    package = _real_directory(imported_root, "protected_source_package_root_invalid")
    source_files = _source_package_files(package)
    project_info = _project_metadata(package)
    candidates = _matching_distributions(distributions)

    mode: str
    distribution: Any | None = None
    metadata_root: Path | None = None
    metadata_files: list[Path] = []
    editable_bridge_files: list[Path] = []
    source_metadata_file: Path | None = None
    source_project_root: Path | None = None
    candidate_reports: list[dict[str, str]] = []
    candidate_set_shape: str
    source_egg_info_present = False
    generation_method = GENERATION_METHOD
    if project_info is not None:
        project_root, project = project_info
        source_project_root = project_root
        source_metadata_file = project_root / "pyproject.toml"
        if str(project.get("version", "")) != version:
            _raise("protected_source_version_mismatch")
        (
            mode,
            distribution,
            metadata_root,
            candidate_reports,
            candidate_set_shape,
            source_egg_info_present,
        ) = _classify_source_candidates(
            candidates,
            package=package,
            project_root=project_root,
            version=version,
            require_active_process_root=distributions is None,
        )
        if mode == "source_tree":
            generation_method = (
                "source_import_surface_plus_pyproject_and_local_egg_info_v1"
                if source_egg_info_present
                else "source_import_surface_plus_pyproject_v1"
            )
        else:
            generation_method = "editable_import_surface_plus_direct_url_and_record_v1"
    else:
        (
            distribution,
            metadata_root,
            candidate_reports,
            candidate_set_shape,
        ) = _classify_wheel_candidates(candidates, version=version)
        mode = "wheel_install"
        generation_method = "wheel_import_surface_plus_distribution_record_v1"

    if distribution is not None and mode != "source_tree":
        assert metadata_root is not None
        if _distribution_metadata_root(distribution, version) != metadata_root:
            _raise("protected_source_distribution_metadata_ambiguous")
        try:
            dist_name = distribution.metadata["Name"]
            dist_version = distribution.version
        except Exception:
            _raise("protected_source_distribution_metadata_malformed")
        if _normalized_name(str(dist_name)) != DIST_NAME or str(dist_version) != version:
            _raise("protected_source_version_mismatch")
        assert metadata_root is not None
        rows = _record_rows(distribution, metadata_root)
        selected_rows: dict[Path, tuple[str, str]] = {}
        for raw, record_values in rows.items():
            normalized_record = PurePosixPath(posixpath.normpath(raw))
            # Wheel console scripts are commonly recorded with parent
            # traversal from site-packages.  They are distribution-owned but
            # intentionally outside this protected-source contract.
            if normalized_record.parts and normalized_record.parts[0] == "..":
                parts = normalized_record.parts
                first_local = next((index for index, part in enumerate(parts) if part != ".."), len(parts))
                external_tail = parts[first_local:]
                if external_tail not in {
                    ("bin", "clu-governance"),
                    ("Scripts", "clu-governance"),
                    ("Scripts", "clu-governance.exe"),
                }:
                    _raise("protected_source_record_external_path_unsupported")
                continue
            located = _record_path_for(distribution, raw)
            first_part = normalized_record.parts[0] if normalized_record.parts else ""
            claims_package_path = first_part == package.name
            claims_metadata_path = first_part == metadata_root.name
            claims_editable_bridge = (
                mode == "editable_install"
                and len(normalized_record.parts) == 1
                and normalized_record.name in _editable_bridge_basenames(version)
            )
            if claims_package_path and not _inside(located, package):
                _raise("protected_source_record_path_escape")
            if claims_metadata_path and not _inside(located, metadata_root):
                _raise("protected_source_record_path_escape")
            if claims_editable_bridge and located.parent != metadata_root.parent:
                _raise("protected_source_record_path_escape")
            if (
                _inside(located, package)
                or _inside(located, metadata_root)
                or claims_editable_bridge
            ):
                if ".." in PurePosixPath(raw).parts:
                    _raise("protected_source_record_malformed")
                if located in selected_rows:
                    _raise("protected_source_record_duplicate_resolved_path")
                selected_rows[located] = record_values
        for path, (hash_value, size_value) in selected_rows.items():
            _verify_record_file(path, hash_value, size_value)
        _validate_metadata_file(metadata_root, version)
        metadata_files = sorted(
            (path for path in selected_rows if _inside(path, metadata_root)),
            key=lambda item: item.relative_to(metadata_root).as_posix(),
        )
        if not metadata_files or metadata_root / "METADATA" not in metadata_files or metadata_root / "RECORD" not in metadata_files:
            _raise("protected_source_distribution_metadata_incomplete")
        metadata_disk_files = set(_tree_files(metadata_root))
        if metadata_disk_files != set(metadata_files):
            _raise("protected_source_distribution_metadata_not_exact")
        if mode == "editable_install":
            editable_bridge_files = sorted(
                (
                    path
                    for path in selected_rows
                    if path.name in _editable_bridge_basenames(version)
                    and path.parent == metadata_root.parent
                ),
                key=lambda item: item.name,
            )
        if mode == "wheel_install":
            recorded_package = {path for path in selected_rows if _inside(path, package)}
            if any(path not in recorded_package for path in source_files):
                _raise("protected_source_package_file_not_owned_by_distribution")

    protected_files = [_relative_record("package_root", package, path) for path in source_files]
    if source_metadata_file is not None and source_project_root is not None:
        protected_files.append(
            _relative_record("source_project_root", source_project_root, source_metadata_file)
        )
    if metadata_root is not None:
        protected_files.extend(
            _relative_record("distribution_metadata_root", metadata_root, path)
            for path in metadata_files
        )
    for bridge in editable_bridge_files:
        protected_files.append(
            _relative_record("editable_import_bridge", bridge.parent, bridge)
        )
    protected_files.sort(key=lambda item: (item["root"], item["relative_path"]))
    fingerprint_payload = {
        "schema_version": SCHEMA_VERSION,
        "distribution_version": version,
        "distribution_mode": mode,
        "protected_files": protected_files,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    roots = [str(package)]
    standalone_files: list[str] = []
    if source_metadata_file is not None:
        standalone_files.append(str(source_metadata_file.resolve(strict=True)))
    standalone_files.extend(str(path) for path in editable_bridge_files)
    protected_directories = [{"root": "package_root", "relative_path": "."}]
    if metadata_root is not None:
        roots.append(str(metadata_root))
        protected_directories.append({"root": "distribution_metadata_root", "relative_path": "."})
    return {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "distribution_name": DIST_NAME,
        "distribution_version": version,
        "distribution_mode": mode,
        "package_root": str(package),
        "distribution_metadata_root": str(metadata_root) if metadata_root is not None else None,
        "discovered_matching_metadata_candidates": candidate_reports,
        "matching_metadata_candidate_count": len(candidate_reports),
        "accepted_candidate_set_shape": candidate_set_shape,
        "source_egg_info_present": source_egg_info_present,
        "source_egg_info_protected": False,
        "editable_import_bridge_present": bool(editable_bridge_files),
        "editable_import_bridge_protected": bool(editable_bridge_files),
        "editable_import_bridge_decision": (
            "exact_recorded_clu_editable_bridge_files_protected"
            if editable_bridge_files
            else "no_exact_recorded_clu_editable_bridge_files_present"
        ),
        "exact_protected_roots": roots,
        "exact_protected_standalone_files": standalone_files,
        "exact_protected_files": protected_files,
        "exact_protected_directories": protected_directories,
        "protected_file_count": len(protected_files),
        "protected_directory_count": len(protected_directories),
        "manifest_generation_method": generation_method,
        "manifest_sha256": manifest_hash,
        "all_protected_files_exist": True,
        "all_protected_files_regular": True,
        "all_protected_files_non_symlink": True,
        "all_protected_paths_within_declared_roots": True,
        "whole_site_packages_protected": False,
        "neighboring_packages_protected": False,
        "neighboring_package_exclusion_result": "passed",
        "exact_blocker": None,
    }


def protected_source_hash() -> str:
    """Return a fresh content-bound fingerprint of the protected manifest."""

    return str(build_protected_source_manifest()["manifest_sha256"])


def protected_source_roots() -> tuple[Path, ...]:
    """Return only the exact roots covered by the current manifest."""

    manifest = build_protected_source_manifest()
    values = [*manifest["exact_protected_roots"], *manifest["exact_protected_standalone_files"]]
    return tuple(Path(value) for value in values)


def diagnostic_manifest() -> dict[str, Any]:
    """Return a privacy-bounded, exact root-relative diagnostic manifest."""

    manifest = build_protected_source_manifest()
    result = dict(manifest)
    result["package_root"] = "<package_root>"
    if result["distribution_metadata_root"] is not None:
        result["distribution_metadata_root"] = "<distribution_metadata_root>"
    result["exact_protected_roots"] = [
        "<package_root>",
        *(["<distribution_metadata_root>"] if manifest["distribution_metadata_root"] is not None else []),
    ]
    standalone_files: list[str] = []
    if any(
        item["root"] == "source_project_root"
        for item in manifest["exact_protected_files"]
    ):
        standalone_files.append("<source_project_root>/pyproject.toml")
    standalone_files.extend(
        f"<editable_import_bridge>/{item['relative_path']}"
        for item in manifest["exact_protected_files"]
        if item["root"] == "editable_import_bridge"
    )
    result["exact_protected_standalone_files"] = standalone_files
    result["package_root_display"] = (
        "source-layout:src/clu_governance"
        if manifest["distribution_mode"] in {"source_tree", "editable_install"}
        else "installed-distribution:clu_governance"
    )
    result.update(
        {
            "result": "ready",
            "absolute_local_paths_disclosed": False,
            "unrelated_site_packages_inventory_disclosed": False,
            "provider_calls": 0,
            "advisor_calls": 0,
            "mem0_runs": 0,
            "benchmark_runs": 0,
            "network_calls": 0,
        }
    )
    return result
