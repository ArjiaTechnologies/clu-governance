from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath

from clu_governance import protected_source_manifest as manifest
from clu_governance import git_diff_adapter


def _record_hash(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return f"sha256={encoded}"


class FakeDistribution:
    def __init__(self, base: Path, name: str, version: str, files: list[str], direct_url: str | None = None):
        self.base = base
        self.metadata = {"Name": name, "Version": version}
        self.version = version
        self.files = files
        self._direct_url = direct_url
        metadata_paths = [
            PurePosixPath(value).parent
            for value in files
            if PurePosixPath(value).name == "METADATA"
            and PurePosixPath(value).parent.name.endswith(".dist-info")
        ]
        self._path = base / metadata_paths[0] if len(metadata_paths) == 1 else None

    def locate_file(self, value: str) -> Path:
        return self.base / value

    def read_text(self, name: str) -> str | None:
        if name == "direct_url.json":
            return self._direct_url
        return None


class ProtectedSourceManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="clu-manifest-test.")
        self.root = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _source_tree(self, version: str = "1.2.3") -> tuple[Path, Path]:
        project = self.root / "project"
        package = project / "src" / "clu_governance"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
        (package / "alpha.py").write_text("VALUE = 1\n", encoding="utf-8")
        (project / "pyproject.toml").write_text(
            f'[project]\nname = "clu-governance"\nversion = "{version}"\n', encoding="utf-8"
        )
        return project, package

    def _wheel(
        self, version: str = "1.2.3", *, root: Path | None = None
    ) -> tuple[Path, Path, FakeDistribution]:
        site = (self.root if root is None else root) / "site-packages"
        package = site / "clu_governance"
        info = site / f"clu_governance-{version}.dist-info"
        package.mkdir(parents=True)
        info.mkdir()
        paths: dict[str, bytes] = {
            "clu_governance/__init__.py": f'__version__ = "{version}"\n'.encode(),
            "clu_governance/alpha.py": b"VALUE = 1\n",
            f"clu_governance-{version}.dist-info/METADATA": (
                f"Metadata-Version: 2.4\nName: clu-governance\nVersion: {version}\n\n"
            ).encode(),
        }
        for relative, data in paths.items():
            target = site / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        record_relative = f"clu_governance-{version}.dist-info/RECORD"
        console_relative = "../../../bin/clu-governance"
        rows = [[relative, _record_hash(data), str(len(data))] for relative, data in paths.items()]
        rows.extend([[console_relative, "", ""], [record_relative, "", ""]])
        with (site / record_relative).open("w", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerows(rows)
        dist = FakeDistribution(site, "clu-governance", version, [*paths, record_relative, console_relative])
        return site, package, dist

    def _source_egg_info(
        self,
        project: Path,
        *,
        version: str = "1.2.3",
        root: Path | None = None,
        basename: str = "clu_governance.egg-info",
        pkg_info: str | None = None,
    ) -> FakeDistribution:
        egg_info = root or project / "src" / basename
        egg_info.mkdir(parents=True, exist_ok=True)
        (egg_info / "PKG-INFO").write_text(
            pkg_info
            or f"Metadata-Version: 2.4\nName: clu-governance\nVersion: {version}\n\n",
            encoding="utf-8",
        )
        distribution = FakeDistribution(
            egg_info.parent, "clu-governance", version, []
        )
        distribution._path = egg_info
        return distribution

    def _editable_pair(
        self, *, version: str = "1.2.3"
    ) -> tuple[Path, Path, FakeDistribution, FakeDistribution, Path]:
        project, package = self._source_tree(version)
        site, _wheel_package, distribution = self._wheel(version)
        record = next(site.glob("*.dist-info/RECORD"))
        rows = [
            row
            for row in csv.reader(record.read_text(encoding="utf-8").splitlines())
            if not row[0].startswith("clu_governance/")
        ]
        with record.open("w", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerows(rows)
        distribution.files = [
            value for value in distribution.files if not value.startswith("clu_governance/")
        ]
        distribution._direct_url = json.dumps(
            {"url": project.as_uri(), "dir_info": {"editable": True}}, sort_keys=True
        )
        egg_distribution = self._source_egg_info(project, version=version)
        return project, package, distribution, egg_distribution, site

    def test_source_mode_is_exact_and_excludes_neighbor(self) -> None:
        project, package = self._source_tree()
        neighbor = project / "src" / "neighbor.py"
        neighbor.write_text("SECRET = True\n", encoding="utf-8")
        result = manifest.build_protected_source_manifest(
            package_root=package, expected_version="1.2.3", distributions=[]
        )
        self.assertEqual(result["distribution_mode"], "source_tree")
        self.assertEqual(result["manifest_generation_method"], "source_import_surface_plus_pyproject_v1")
        entries = {(item["root"], item["relative_path"]) for item in result["exact_protected_files"]}
        self.assertIn(("package_root", "alpha.py"), entries)
        self.assertIn(("source_project_root", "pyproject.toml"), entries)
        self.assertNotIn(("package_root", "neighbor.py"), entries)
        self.assertFalse(result["whole_site_packages_protected"])
        self.assertFalse(result["neighboring_packages_protected"])
        self.assertEqual(result["protected_directory_count"], 1)

    def test_source_hash_ignores_neighbor_but_binds_module(self) -> None:
        project, package = self._source_tree()
        first = manifest.build_protected_source_manifest(
            package_root=package, expected_version="1.2.3", distributions=[]
        )["manifest_sha256"]
        (project / "src" / "unrelated.txt").write_text("outside", encoding="utf-8")
        second = manifest.build_protected_source_manifest(
            package_root=package, expected_version="1.2.3", distributions=[]
        )["manifest_sha256"]
        self.assertEqual(first, second)
        (package / "alpha.py").write_text("VALUE = 2\n", encoding="utf-8")
        third = manifest.build_protected_source_manifest(
            package_root=package, expected_version="1.2.3", distributions=[]
        )["manifest_sha256"]
        self.assertNotEqual(second, third)

    def test_source_adjacent_egg_info_remains_source_mode(self) -> None:
        project, package = self._source_tree()
        distribution = self._source_egg_info(project)
        result = manifest.build_protected_source_manifest(
            package_root=package,
            expected_version="1.2.3",
            distributions=[distribution],
        )
        self.assertEqual(result["distribution_mode"], "source_tree")
        self.assertEqual(
            result["manifest_generation_method"],
            "source_import_surface_plus_pyproject_and_local_egg_info_v1",
        )

    def test_wrong_egg_info_basename_fails_closed(self) -> None:
        project, package = self._source_tree()
        egg_info = project / "src" / "evil.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            "Metadata-Version: 2.4\nName: clu-governance\nVersion: 1.2.3\n\n",
            encoding="utf-8",
        )
        distribution = FakeDistribution(
            project / "src", "clu-governance", "1.2.3", []
        )
        distribution._path = egg_info
        with self.assertRaisesRegex(
            manifest.ProtectedSourceManifestError, "source_egg_info_invalid"
        ):
            manifest.build_protected_source_manifest(
                package_root=package,
                expected_version="1.2.3",
                distributions=[distribution],
            )

    def test_editable_pair_is_reconciled_and_egg_info_is_not_protected(self) -> None:
        _project, package, editable, egg_info, _site = self._editable_pair()
        result = manifest.build_protected_source_manifest(
            package_root=package,
            expected_version="1.2.3",
            distributions=[editable, egg_info],
        )
        self.assertEqual(result["distribution_mode"], "editable_install")
        self.assertEqual(
            result["accepted_candidate_set_shape"],
            "editable_active_dist_info_plus_source_adjacent_egg_info",
        )
        self.assertTrue(result["source_egg_info_present"])
        self.assertFalse(result["source_egg_info_protected"])
        self.assertEqual(
            [entry["classified_role"] for entry in result["discovered_matching_metadata_candidates"]],
            ["active_editable_dist_info", "source_egg_info"],
        )
        self.assertFalse(
            any(
                "egg-info" in str(value)
                for value in [
                    *result["exact_protected_roots"],
                    *result["exact_protected_standalone_files"],
                ]
            )
        )

    def test_editable_pair_with_recorded_bridge_protects_only_that_bridge(self) -> None:
        _project, package, editable, egg_info, site = self._editable_pair()
        bridge_name = "__editable__.clu_governance-1.2.3.pth"
        bridge = site / bridge_name
        bridge_bytes = b"/tmp/expected-src\n"
        bridge.write_bytes(bridge_bytes)
        record = next(site.glob("*.dist-info/RECORD"))
        rows = list(csv.reader(record.read_text(encoding="utf-8").splitlines()))
        rows.insert(0, [bridge_name, _record_hash(bridge_bytes), str(len(bridge_bytes))])
        with record.open("w", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerows(rows)
        editable.files.append(bridge_name)
        (site / "neighbor.pth").write_text("/tmp/neighbor\n", encoding="utf-8")
        result = manifest.build_protected_source_manifest(
            package_root=package,
            expected_version="1.2.3",
            distributions=[editable, egg_info],
        )
        bridge_entries = [
            item
            for item in result["exact_protected_files"]
            if item["root"] == "editable_import_bridge"
        ]
        self.assertEqual([item["relative_path"] for item in bridge_entries], [bridge_name])
        self.assertTrue(result["editable_import_bridge_present"])
        self.assertTrue(result["editable_import_bridge_protected"])
        self.assertNotIn(str(site / "neighbor.pth"), result["exact_protected_standalone_files"])

    def test_editable_without_source_egg_info_is_blocked(self) -> None:
        _project, package, editable, _egg_info, _site = self._editable_pair()
        with self.assertRaisesRegex(
            manifest.ProtectedSourceManifestError,
            "editable_source_egg_info_missing",
        ):
            manifest.build_protected_source_manifest(
                package_root=package,
                expected_version="1.2.3",
                distributions=[editable],
            )

    def test_two_active_editable_dist_info_roots_are_ambiguous(self) -> None:
        project, package, editable, egg_info, _site = self._editable_pair()
        _other_site, _other_package, second = self._wheel(root=self.root / "second")
        second._direct_url = json.dumps(
            {"url": project.as_uri(), "dir_info": {"editable": True}}, sort_keys=True
        )
        with self.assertRaisesRegex(
            manifest.ProtectedSourceManifestError,
            "editable_distribution_ambiguous",
        ):
            manifest.build_protected_source_manifest(
                package_root=package,
                expected_version="1.2.3",
                distributions=[editable, second, egg_info],
            )

    def test_editable_plus_wheel_dist_info_is_ambiguous(self) -> None:
        _project, package, editable, egg_info, _site = self._editable_pair()
        _wheel_site, _wheel_package, wheel = self._wheel(root=self.root / "wheel")
        with self.assertRaisesRegex(
            manifest.ProtectedSourceManifestError, "distribution_ambiguous"
        ):
            manifest.build_protected_source_manifest(
                package_root=package,
                expected_version="1.2.3",
                distributions=[editable, wheel, egg_info],
            )

    def test_two_source_egg_info_candidates_are_ambiguous(self) -> None:
        project, package = self._source_tree()
        first = self._source_egg_info(project)
        second = self._source_egg_info(
            project,
            root=project / "second-src" / "clu_governance.egg-info",
        )
        with self.assertRaisesRegex(
            manifest.ProtectedSourceManifestError, "source_egg_info_ambiguous"
        ):
            manifest.build_protected_source_manifest(
                package_root=package,
                expected_version="1.2.3",
                distributions=[first, second],
            )

    def test_foreign_egg_info_project_root_is_blocked(self) -> None:
        project, package = self._source_tree()
        foreign_project = self.root / "foreign-project"
        foreign = self._source_egg_info(
            foreign_project,
            root=foreign_project / "src" / "clu_governance.egg-info",
        )
        with self.assertRaisesRegex(
            manifest.ProtectedSourceManifestError,
            "source_egg_info_project_root_mismatch",
        ):
            manifest.build_protected_source_manifest(
                package_root=package,
                expected_version="1.2.3",
                distributions=[foreign],
            )

    def test_editable_direct_url_mismatch_is_blocked(self) -> None:
        _project, package, editable, egg_info, _site = self._editable_pair()
        foreign_project = self.root / "foreign-project"
        foreign_project.mkdir()
        editable._direct_url = json.dumps(
            {"url": foreign_project.as_uri(), "dir_info": {"editable": True}},
            sort_keys=True,
        )
        with self.assertRaisesRegex(
            manifest.ProtectedSourceManifestError, "editable_root_mismatch"
        ):
            manifest.build_protected_source_manifest(
                package_root=package,
                expected_version="1.2.3",
                distributions=[editable, egg_info],
            )

    def test_source_egg_info_version_mismatch_is_blocked(self) -> None:
        project, package = self._source_tree()
        egg_info = self._source_egg_info(project, version="9.9.9")
        with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, "version_mismatch"):
            manifest.build_protected_source_manifest(
                package_root=package,
                expected_version="1.2.3",
                distributions=[egg_info],
            )

    def test_malformed_source_egg_info_is_blocked(self) -> None:
        project, package = self._source_tree()
        egg_info = self._source_egg_info(
            project,
            pkg_info="Metadata-Version: 2.4\nName: clu-governance\nName: duplicate\n\n",
        )
        with self.assertRaisesRegex(
            manifest.ProtectedSourceManifestError, "metadata_malformed"
        ):
            manifest.build_protected_source_manifest(
                package_root=package,
                expected_version="1.2.3",
                distributions=[egg_info],
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlinked_source_egg_info_is_blocked(self) -> None:
        project, package = self._source_tree()
        outside = self.root / "outside.egg-info"
        outside.mkdir()
        (outside / "PKG-INFO").write_text(
            "Metadata-Version: 2.4\nName: clu-governance\nVersion: 1.2.3\n\n",
            encoding="utf-8",
        )
        egg_info = project / "src" / "clu_governance.egg-info"
        os.symlink(outside, egg_info)
        distribution = FakeDistribution(project / "src", "clu-governance", "1.2.3", [])
        distribution._path = egg_info
        with self.assertRaisesRegex(
            manifest.ProtectedSourceManifestError, "distribution_metadata_invalid"
        ):
            manifest.build_protected_source_manifest(
                package_root=package,
                expected_version="1.2.3",
                distributions=[distribution],
            )

    def test_neighboring_non_clu_distribution_is_excluded_from_editable_pair(self) -> None:
        _project, package, editable, egg_info, _site = self._editable_pair()
        neighbor_root = self.root / "site-packages" / "neighbor-1.0.dist-info"
        neighbor_root.mkdir(parents=True)
        neighbor = FakeDistribution(self.root / "site-packages", "neighbor", "1.0", [])
        neighbor._path = neighbor_root
        result = manifest.build_protected_source_manifest(
            package_root=package,
            expected_version="1.2.3",
            distributions=[editable, egg_info, neighbor],
        )
        self.assertEqual(result["matching_metadata_candidate_count"], 2)
        self.assertFalse(result["neighboring_packages_protected"])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_source_symlink_fails_closed(self) -> None:
        _project, package = self._source_tree()
        (package / "alpha.py").unlink()
        os.symlink(package / "__init__.py", package / "alpha.py")
        with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, "protected_source_file_not_regular"):
            manifest.build_protected_source_manifest(
                package_root=package, expected_version="1.2.3", distributions=[]
            )

    def test_duplicate_matching_distributions_fail_closed(self) -> None:
        _project, package = self._source_tree()
        fake = FakeDistribution(self.root, "clu-governance", "1.2.3", [])
        with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, "distribution_ambiguous"):
            manifest.build_protected_source_manifest(
                package_root=package, expected_version="1.2.3", distributions=[fake, fake]
            )

    def test_wheel_record_protects_only_package_and_dist_info(self) -> None:
        site, package, dist = self._wheel()
        (site / "neighbor_package.py").write_text("PRIVATE = 1\n", encoding="utf-8")
        result = manifest.build_protected_source_manifest(
            package_root=package, expected_version="1.2.3", distributions=[dist]
        )
        self.assertEqual(result["distribution_mode"], "wheel_install")
        self.assertEqual(result["manifest_generation_method"], "wheel_import_surface_plus_distribution_record_v1")
        self.assertEqual(Path(result["package_root"]), package.resolve())
        self.assertNotEqual(Path(result["package_root"]), site.resolve())
        relative = {item["relative_path"] for item in result["exact_protected_files"]}
        self.assertNotIn("neighbor_package.py", relative)
        self.assertFalse(any("bin/clu-governance" in item for item in map(str, result["exact_protected_files"])))
        self.assertEqual(result["protected_directory_count"], 2)

    def test_noneditable_archive_direct_url_remains_wheel_mode(self) -> None:
        _site, package, dist = self._wheel()
        dist._direct_url = json.dumps(
            {"url": "file:///tmp/clu_governance-1.2.3.whl", "archive_info": {}}
        )
        result = manifest.build_protected_source_manifest(
            package_root=package, expected_version="1.2.3", distributions=[dist]
        )
        self.assertEqual(result["distribution_mode"], "wheel_install")

    def test_unrecorded_wheel_module_fails_closed(self) -> None:
        _site, package, dist = self._wheel()
        (package / "unrecorded.py").write_text("VALUE = 9\n", encoding="utf-8")
        with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, "package_file_not_owned"):
            manifest.build_protected_source_manifest(
                package_root=package, expected_version="1.2.3", distributions=[dist]
            )

    def test_record_hash_and_size_mismatches_fail_closed(self) -> None:
        original_root = self.root
        for mismatch in ("hash", "size"):
            with self.subTest(mismatch=mismatch):
                self.root = original_root / mismatch
                self.root.mkdir()
                site, package, dist = self._wheel()
                alpha = package / "alpha.py"
                if mismatch == "hash":
                    alpha.write_text("VALUE = 2\n", encoding="utf-8")
                    blocker = "record_hash_mismatch"
                else:
                    record = next(site.glob("*.dist-info/RECORD"))
                    rows = list(csv.reader(record.read_text(encoding="utf-8").splitlines()))
                    for row in rows:
                        if row[0] == "clu_governance/alpha.py":
                            row[2] = str(int(row[2]) + 1)
                    with record.open("w", encoding="utf-8", newline="") as stream:
                        csv.writer(stream).writerows(rows)
                    blocker = "record_size_mismatch"
                with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, blocker):
                    manifest.build_protected_source_manifest(
                        package_root=package, expected_version="1.2.3", distributions=[dist]
                    )
        self.root = original_root

    def test_record_external_path_escape_fails_closed(self) -> None:
        site, package, dist = self._wheel()
        record = next(site.glob("*.dist-info/RECORD"))
        with record.open("a", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerow(["../../outside-secret.txt", "", ""])
        with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, "record_external_path_unsupported"):
            manifest.build_protected_source_manifest(
                package_root=package, expected_version="1.2.3", distributions=[dist]
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_distribution_metadata_symlink_fails_closed(self) -> None:
        site, package, dist = self._wheel()
        metadata_file = next(site.glob("*.dist-info/METADATA"))
        outside = self.root / "outside-metadata"
        outside.write_text(metadata_file.read_text(encoding="utf-8"), encoding="utf-8")
        metadata_file.unlink()
        os.symlink(outside, metadata_file)
        with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, "record_file_invalid"):
            manifest.build_protected_source_manifest(
                package_root=package, expected_version="1.2.3", distributions=[dist]
            )

    def test_git_adapter_overlap_uses_exact_roots_not_site_packages(self) -> None:
        site = self.root / "site-packages"
        package = site / "clu_governance"
        metadata_root = site / "clu_governance-1.2.3.dist-info"
        repo = self.root / "repo"
        for directory in (site, package, metadata_root, repo):
            directory.mkdir(parents=True, exist_ok=True)
        final, parent = git_diff_adapter._validate_output_path(
            site / "neighbor-output", repo, (package, metadata_root)
        )
        try:
            self.assertEqual(final, site / "neighbor-output")
        finally:
            parent.close()
        with self.assertRaisesRegex(git_diff_adapter.GitAdapterError, "output_candidate_source_overlap_denied"):
            git_diff_adapter._validate_output_path(package / "output", repo, (package, metadata_root))

    def test_duplicate_record_rows_resolving_to_owned_file_fail(self) -> None:
        site, package, dist = self._wheel()
        record = next(site.glob("*.dist-info/RECORD"))
        with record.open("a", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerow(["clu_governance/../clu_governance/alpha.py", "", ""])
        dist.files.append("clu_governance/../clu_governance/alpha.py")
        with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, "record_malformed"):
            manifest.build_protected_source_manifest(
                package_root=package, expected_version="1.2.3", distributions=[dist]
            )

    def test_malformed_metadata_fails_closed(self) -> None:
        site, package, dist = self._wheel()
        metadata_file = next(site.glob("*.dist-info/METADATA"))
        bad = b"Metadata-Version: 2.4\nName: clu-governance\nName: other\nVersion: 1.2.3\n\n"
        metadata_file.write_bytes(bad)
        record = next(site.glob("*.dist-info/RECORD"))
        rows = list(csv.reader(record.read_text(encoding="utf-8").splitlines()))
        for row in rows:
            if row[0].endswith("/METADATA"):
                row[1], row[2] = _record_hash(bad), str(len(bad))
        with record.open("w", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerows(rows)
        with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, "metadata_malformed"):
            manifest.build_protected_source_manifest(
                package_root=package, expected_version="1.2.3", distributions=[dist]
            )

    def test_nested_shadow_dist_info_cannot_replace_distribution_root(self) -> None:
        site, package, dist = self._wheel()
        outer = Path(dist._path)
        shadow = outer / "shadow.dist-info"
        shadow.mkdir()
        (shadow / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: clu-governance\nVersion: 1.2.3\n\n",
            encoding="utf-8",
        )
        (shadow / "RECORD").write_text("", encoding="utf-8")
        dist.files = [
            value for value in dist.files
            if "clu_governance/" in value and not value.startswith("../")
        ] + [
            f"{outer.name}/shadow.dist-info/METADATA",
            f"{outer.name}/shadow.dist-info/RECORD",
        ]
        with self.assertRaisesRegex(
            manifest.ProtectedSourceManifestError,
            "distribution_metadata_ambiguous",
        ):
            manifest.build_protected_source_manifest(
                package_root=package, expected_version="1.2.3", distributions=[dist]
            )

    def test_wrong_dist_info_basename_is_rejected(self) -> None:
        site, package, dist = self._wheel()
        original = Path(dist._path)
        evil = site / "evil.dist-info"
        original.rename(evil)
        dist._path = evil
        dist.files = [value.replace(original.name, evil.name) for value in dist.files]
        with self.assertRaisesRegex(
            manifest.ProtectedSourceManifestError,
            "distribution_metadata_invalid",
        ):
            manifest.build_protected_source_manifest(
                package_root=package, expected_version="1.2.3", distributions=[dist]
            )

    def test_editable_mode_requires_matching_direct_url(self) -> None:
        _project, package, dist, egg_info, site = self._editable_pair()
        result = manifest.build_protected_source_manifest(
            package_root=package,
            expected_version="1.2.3",
            distributions=[dist, egg_info],
        )
        self.assertEqual(result["distribution_mode"], "editable_install")
        self.assertEqual(
            result["manifest_generation_method"],
            "editable_import_surface_plus_direct_url_and_record_v1",
        )
        self.assertEqual(Path(result["distribution_metadata_root"]).parent, site.resolve())

    def test_malformed_editable_direct_url_variants_fail_closed(self) -> None:
        original_root = self.root
        cases = {
            "contradictory": (
                lambda project: json.dumps(
                    {
                        "url": project.as_uri(),
                        "dir_info": {"editable": True},
                        "archive_info": {},
                    }
                ),
                "direct_url_malformed",
            ),
            "query": (
                lambda project: json.dumps(
                    {"url": project.as_uri() + "?unexpected=1", "dir_info": {"editable": True}}
                ),
                "editable_root_invalid",
            ),
            "nul": (
                lambda _project: json.dumps(
                    {"url": "file:///tmp/%00", "dir_info": {"editable": True}}
                ),
                "editable_root_invalid",
            ),
        }
        for name, (payload, blocker) in cases.items():
            with self.subTest(name=name):
                self.root = original_root / name
                self.root.mkdir()
                project, package = self._source_tree()
                site, _wheel_package, dist = self._wheel()
                record = next(site.glob("*.dist-info/RECORD"))
                rows = [
                    row for row in csv.reader(record.read_text(encoding="utf-8").splitlines())
                    if not row[0].startswith("clu_governance/")
                ]
                with record.open("w", encoding="utf-8", newline="") as stream:
                    csv.writer(stream).writerows(rows)
                dist.files = [
                    value for value in dist.files if not value.startswith("clu_governance/")
                ]
                dist._direct_url = payload(project)
                with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, blocker):
                    manifest.build_protected_source_manifest(
                        package_root=package,
                        expected_version="1.2.3",
                        distributions=[dist],
                    )
        self.root = original_root

    def test_direct_url_read_failure_is_structural_block(self) -> None:
        _project, package = self._source_tree()
        _site, _wheel_package, dist = self._wheel()

        def fail_read(_name: str) -> str:
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")

        dist.read_text = fail_read
        with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, "direct_url_malformed"):
            manifest.build_protected_source_manifest(
                package_root=package,
                expected_version="1.2.3",
                distributions=[dist],
            )

    def test_invalid_utf8_record_is_structural_block(self) -> None:
        site, package, dist = self._wheel()
        next(site.glob("*.dist-info/RECORD")).write_bytes(b"\xff")
        with self.assertRaisesRegex(manifest.ProtectedSourceManifestError, "record_malformed"):
            manifest.build_protected_source_manifest(
                package_root=package, expected_version="1.2.3", distributions=[dist]
            )

    def test_cli_json_is_single_privacy_bounded_object(self) -> None:
        candidate = Path(__file__).resolve().parents[1]
        env = dict(os.environ, PYTHONPATH=str(candidate / "src"), PYTHONDONTWRITEBYTECODE="1")
        completed = subprocess.run(
            [sys.executable, "-B", "-m", "clu_governance.cli", "protected-source-manifest", "--json"],
            cwd=candidate,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["result"], "ready")
        self.assertEqual(payload["package_root"], "<package_root>")
        self.assertFalse(payload["absolute_local_paths_disclosed"])
        self.assertFalse(payload["unrelated_site_packages_inventory_disclosed"])
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
