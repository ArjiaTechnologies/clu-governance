from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from clu_governance.bundle_verifier import verify_bundle
from clu_governance.path_chain import AbsoluteDirectoryChainLease, PathChainError


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SRC = (PACKAGE_ROOT / "src").resolve()
MISSING_BUNDLE_BLOCKER = "bundle_path_missing"
SYMLINKED_ANCESTOR_BLOCKER = "bundle_parent_symlink_or_identity_denied"
REPLACED_BOUND_ROOT_BLOCKER = "bundle_parent_identity_changed"
DISAPPEARED_BOUND_ROOT_BLOCKER = "caller_visible_bundle_path_replaced"


def parse_single_json(stdout: str) -> dict[str, object]:
    decoder = json.JSONDecoder()
    payload, end = decoder.raw_decode(stdout)
    if stdout[end:].strip() or not isinstance(payload, dict):
        raise AssertionError("expected exactly one JSON object on stdout")
    return payload


def assert_no_symlink_ancestors(test: unittest.TestCase, path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        test.assertFalse(current.is_symlink(), current)


class BundleVerifierPortableContractTest(unittest.TestCase):
    """Portable verifier checks remain active when macOS bundle fixtures skip."""

    def test_nonexistent_leaf_under_real_parent_fails_closed_in_direct_and_cli_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="clu-bundle-verifier-platform.") as temporary:
            parent = Path(temporary).resolve(strict=True)
            self.assertTrue(parent.is_dir())
            assert_no_symlink_ancestors(self, parent)
            missing = parent / "missing-bundle"
            self.assertFalse(missing.exists())
            before = sorted(path.name for path in parent.iterdir())
            result = verify_bundle(missing)
            self.assertEqual(result["result"], "invalid")
            self.assertFalse(result["verified"])
            self.assertEqual(result["exact_blocker"], MISSING_BUNDLE_BLOCKER)
            self.assertFalse(result["verification_mutation_performed"])
            self.assertFalse(result["cleanup_performed"])
            self.assertEqual(sorted(path.name for path in parent.iterdir()), before)

            process = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "clu_governance.cli",
                    "verify-bundle",
                    "--bundle",
                    str(missing),
                    "--json",
                ],
                cwd=PACKAGE_ROOT,
                env={
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": str(PACKAGE_SRC),
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
            )
            self.assertEqual(sorted(path.name for path in parent.iterdir()), before)
        self.assertEqual(process.returncode, 2, process.stderr or process.stdout)
        self.assertEqual(process.stderr, "")
        payload = parse_single_json(process.stdout)
        self.assertEqual(payload["result"], "invalid")
        self.assertEqual(payload["exact_blocker"], MISSING_BUNDLE_BLOCKER)
        self.assertFalse(payload["verification_mutation_performed"])
        self.assertFalse(payload["cleanup_performed"])

    def test_symlinked_ancestor_remains_a_no_follow_blocker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="clu-bundle-verifier-platform.") as temporary:
            real_parent = Path(temporary).resolve(strict=True)
            assert_no_symlink_ancestors(self, real_parent)
            target = real_parent / "target"
            target.mkdir()
            symlinked_parent = real_parent / "symlinked-parent"
            os.symlink(target, symlinked_parent, target_is_directory=True)
            self.assertTrue(symlinked_parent.is_symlink())
            before = sorted(path.name for path in real_parent.iterdir())
            result = verify_bundle(symlinked_parent / "missing-bundle")
            self.assertEqual(result["result"], "invalid")
            self.assertEqual(result["exact_blocker"], SYMLINKED_ANCESTOR_BLOCKER)
            self.assertFalse(result["verification_mutation_performed"])
            self.assertFalse(result["cleanup_performed"])
            self.assertEqual(sorted(path.name for path in real_parent.iterdir()), before)

    def test_nonexistent_ancestor_is_an_initial_missing_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="clu-bundle-verifier-platform.") as temporary:
            parent = Path(temporary).resolve(strict=True)
            assert_no_symlink_ancestors(self, parent)
            missing = parent / "missing-parent" / "bundle"
            before = sorted(path.name for path in parent.iterdir())
            result = verify_bundle(missing)
            self.assertEqual(result["result"], "invalid")
            self.assertEqual(result["exact_blocker"], MISSING_BUNDLE_BLOCKER)
            self.assertFalse(result["verification_mutation_performed"])
            self.assertFalse(result["cleanup_performed"])
            self.assertEqual(sorted(path.name for path in parent.iterdir()), before)

    def test_bound_root_replacement_has_a_replacement_specific_blocker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="clu-bundle-verifier-platform.") as temporary:
            parent = Path(temporary).resolve(strict=True)
            assert_no_symlink_ancestors(self, parent)
            bundle = parent / "bundle"
            bundle.mkdir()
            lease = AbsoluteDirectoryChainLease.acquire(bundle)
            displaced = parent / "bundle-displaced"
            try:
                os.rename(bundle, displaced)
                bundle.mkdir()
                # The replacement changes the bound parent namespace before
                # the rebind can accept the new root directory.
                with self.assertRaisesRegex(PathChainError, REPLACED_BOUND_ROOT_BLOCKER):
                    lease.fresh_rebind()
                self.assertTrue(displaced.is_dir())
                self.assertTrue(bundle.is_dir())
            finally:
                lease.close()

    def test_bound_root_disappearance_is_not_reclassified_as_initial_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="clu-bundle-verifier-platform.") as temporary:
            parent = Path(temporary).resolve(strict=True)
            assert_no_symlink_ancestors(self, parent)
            bundle = parent / "bundle"
            bundle.mkdir()
            lease = AbsoluteDirectoryChainLease.acquire(bundle)
            try:
                bundle.rmdir()
                with self.assertRaisesRegex(PathChainError, DISAPPEARED_BOUND_ROOT_BLOCKER):
                    lease.fresh_rebind()
                self.assertFalse(bundle.exists())
            finally:
                lease.close()


if __name__ == "__main__":
    unittest.main()
