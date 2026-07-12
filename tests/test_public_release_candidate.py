from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from clu_governance import __version__


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_VERSION = "0.1.0a1"


class PublicReleaseCandidateTests(unittest.TestCase):
    def test_required_public_files_are_present(self) -> None:
        required = {
            "README.md",
            "LICENSE",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "CHANGELOG.md",
            ".gitignore",
            ".github/workflows/ci.yml",
            "docs/development-methodology.md",
            "docs/engineering-decisions.md",
            "docs/architecture.md",
        }
        self.assertEqual({path for path in required if not (ROOT / path).is_file()}, set())

    def test_public_version_surfaces_agree(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["version"], PUBLIC_VERSION)
        self.assertEqual(__version__, PUBLIC_VERSION)
        for relative in ("README.md", "CHANGELOG.md", "docs/quickstart.md", "docs/cli-contract.md"):
            self.assertIn(PUBLIC_VERSION, (ROOT / relative).read_text(encoding="utf-8"), relative)

    def test_readme_states_approval_and_adapter_boundaries(self) -> None:
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("eligible for a separate approval", text)
        self.assertIn("does **not** authorize", text)
        self.assertIn("Experimental Git adapter", text)
        self.assertIn("not a sandbox", text)

    def test_security_and_adapter_docs_have_visible_warning(self) -> None:
        for relative in ("SECURITY.md", "docs/git-diff-adapter.md"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("experimental", text.lower(), relative)
            self.assertIn("trusted local", text.lower(), relative)
            self.assertIn("not a sandbox", text.lower(), relative)

    def test_development_methodology_describes_human_direction_and_ai_assistance(self) -> None:
        text = (ROOT / "docs/development-methodology.md").read_text(encoding="utf-8")
        self.assertIn("Gabriel Williams", text)
        self.assertIn("human-directed", text)
        self.assertIn("Codex and ChatGPT", text)
        self.assertIn("does not establish correctness", text)

    def test_ci_declares_focused_public_jobs(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        for job in (
            "core_linux:",
            "core_macos:",
            "macos_git_adapter:",
            "package_wheel:",
            "editable_install:",
            "hygiene_and_strict_json:",
        ):
            self.assertIn(job, workflow)
        self.assertNotIn("-m pytest", workflow)
        self.assertNotIn("publish", workflow.lower())

    def test_ci_partitions_macos_adapter_execution_and_has_no_release_credentials(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        linux_job = workflow.split("  core_linux:", 1)[1].split("  core_macos:", 1)[0]
        macos_adapter_job = workflow.split("  macos_git_adapter:", 1)[1].split(
            "  package_wheel:", 1
        )[0]
        self.assertIn("unittest discover -s tests -q", linux_job)
        self.assertIn("expected skips", linux_job)
        self.assertNotIn("Run macOS adapter integration suite without skips", linux_job)
        self.assertIn("Run macOS adapter integration suite without skips", macos_adapter_job)
        self.assertIn("result.skipped", macos_adapter_job)
        for filename in (
            "test_git_diff_adapter.py",
            "test_git_snapshot_closure.py",
            "test_git_publication_binding.py",
            "test_git_ref_storage.py",
            "test_git_path_result_contract.py",
            "test_bundle_verifier.py",
            "test_bundle_verifier_semantic_binding.py",
        ):
            self.assertIn(filename, macos_adapter_job)
        lowered = workflow.lower()
        for forbidden in ("secrets.", "gh release", "twine upload", "python -m build --upload"):
            self.assertNotIn(forbidden, lowered)

    def test_git_adapter_docs_state_the_unsupported_platform_blocker(self) -> None:
        text = (ROOT / "docs/git-diff-adapter.md").read_text(encoding="utf-8")
        self.assertIn("content_sensitive_git_sandbox_unavailable", text)
        self.assertIn("Linux CI verifies", text)

    def test_cli_docs_state_initial_missing_bundle_path_contract(self) -> None:
        text = (ROOT / "docs/cli-contract.md").read_text(encoding="utf-8")
        self.assertIn("bundle_path_missing", text)
        self.assertIn("bundle_parent_symlink_or_identity_denied", text)
        self.assertIn("bundle_parent_identity_changed", text)

    def test_public_docs_do_not_embed_local_workspace_markers(self) -> None:
        forbidden = (
            "/" + "Users/",
            "/" + "home/",
            "Documents" + "/Codex",
            "EVIDENCE" + "_ROOTS",
        )
        for path in [ROOT / "README.md", *(ROOT / "docs").glob("*.md"), ROOT / "SECURITY.md"]:
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, text, path)


if __name__ == "__main__":
    unittest.main()
