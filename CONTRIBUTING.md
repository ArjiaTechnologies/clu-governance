# Contributing

Thanks for helping improve CLU Governance. This project is a pre-alpha local developer tool, so focused, reproducible changes are especially valuable.

## Local setup

Use CPython 3.12 and a local checkout:

```bash
python -m pip install -e .
python -B -m unittest discover -s tests -q
```

The cross-platform/core command above passes on Linux. Linux reports expected skips for the tests that require successful macOS `git-adapt` execution; it still runs portable parser, result-contract, CLI-help, bundle-verifier, policy, and package checks. Unsupported-platform behavior is a fail-closed contract, not an emulation of macOS adapter success.

On macOS, also run the real adapter-integration suite:

```bash
python -B -m unittest tests/test_git_diff_adapter.py tests/test_git_snapshot_closure.py tests/test_git_publication_binding.py tests/test_git_ref_storage.py tests/test_git_path_result_contract.py tests/test_bundle_verifier.py tests/test_bundle_verifier_semantic_binding.py -q
```

Useful focused checks include:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -B -m unittest tests/test_protected_source_manifest.py -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -B -m unittest tests/test_public_cli.py tests/test_strict_json_boundaries.py -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -B -m clu_governance.cli demo-run-all --json
```

## Change expectations

- Keep code compatible with the supported Python version and the zero-runtime-dependency design.
- Add focused regression tests for behavioral changes.
- Keep JSON handling strict and keep `--json` output to one object on stdout.
- Use clear, conventional Python formatting and type-aware code; avoid unrelated rewrites.
- Update documentation when a user-visible contract, supported installation path, or limitation changes.
- State claims narrowly. Do not describe a feature as production-ready, authenticated, non-bypassable, immutable, tamper-evident, or guaranteed unless the executable behavior and evidence support that claim.

Do not add network calls, provider integrations, autonomous mutation behavior, or new source-writing behavior without explicit design review. An allow decision must remain distinct from approval and application.

Changes to `git-adapt` require focused macOS validation because its supported boundary is macOS/Python/Git and trusted-local single-user repositories. Linux contributors should verify the documented fail-closed result, not expect successful adapter integration execution.

## Reporting bugs

Please provide a small reproduction, the version, operating system, Python version, command, expected result, and actual result. Do not include credentials, customer data, or private repository contents. For security-sensitive reports, follow [SECURITY.md](SECURITY.md) rather than opening a public issue.
