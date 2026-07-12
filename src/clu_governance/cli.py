"""Public console entry point for CLU Governance.

This module intentionally contains no policy, approval, execution, rollback,
workspace, or compensation logic. It exposes package version reporting and
delegates the command contract to the existing policy-gate implementation.
"""

from __future__ import annotations

import sys

from . import __version__
from .source_mutation_policy_gate import main as policy_gate_main


EXECUTABLE_NAME = "clu-governance"


def main(argv: list[str] | None = None) -> int:
    """Run the versioned public CLI without duplicating governance logic."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--version"]:
        print(f"{EXECUTABLE_NAME} {__version__}")
        return 0
    return policy_gate_main(arguments)


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess tests.
    raise SystemExit(main())
