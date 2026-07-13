"""Standalone CLU Governance source-mutation gate package."""

__version__ = "0.1.0a2"

__all__ = [
    "__version__",
    "canonical_sha256",
    "evaluate_source_mutation_request",
    "verify_decision_artifact",
]


def __getattr__(name: str):
    if name in __all__:
        if name == "__version__":
            return __version__
        from . import source_mutation_policy_gate as gate

        return getattr(gate, name)
    raise AttributeError(name)
