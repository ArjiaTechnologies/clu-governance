"""Agent-neutral stdin/stdout bridge for the existing policy evaluator.

The bridge accepts one strict JSON envelope, delegates to the existing
read-only evaluator, and writes exactly one JSON object to stdout. It never
records approval, applies a mutation, starts an agent, or starts a subprocess.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TextIO

from . import strict_json
from .source_mutation_policy_gate import DENIAL_EXIT_CODE, evaluate_source_mutation_request


INPUT_SCHEMA_NAME = "clu_governance_agent_preflight_input.v1"
ERROR_SCHEMA_NAME = "clu_governance_agent_preflight_error.v1"
SCHEMA_VERSION = "1"
INPUT_REJECTION_EXIT_CODE = 1
RUNTIME_FAILURE_EXIT_CODE = 1
REQUIRED_INPUT_FIELDS = {
    "schema_name",
    "schema_version",
    "policy_path",
    "request_path",
    "source_root",
    "event_timestamp",
    "sequence_index",
}


class AgentPreflightInputError(ValueError):
    """Raised with a stable public blocker for invalid adapter input."""


def error_payload(*, result: str, exact_blocker: str) -> dict[str, Any]:
    """Build a bounded JSON result without echoing caller-controlled paths."""

    return {
        "schema_name": ERROR_SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "result": result,
        "exact_blocker": exact_blocker,
        "eligible_for_human_approval": False,
        "operator_approval_required": True,
        "approval_recorded": False,
        "application_requested": False,
        "mutation_authorized": False,
        "mutation_applied": False,
        "agent_subprocess_started": False,
        "provider_calls": 0,
        "advisor_calls": 0,
        "mem0_runs": 0,
        "benchmark_runs": 0,
        "network_calls": 0,
    }


def _absolute_path(value: Any, *, field_name: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise AgentPreflightInputError(f"agent_preflight_input_{field_name}_missing_or_invalid")
    path = Path(value)
    if not path.is_absolute():
        raise AgentPreflightInputError(f"agent_preflight_input_{field_name}_must_be_absolute")
    return path


def parse_input(document: str) -> tuple[Path, Path, Path, str, int]:
    """Validate one deterministic adapter envelope before delegation."""

    if not document.strip():
        raise AgentPreflightInputError("agent_preflight_input_missing")
    try:
        payload = strict_json.loads(document)
    except strict_json.DuplicateJSONKeyError:
        raise AgentPreflightInputError("agent_preflight_input_duplicate_json_key") from None
    except Exception:
        raise AgentPreflightInputError("agent_preflight_input_malformed_json") from None
    if not isinstance(payload, dict):
        raise AgentPreflightInputError("agent_preflight_input_not_object")
    supplied_fields = set(payload)
    if REQUIRED_INPUT_FIELDS - supplied_fields:
        raise AgentPreflightInputError("agent_preflight_input_required_field_missing")
    if supplied_fields - REQUIRED_INPUT_FIELDS:
        raise AgentPreflightInputError("agent_preflight_input_unknown_field")
    if payload.get("schema_name") != INPUT_SCHEMA_NAME:
        raise AgentPreflightInputError("agent_preflight_input_schema_name_invalid")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise AgentPreflightInputError("agent_preflight_input_schema_version_invalid")

    event_timestamp = payload.get("event_timestamp")
    if not isinstance(event_timestamp, str) or not event_timestamp.strip():
        raise AgentPreflightInputError("agent_preflight_input_event_timestamp_missing_or_invalid")
    sequence_index = payload.get("sequence_index")
    if isinstance(sequence_index, bool) or not isinstance(sequence_index, int) or sequence_index < 1:
        raise AgentPreflightInputError("agent_preflight_input_sequence_index_invalid")
    return (
        _absolute_path(payload.get("policy_path"), field_name="policy_path"),
        _absolute_path(payload.get("request_path"), field_name="request_path"),
        _absolute_path(payload.get("source_root"), field_name="source_root"),
        event_timestamp,
        sequence_index,
    )


def run(document: str) -> tuple[int, dict[str, Any]]:
    """Evaluate a proposal through the existing contract without writing files."""

    try:
        policy_path, request_path, source_root, event_timestamp, sequence_index = parse_input(document)
    except AgentPreflightInputError as exc:
        return INPUT_REJECTION_EXIT_CODE, error_payload(result="input_rejected", exact_blocker=str(exc))

    try:
        decision = evaluate_source_mutation_request(
            policy_path=policy_path,
            request_path=request_path,
            source_root=source_root,
            event_timestamp=event_timestamp,
            sequence_index=sequence_index,
        )
    except Exception:
        return RUNTIME_FAILURE_EXIT_CODE, error_payload(result="failed", exact_blocker="agent_preflight_evaluation_failed")
    return (0 if decision.get("decision") == "allow" else DENIAL_EXIT_CODE), decision


def main(argv: list[str] | None = None, *, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Run the stable stdin/stdout adapter command."""

    if argv not in (None, []):
        payload = error_payload(result="input_rejected", exact_blocker="agent_preflight_arguments_not_supported")
        (stdout or sys.stdout).write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return INPUT_REJECTION_EXIT_CODE
    exit_code, payload = run((stdin or sys.stdin).read())
    (stdout or sys.stdout).write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return exit_code
