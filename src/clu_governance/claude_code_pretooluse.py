"""Thin, local Claude Code ``PreToolUse`` translation over agent-preflight.

This module deliberately owns no policy rules.  It converts the narrow,
supported Claude Code ``Edit`` hook shape into an ephemeral generic
``agent-preflight`` envelope, then translates the resulting evidence into the
documented Claude Code hook response.  In particular, a CLU policy allow is
translated to Claude Code's ``ask`` decision, never to ``allow``.
"""

from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from . import agent_preflight, strict_json
from .source_mutation_policy_gate import (
    ROLLBACK_SCHEMA_NAME,
    REQUEST_SCHEMA_NAME,
    canonical_sha256,
    sha256_file,
    source_tree_hash,
)


SUPPORTED_HOOK_EVENT = "PreToolUse"
SUPPORTED_TOOL = "Edit"
DECLARED_ACTOR_ID = "claude_code"
REQUESTED_SCOPE = "claude_code_edit"


class ClaudePreToolUseInputError(ValueError):
    """Raised with a stable blocker for malformed hook input."""


@dataclass(frozen=True)
class EditInvocation:
    """The bounded supported subset of one Claude Code Edit tool call."""

    source_root: Path
    target: Path
    relative_path: str
    original_content: str
    old_string: str
    new_string: str


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _parse_document(document: str) -> dict[str, Any]:
    if not document.strip():
        raise ClaudePreToolUseInputError("claude_pretooluse_input_missing")
    try:
        payload = strict_json.loads(document)
    except strict_json.DuplicateJSONKeyError:
        raise ClaudePreToolUseInputError("claude_pretooluse_input_duplicate_json_key") from None
    except Exception:
        raise ClaudePreToolUseInputError("claude_pretooluse_input_malformed_json") from None
    if not isinstance(payload, dict):
        raise ClaudePreToolUseInputError("claude_pretooluse_input_not_object")
    return payload


def parse_hook_input(document: str) -> tuple[str, EditInvocation | None]:
    """Parse the official command-hook fields needed by this narrow adapter.

    Unknown outer hook fields are deliberately ignored.  Claude Code provides
    additional common fields, and this adapter only needs the documented event,
    tool name, working directory, and ``Edit`` input to build a preflight.
    """

    payload = _parse_document(document)
    if payload.get("hook_event_name") != SUPPORTED_HOOK_EVENT:
        raise ClaudePreToolUseInputError("claude_pretooluse_hook_event_invalid")
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        raise ClaudePreToolUseInputError("claude_pretooluse_tool_name_missing_or_invalid")
    if tool_name != SUPPORTED_TOOL:
        return tool_name, None

    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        raise ClaudePreToolUseInputError("claude_pretooluse_cwd_missing_or_invalid")
    source_root = Path(cwd)
    if not source_root.is_absolute():
        raise ClaudePreToolUseInputError("claude_pretooluse_cwd_must_be_absolute")
    try:
        source_root = source_root.resolve(strict=True)
    except OSError:
        raise ClaudePreToolUseInputError("claude_pretooluse_cwd_missing_or_invalid") from None
    if not source_root.is_dir():
        raise ClaudePreToolUseInputError("claude_pretooluse_cwd_missing_or_invalid")

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        raise ClaudePreToolUseInputError("claude_pretooluse_tool_input_missing_or_invalid")
    raw_path = tool_input.get("file_path")
    if not isinstance(raw_path, str) or not raw_path:
        raise ClaudePreToolUseInputError("claude_edit_file_path_missing_or_invalid")
    raw_target = Path(raw_path)
    if not raw_target.is_absolute():
        raise ClaudePreToolUseInputError("claude_edit_file_path_must_be_absolute")
    if raw_target.is_symlink():
        raise ClaudePreToolUseInputError("claude_edit_target_symlink_denied")
    try:
        target = raw_target.resolve(strict=True)
    except OSError:
        raise ClaudePreToolUseInputError("claude_edit_target_missing_or_invalid") from None
    if not _is_relative_to(target, source_root):
        raise ClaudePreToolUseInputError("claude_edit_target_outside_project_denied")
    if not target.is_file():
        raise ClaudePreToolUseInputError("claude_edit_target_missing_or_invalid")

    old_string = tool_input.get("old_string")
    if not isinstance(old_string, str):
        raise ClaudePreToolUseInputError("claude_edit_old_string_missing_or_invalid")
    if not old_string:
        raise ClaudePreToolUseInputError("claude_edit_old_string_empty_unsupported")
    new_string = tool_input.get("new_string")
    if not isinstance(new_string, str):
        raise ClaudePreToolUseInputError("claude_edit_new_string_missing_or_invalid")
    replace_all = tool_input.get("replace_all", False)
    if not isinstance(replace_all, bool):
        raise ClaudePreToolUseInputError("claude_edit_replace_all_invalid")
    if replace_all:
        raise ClaudePreToolUseInputError("claude_edit_replace_all_unsupported")
    try:
        original_content = target.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise ClaudePreToolUseInputError("claude_edit_target_not_utf8") from None
    except OSError:
        raise ClaudePreToolUseInputError("claude_edit_target_missing_or_invalid") from None
    matches = original_content.count(old_string)
    if matches == 0:
        raise ClaudePreToolUseInputError("claude_edit_old_string_not_found")
    if matches != 1:
        raise ClaudePreToolUseInputError("claude_edit_old_string_not_unique")
    return tool_name, EditInvocation(
        source_root=source_root,
        target=target,
        relative_path=target.relative_to(source_root).as_posix(),
        original_content=original_content,
        old_string=old_string,
        new_string=new_string,
    )


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_preflight_document(invocation: EditInvocation, temporary_root: Path) -> str:
    """Build the generic contract files in a disposable directory only."""

    before_sha256 = sha256_file(invocation.target)
    proposed_content = invocation.original_content.replace(invocation.old_string, invocation.new_string, 1)
    proposal_body = {
        "tool": SUPPORTED_TOOL,
        "path": invocation.relative_path,
        "old_content_sha256": canonical_sha256(invocation.old_string),
        "new_content_sha256": canonical_sha256(invocation.new_string),
        "proposed_content": proposed_content,
        "replacement_count": 1,
    }
    proposal_id = f"claude-code-edit-{canonical_sha256(proposal_body)[:16]}"
    rollback = {
        "schema_name": ROLLBACK_SCHEMA_NAME,
        "schema_version": "1",
        "snapshot_id": f"claude-code-pretooluse-{before_sha256[:16]}",
        "files": {
            invocation.relative_path: {
                "path": invocation.relative_path,
                "before_sha256": before_sha256,
                "original_content": invocation.original_content,
                "content_encoding": "utf-8",
            }
        },
    }
    rollback_path = temporary_root / "rollback.json"
    _write_json(rollback_path, rollback)
    request = {
        "schema_name": REQUEST_SCHEMA_NAME,
        "schema_version": "1",
        "request_id": f"claude-code-pretooluse-{canonical_sha256(proposal_body)[:16]}",
        "declared_actor_id": DECLARED_ACTOR_ID,
        "actor_identity_source": "caller_declared",
        "requested_scope": REQUESTED_SCOPE,
        "proposal_id": proposal_id,
        "proposal_body": proposal_body,
        "proposal_hash": canonical_sha256(proposal_body),
        "source_tree_hash": source_tree_hash(invocation.source_root),
        "operations": [
            {
                "operation": "modify",
                "path": invocation.relative_path,
                "before_sha256": before_sha256,
            }
        ],
        "rollback_readiness": {
            "schema_name": ROLLBACK_SCHEMA_NAME,
            "schema_version": "1",
            "artifact_path": str(rollback_path),
            "artifact_sha256": sha256_file(rollback_path),
            "files": {invocation.relative_path: {"before_sha256": before_sha256}},
        },
    }
    request_path = temporary_root / "request.json"
    _write_json(request_path, request)
    envelope = {
        "schema_name": agent_preflight.INPUT_SCHEMA_NAME,
        "schema_version": agent_preflight.SCHEMA_VERSION,
        "policy_path": "",  # Filled only by the caller after policy-path validation.
        "request_path": str(request_path),
        "source_root": str(invocation.source_root),
        "event_timestamp": _now_utc(),
        "sequence_index": 1,
    }
    return json.dumps(envelope, sort_keys=True)


def _hook_response(decision: str, reason: str) -> dict[str, Any]:
    """Return the documented structured PreToolUse command-hook response."""

    return {
        "hookSpecificOutput": {
            "hookEventName": SUPPORTED_HOOK_EVENT,
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def _deny(blocker: str, *, next_step: str) -> tuple[int, dict[str, Any]]:
    return 0, _hook_response(
        "deny",
        f"CLU preflight denied this Edit (blocker: {blocker}). Next step: {next_step}",
    )


def _ask_for_unsupported(tool_name: str) -> tuple[int, dict[str, Any]]:
    return 0, _hook_response(
        "ask",
        f"CLU did not evaluate {tool_name}: this experimental adapter supports Edit only. "
        "Next step: use a supported Edit or continue through Claude Code's normal permission flow.",
    )


def run(
    document: str,
    *,
    policy_path: Path,
    temporary_parent: Path | None = None,
) -> tuple[int, dict[str, Any]]:
    """Translate one hook call through the existing generic preflight contract.

    ``temporary_parent`` is intentionally an internal test seam.  It lets the
    regression suite prove cleanup without adding a user-facing state option.
    """

    if not policy_path.is_absolute():
        return _deny(
            "claude_pretooluse_policy_path_must_be_absolute",
            next_step="configure an absolute project-local policy path and retry.",
        )
    try:
        tool_name, invocation = parse_hook_input(document)
    except ClaudePreToolUseInputError as exc:
        return _deny(str(exc), next_step="correct the hook input and retry.")
    if invocation is None:
        return _ask_for_unsupported(tool_name)

    try:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="clu-governance-claude-pretooluse-",
            dir=str(temporary_parent) if temporary_parent is not None else None,
        )
        with temporary_directory as temporary_name:
            temporary_root = Path(temporary_name)
            envelope = json.loads(_build_preflight_document(invocation, temporary_root))
            envelope["policy_path"] = str(policy_path)
            exit_code, evidence = agent_preflight.run(json.dumps(envelope, sort_keys=True))
    except Exception:
        return _deny(
            "claude_pretooluse_local_preflight_failed",
            next_step="check the project policy and source state, then retry.",
        )

    if exit_code == 0 and evidence.get("decision") == "allow":
        return 0, _hook_response(
            "ask",
            "CLU preflight found this Edit eligible for separate approval; it is not an automatic permission approval. "
            "Next step: complete Claude Code's normal permission prompt.",
        )
    if exit_code == 2 and evidence.get("decision") == "deny":
        blocker = evidence.get("exact_blocker")
        if not isinstance(blocker, str) or not blocker:
            blocker = "claude_pretooluse_policy_denied"
        return _deny(blocker, next_step="update the proposed edit or local policy, then retry.")
    blocker = evidence.get("exact_blocker")
    if not isinstance(blocker, str) or not blocker:
        blocker = "claude_pretooluse_invalid_agent_preflight_result"
    return _deny(blocker, next_step="check the local preflight inputs and retry.")


def main(
    argv: list[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> int:
    """Run the hook adapter with the policy argument supplied by the CLI shim."""

    arguments = [] if argv is None else list(argv)
    if len(arguments) != 2 or arguments[0] != "--policy":
        _, payload = _deny(
            "claude_pretooluse_policy_argument_required",
            next_step="configure the hook with --policy <absolute-policy-path>.",
        )
    else:
        _, payload = run((stdin or sys.stdin).read(), policy_path=Path(arguments[1]))
    (stdout or sys.stdout).write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0
