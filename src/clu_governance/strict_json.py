"""Strict standard-library JSON decoding for governance artifacts.

The default decoder accepts duplicate object keys and non-finite numeric
extensions. Deeply nested inputs can also escape an ordinary JSON error path
as ``RecursionError``. Governance inputs fail closed on all three conditions.
"""

from __future__ import annotations

import json
import math
from typing import Any


MAX_JSON_NESTING_DEPTH = 128


class StrictJSONDecodeError(json.JSONDecodeError):
    """Bounded JSON error that never retains caller-controlled document text."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason, "", 0)


class DuplicateJSONKeyError(StrictJSONDecodeError):
    def __init__(self) -> None:
        super().__init__("duplicate_json_key")


class NonFiniteJSONNumberError(StrictJSONDecodeError):
    def __init__(self) -> None:
        super().__init__("non_finite_json_number")


class JSONNestingDepthError(StrictJSONDecodeError):
    def __init__(self) -> None:
        super().__init__("json_nesting_depth_exceeded")


class InvalidUnicodeJSONError(StrictJSONDecodeError):
    def __init__(self) -> None:
        super().__init__("invalid_json_unicode_scalar")


def _text_for_preflight(document: str | bytes | bytearray) -> str:
    if isinstance(document, str):
        return document
    raw = bytes(document)
    return raw.decode(json.detect_encoding(raw), errors="strict")


def _enforce_nesting_limit(document: str | bytes | bytearray) -> None:
    text = _text_for_preflight(document)
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING_DEPTH:
                raise JSONNestingDepthError()
        elif character in "]}":
            depth = max(0, depth - 1)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJSONKeyError()
        value[key] = item
    return value


def _reject_non_finite_constant(_value: str) -> Any:
    raise NonFiniteJSONNumberError()


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise NonFiniteJSONNumberError()
    return parsed


def _normalize_unicode_scalars(value: Any) -> Any:
    """Combine valid surrogate pairs and reject lone surrogate code points."""

    if isinstance(value, str):
        output: list[str] = []
        index = 0
        while index < len(value):
            codepoint = ord(value[index])
            if 0xD800 <= codepoint <= 0xDBFF:
                if index + 1 >= len(value):
                    raise InvalidUnicodeJSONError()
                low = ord(value[index + 1])
                if not 0xDC00 <= low <= 0xDFFF:
                    raise InvalidUnicodeJSONError()
                output.append(
                    chr(0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00))
                )
                index += 2
                continue
            if 0xDC00 <= codepoint <= 0xDFFF:
                raise InvalidUnicodeJSONError()
            output.append(value[index])
            index += 1
        return "".join(output)
    if isinstance(value, list):
        return [_normalize_unicode_scalars(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = _normalize_unicode_scalars(key)
            if normalized_key in normalized:
                raise DuplicateJSONKeyError()
            normalized[normalized_key] = _normalize_unicode_scalars(item)
        return normalized
    return value


def loads(document: str | bytes | bytearray) -> Any:
    """Decode strict JSON with bounded, ``JSONDecodeError``-compatible failures."""

    _enforce_nesting_limit(document)
    try:
        parsed = json.loads(
            document,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_non_finite_constant,
            parse_float=_parse_finite_float,
        )
        return _normalize_unicode_scalars(parsed)
    except RecursionError as exc:
        raise JSONNestingDepthError() from exc
