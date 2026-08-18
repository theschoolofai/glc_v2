"""CF-2 — JSON schema bomb (#25).

These tests arrived with PR #25, written against that branch's own validator,
which raised ``ValueError`` and enforced a wall-clock timeout through a thread
pool. The consolidated implementation on ``main`` bounds the schema up front in
``assert_schema_sane()`` and rejects with ``HTTPException(400)`` instead, so a
bomb never reaches the validator and no timeout is needed. The assertions below
target that behaviour.

The pool/timeout test from the original file is deliberately not carried over:
``main`` has no ``_VALIDATOR_POOL`` to exercise.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException


def test_cf2_self_ref_raises_immediately():
    """A ``$ref: '#'`` schema must be rejected before validation starts."""
    from glc.routes.chat import _validate_structured

    with pytest.raises(HTTPException, match="self-referential") as ei:
        _validate_structured('{"x": 1}', {"$ref": "#"})
    assert ei.value.status_code == 400


def test_cf2_nested_self_ref_raises():
    """A nested self-referential ``$ref`` must also be caught.

    This shape is small enough to clear both the depth and the node cap, so it
    is the case that proves the pointer is rejected by value rather than by
    the structural bounds.
    """
    from glc.routes.chat import _validate_structured

    with pytest.raises(HTTPException, match="self-referential") as ei:
        _validate_structured('{"a": 1}', {"properties": {"a": {"$ref": "#"}}})
    assert ei.value.status_code == 400


def test_cf2_depth_limit_raises():
    """A schema nested past MAX_SCHEMA_DEPTH must be rejected."""
    from glc.routes.chat import MAX_SCHEMA_DEPTH, _validate_structured

    deep: dict = {"type": "string"}
    for _ in range(MAX_SCHEMA_DEPTH + 5):
        deep = {"properties": {"x": deep}}
    with pytest.raises(HTTPException, match="too deeply nested") as ei:
        _validate_structured("{}", deep)
    assert ei.value.status_code == 400


def test_cf2_ordinary_ref_still_allowed():
    """Only root-pointing refs are bombs; a normal ``$defs`` ref must survive."""
    from glc.routes.chat import assert_schema_sane

    assert_schema_sane(
        {
            "type": "object",
            "properties": {"n": {"$ref": "#/$defs/pos"}},
            "$defs": {"pos": {"type": "integer", "minimum": 0}},
        }
    )


def test_cf2_valid_schema_passes():
    """A well-formed schema with a matching object must pass without error."""
    from glc.routes.chat import _validate_structured

    schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
        "required": ["name"],
    }
    assert _validate_structured('{"name": "Alice", "age": 30}', schema) == {
        "name": "Alice",
        "age": 30,
    }


def test_cf2_invalid_json_raises():
    """Non-JSON text must raise ValueError mentioning JSON."""
    from glc.routes.chat import _validate_structured

    with pytest.raises(ValueError, match="not JSON"):
        _validate_structured("not json at all", {"type": "object"})


def test_cf2_schema_mismatch_raises_validation_error():
    """A JSON value that violates the schema must raise jsonschema.ValidationError."""
    from jsonschema import ValidationError

    from glc.routes.chat import _validate_structured

    schema = {"type": "object", "properties": {"count": {"type": "integer"}}, "required": ["count"]}
    with pytest.raises(ValidationError):
        _validate_structured('{"count": "not-an-int"}', schema)
