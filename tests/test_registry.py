"""Tests for the declarative tool registry."""

import pytest
from codesight_mcp.tools.registry import (
    ToolSpec, register, get_all_specs,
    _snapshot_registry, _restore_registry,
)


@pytest.fixture(autouse=True)
def isolated_registry():
    """Save registry state before each test, restore after."""
    snapshot = _snapshot_registry()
    # Start each test with an empty registry so test-registered tools
    # don't collide with the real tool specs.
    _restore_registry({})
    yield
    _restore_registry(snapshot)


def _noop(args, storage_path):
    return {}


def test_register_and_retrieve():
    spec = register(ToolSpec(
        name="test_tool",
        description="A test tool",
        input_schema={"type": "object", "properties": {}},
        handler=_noop,
    ))
    assert spec.name == "test_tool"
    specs = get_all_specs()
    assert "test_tool" in specs
    assert specs["test_tool"] is spec


def test_duplicate_registration_raises():
    register(ToolSpec(
        name="dup_tool",
        description="First",
        input_schema={},
        handler=_noop,
    ))
    with pytest.raises(ValueError, match="Duplicate tool registration: dup_tool"):
        register(ToolSpec(
            name="dup_tool",
            description="Second",
            input_schema={},
            handler=_noop,
        ))


def test_get_all_specs_returns_copy():
    register(ToolSpec(
        name="copy_test",
        description="Copy test",
        input_schema={},
        handler=_noop,
    ))
    specs1 = get_all_specs()
    specs2 = get_all_specs()
    assert specs1 is not specs2
    assert specs1 == specs2


def test_flags_default_false():
    spec = ToolSpec(
        name="flags_test",
        description="Flags",
        input_schema={},
        handler=_noop,
    )
    assert spec.untrusted is False
    assert spec.index_gate is False
    assert spec.destructive is False
    assert spec.text_search is False
    assert spec.required_args == []


def test_flags_set_correctly():
    spec = ToolSpec(
        name="flagged",
        description="Flagged",
        input_schema={},
        handler=_noop,
        untrusted=True,
        index_gate=True,
        destructive=True,
        text_search=True,
        required_args=["repo"],
    )
    assert spec.untrusted is True
    assert spec.index_gate is True
    assert spec.destructive is True
    assert spec.text_search is True
    assert spec.required_args == ["repo"]


def test_multiple_registrations():
    for i in range(5):
        register(ToolSpec(
            name=f"tool_{i}",
            description=f"Tool {i}",
            input_schema={},
            handler=_noop,
        ))
    specs = get_all_specs()
    assert len(specs) == 5
    for i in range(5):
        assert f"tool_{i}" in specs
