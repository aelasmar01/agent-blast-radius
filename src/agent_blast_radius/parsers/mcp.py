"""MCP ``tools/list`` result → tools with argument names.

Accepts the JSON-RPC result object (``{"tools": [...]}``), a full JSON-RPC response
(``{"result": {"tools": [...]}}``), or a bare list of tool objects. Argument names come
from ``inputSchema.properties`` and become the valid set for ``tainted_inputs``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..errors import IRValidationError
from . import ParsedTool


def parse(raw: Any, source: str = "") -> tuple[ParsedTool, ...]:
    if isinstance(raw, dict) and "result" in raw:
        raw = raw["result"]
    if isinstance(raw, dict):
        raw = raw.get("tools")
    if not isinstance(raw, list):
        raise IRValidationError(f"{source or 'mcp manifest'}: expected a tools list")
    tools = []
    for entry in raw:
        if "name" not in entry:
            raise IRValidationError(f"{source or 'mcp manifest'}: tool without a name: {entry!r}")
        schema = entry.get("inputSchema") or entry.get("input_schema") or {}
        props = schema.get("properties") if isinstance(schema, dict) else None
        tools.append(
            ParsedTool(
                name=entry["name"],
                arguments=frozenset(props) if isinstance(props, dict) else None,
                description=entry.get("description", ""),
                source=source,
            )
        )
    return tuple(tools)


def parse_file(path: Path) -> tuple[ParsedTool, ...]:
    return parse(json.loads(path.read_text()), source=str(path))
