"""Registry for notebook tools."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

@dataclass
class ToolContext:
    """Shared host state handed to every tool tab.

    ``extra_sources_fn`` returns the host's ``get_plugin_sources()``
    tuple ``(dlls, lib_dirs, label)``; each tab picks the part it needs
    (Surgeon takes [0], Healer takes [1]).
    """

    game_exe: Any = None
    plugins_dir_fn: Optional[Callable[[], Any]] = None
    work: Any = None
    extra_sources_fn: Optional[Callable[[], Any]] = None
    game_dir_fn: Optional[Callable[[], Any]] = None

@dataclass
class ToolSpec:
    """One notebook tool: how to title and build its tab."""

    name: str
    title: str
    factory: Callable[[Any, ToolContext], Any]

TOOLS: List[ToolSpec] = []

def register_tool(name, title=None, factory=None):
    """Add a tool to TOOLS; accepts a ToolSpec or (name, title, factory).

    Returns the registered ToolSpec. Re-registering an existing name
    replaces it in place so rebuilding never duplicates tabs.
    """
    if isinstance(name, ToolSpec):
        spec = name
    else:
        assert title is not None and factory is not None
        spec = ToolSpec(name=name, title=title, factory=factory)
    for i, existing in enumerate(TOOLS):
        if existing.name == spec.name:
            TOOLS[i] = spec
            return spec
    TOOLS.append(spec)
    return spec

__all__ = ["ToolContext", "ToolSpec", "TOOLS", "register_tool"]
