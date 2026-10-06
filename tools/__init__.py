"""Central tool registry: the ONE place to add a notebook tool.

Adding a future tool takes ~2 lines here and zero ``compasse_gui`` edits::

    register_tool("mytool", "  My Tool  ",
                  lambda parent, ctx: importlib.import_module("mytool.tab").MyToolTab(parent, ctx=ctx))

Factories import their tab modules lazily (inside the lambda) so this
package never creates import cycles at startup. Mechanism
(``ToolContext``/``ToolSpec``/``TOOLS``/``register_tool``) lives in
``core.tools`` and is re-exported here for convenience.
"""
import importlib

from core.tools import TOOLS, ToolContext, ToolSpec, register_tool

register_tool("therapist", "  Therapist  ",
              lambda parent, ctx: importlib.import_module("therapist.tab").TherapistTab(parent, ctx=ctx))
register_tool("healer", "  Healer  ",
              lambda parent, ctx: importlib.import_module("healer.tab").HealerTab(parent, ctx=ctx))
register_tool("surgeon", "  Surgeon  ",
              lambda parent, ctx: importlib.import_module("surgeon.tab").SurgeonTab(parent, ctx=ctx))
register_tool("porter", "  Porter  ",
              lambda parent, ctx: importlib.import_module("porter.tab").PorterTab(parent, ctx=ctx))

__all__ = ["TOOLS", "ToolContext", "ToolSpec", "register_tool"]
