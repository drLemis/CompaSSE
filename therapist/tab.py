#!/usr/bin/env python3
"""Therapist tab - thin host wrapper for the main flags/versions tab.

The full scan/fix card UI still lives in compasse_gui (which builds it
into this tab's frame). This wrapper only holds the frame plus the
shared ToolContext so Therapist registers like every other tool.
Never imports compasse_gui (that way lies a cycle).
"""
import tkinter as tk

class TherapistTab:
    """Placeholder owning the Therapist notebook frame."""

    def __init__(self, parent, ctx=None, **_ignored):
        self.parent = parent
        self.ctx = ctx
        self.frame = parent
        try:
            game = getattr(ctx, "game_exe", None)
        except Exception:
            game = None
        self.game_exe = game
        self._hint = None

    @property
    def root(self):
        try:
            return self.parent.winfo_toplevel()
        except Exception:
            return None

__all__ = ["TherapistTab"]
