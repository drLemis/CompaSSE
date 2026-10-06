"""Shared widgets, palette, and work lock."""
import threading
import tkinter as tk
import tkinter.font as tkfont
import tkinter.ttk as ttk
from tkinter import messagebox

FONT_FAMILY = "Segoe UI"

FONT_MONO = "Consolas"

BG = "#f0f2f5"

CARD_BG = "#ffffff"

TEXT_PRIMARY = "#1f2937"

TEXT_SECONDARY = "#6b7280"

NAME_PX = 300

NAME_FONT_SPEC = (FONT_FAMILY, 11, "bold")

def _ellipsize(font, text, max_px=NAME_PX):
    """Shorten text to max_px with ..., returning (short, was_cut)."""
    if font.measure(text) <= max_px:
        return text, False
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi) // 2
        if font.measure(text[:mid] + "...") <= max_px:
            lo = mid + 1
        else:
            hi = mid
    return text[:max(lo - 1, 0)] + "...", True

class _HoverTip:
    """Full text on hover, for ellipsized labels."""

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.win = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")

    def _show(self, _event=None):
        if self.win is not None or not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + 12
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        except Exception:
            return
        self.win = tk.Toplevel(self.widget)
        self.win.wm_overrideredirect(True)
        self.win.wm_geometry(f"+{x}+{y}")
        tk.Label(self.win, text=self.text, font=(FONT_MONO, 8),
                 bg="#1f2937", fg="#f9fafb", relief="solid", bd=1,
                 padx=6, pady=3).pack()

    def _hide(self, _event=None):
        if self.win is not None:
            try:
                self.win.destroy()
            except Exception:
                pass
            self.win = None

def _name_label(parent, text):
    """Bold name label, ellipsized with hover for long names."""
    short, cut = _ellipsize(tkfont.Font(font=NAME_FONT_SPEC), text)
    lbl = tk.Label(parent, text=short, font=NAME_FONT_SPEC,
                   fg=TEXT_PRIMARY, bg=CARD_BG)
    if cut:
        _HoverTip(lbl, text)
    return lbl

class BusyState:
    """Global work lock across all tabs. acquire() disables every

    action button via listeners; refusals must show "please wait"."""

    def __init__(self):
        self._busy = False
        self._desc = ""
        self._listeners = []

    def listen(self, fn):
        self._listeners.append(fn)

    @property
    def busy(self):
        return self._busy

    def acquire(self, desc="Working..."):
        if self._busy:
            return False
        self._busy = True
        self._desc = desc
        for fn in self._listeners:
            try:
                fn(True, desc)
            except Exception:
                pass
        return True

    def set_desc(self, desc):
        self._desc = desc
        if self._busy:
            for fn in self._listeners:
                try:
                    fn(True, desc)
                except Exception:
                    pass

    def release(self):
        self._busy = False
        self._desc = ""
        for fn in self._listeners:
            try:
                fn(False, "")
            except Exception:
                pass

class BusyMixin:
    """Shared busy/done status behaviour for per-item cards.

    Consolidates the set_working / mark_idle / mark_busy / mark_fixed /
    mark_dropped variants previously duplicated across compasse_gui.py
    (PluginCard), healer/tab.py (HealerCard) and surgeon/tab.py
    (SurgeonCard). Subclasses only provide widgets; this mixin provides
    the state transitions.

    Widget contract (all optional; missing ones are skipped safely):
      - self.status_lbl: tk.Label used for status text.
      - self.fix_btn / self.drop_btn: primary action button.
      - self.fix_buttons: list of extra action buttons.
      - self.kind_buttons + self._done_kinds: per-kind buttons where
        finished kinds stay disabled after mark_idle() (compasse_gui).
      - self.undo_btn / self.skip_box: extra widgets disabled while
        working (compasse_gui PluginCard).
      - self.fixed / self.dropped: done flags. Either one locks the
        card; mark_fixed() sets fixed, mark_dropped() sets dropped.

    Subclasses with different widget names override _action_widgets()
    to return the list of widgets to disable while working.
    """

    # -- widget discovery (override point) --
    def _action_widgets(self):
        widgets = []
        for name in ("fix_btn", "drop_btn", "undo_btn", "skip_box"):
            w = getattr(self, name, None)
            if w is not None:
                widgets.append(w)
        for w in list(getattr(self, "fix_buttons", []) or []):
            if w is not None and w not in widgets:
                widgets.append(w)
        return widgets

    @property
    def _done(self):
        return bool(getattr(self, "fixed", False)
                    or getattr(self, "dropped", False))

    def _set_status(self, text, fg=None):
        lbl = getattr(self, "status_lbl", None)
        if lbl is None:
            return
        try:
            lbl.config(text=text)
            if fg is not None:
                lbl.config(fg=fg)
        except Exception:
            pass

    @staticmethod
    def _set_state(widgets, state):
        for w in widgets:
            try:
                w.config(state=state)
            except Exception:
                pass

    # -- public API used by all tabs --
    def set_working(self, working):
        """Disable actions while global work runs; restore via mark_idle.

        Done cards (fixed/dropped) stay locked in both directions, which
        matches the healer early-return and the compasse/surgeon
        mark_idle guards.
        """
        if self._done:
            return
        if working:
            self._set_state(self._action_widgets(), "disabled")
        else:
            self.mark_idle()

    def mark_busy(self, message="Working\u2026"):
        """Show in-progress status and lock actions."""
        self._set_state(self._action_widgets(), "disabled")
        self._set_status(message)

    def mark_idle(self):
        """Restore actions unless the card is already done."""
        if self._done:
            return
        self._set_state(self._action_widgets(), "normal")
        # compasse_gui per-kind buttons: keep finished kinds disabled.
        done_kinds = getattr(self, "_done_kinds", None)
        kind_buttons = getattr(self, "kind_buttons", None)
        if done_kinds and kind_buttons:
            try:
                for kind in done_kinds:
                    btn = kind_buttons.get(kind)
                    if btn is not None:
                        btn.config(state="disabled")
            except Exception:
                pass
        self._set_status("")

    def mark_fixed(self, success, message=""):
        """Lock the card as fixed/failed (healer + compasse_gui)."""
        try:
            self.fixed = True
        except Exception:
            pass
        self._set_state(self._action_widgets(), "disabled")
        if success:
            self._set_status("Fixed \u2713", fg="#16a34a")
        else:
            self._set_status("Failed: " + str(message), fg="#dc2626")

    def mark_dropped(self, success, message=""):
        """Lock the card as dropped/failed (surgeon)."""
        try:
            self.dropped = True
        except Exception:
            pass
        self._set_state(self._action_widgets(), "disabled")
        if success:
            self._set_status("Dropped \u2713", fg="#16a34a")
        else:
            self._set_status("Failed: " + str(message), fg="#dc2626")

    def mark_noop(self, message):
        """Transient note; does not lock the card (compasse_gui)."""
        self._set_status(str(message), fg=TEXT_SECONDARY)

    def note(self, text):
        """Transient note (surgeon SurgeonCard.note)."""
        try:
            self._note = True
        except Exception:
            pass
        self._set_status(str(text), fg=TEXT_SECONDARY)

class BusyCard(BusyMixin, tk.Frame):
    """tk.Frame base with BusyMixin behaviour built in.

    New cards should subclass this instead of (tk.Frame,) and get
    set_working / mark_idle / mark_busy / mark_fixed / mark_dropped /
    mark_noop / note for free. Existing cards can adopt it incrementally
    by inheriting BusyMixin alone, e.g. ``class PluginCard(BusyMixin,
    tk.Frame)``, without changing widget construction order.
    """

    def __init__(self, parent, **kw):
        kw.setdefault("bg", CARD_BG)
        super().__init__(parent, **kw)

def _launch(root, work, fn, on_error=None):
    """Run fn in a daemon worker; always release work on the UI thread.

    Guarantees ``work.release()`` is scheduled via ``root.after(0, ...)``
    even when ``fn`` raises, so the global BusyState can never stick
    busy. ``on_error`` is an optional ``callable(exc)`` run on the UI
    thread; by default a messagebox.showerror is shown. The parameter
    is optional so existing callers keep working::

        _launch(self.root, self.work, fn)
        _launch(self.root, self.work, fn, on_error=self._fail)

    Migration example for raw-Thread callers (healer/tab.py,
    porter/tab.py -- do NOT edit those files here; shown for the
    owning lane)::

        # before (healer/tab.py, porter/tab.py pattern):
        import threading
        def _do():
            try:
                result = apply_plan(...)
            except Exception as exc:
                msg = str(exc)
                self.root.after(
                    0, lambda m=msg: messagebox.showerror("Error", m))
                self.root.after(0, lambda m=msg: self._fail(m))
                if self.work is not None:
                    self.root.after(0, self.work.release)
                return
            if self.work is not None:
                self.root.after(0, self.work.release)
            self.root.after(0, lambda: card.mark_fixed(True, "ok"))
        threading.Thread(target=_do, daemon=True).start()

        # after:
        from gui_kit import _launch
        if not self.work.acquire("Fixing..."):
            messagebox.showinfo("Please wait", "Another task is running.")
            card.mark_idle()
            return
        card.mark_busy()
        def _do():
            result = apply_plan(...)  # may raise; _launch reports it
            self.root.after(0, lambda: card.mark_fixed(True, "ok"))
        _launch(self.root, self.work, _do, on_error=self._fail)
    """
    def _worker():
        try:
            fn()
        except Exception as exc:
            handler = on_error
            if handler is not None:
                try:
                    root.after(0, lambda e=exc, h=handler: h(e))
                except Exception:
                    pass
            else:
                try:
                    root.after(0, lambda e=exc: messagebox.showerror(
                        "Error", str(e)))
                except Exception:
                    pass
        finally:
            try:
                if work is not None:
                    root.after(0, work.release)
            except Exception:
                try:
                    if work is not None:
                        work.release()
                except Exception:
                    pass
    threading.Thread(target=_worker, daemon=True).start()

class ScrollFrame(tk.Frame):
    """A scrollable container built from a Canvas with an inner Frame."""

    def __init__(self, parent, **kw):
        bg = kw.pop("bg", BG)
        super().__init__(parent, bg=bg, **kw)

        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.vbar = ttk.Scrollbar(self, orient="vertical",
                                  command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)

        self.inner.bind("<Configure>",
                        lambda _e: self.canvas.configure(
                            scrollregion=self.canvas.bbox("all")))
        self._win = self.canvas.create_window((0, 0), window=self.inner,
                                              anchor="nw")
        self.canvas.configure(yscrollcommand=self.vbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.vbar.pack(side="right", fill="y")

        self.canvas.bind("<Configure>", self._on_canvas_resize)

        # Mousewheel: bind when pointer enters this widget
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        # Also bind to the canvas itself
        self.canvas.bind("<Enter>", self._enter)
        self.canvas.bind("<Leave>", self._leave)

    def _on_canvas_resize(self, event):
        self.canvas.itemconfig(self._win, width=event.width)

    def _enter(self, _event):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _leave(self, _event):
        # Defer unbinding: the pointer may have moved to a child widget.
        self.after(80, self._maybe_unbind)

    def _maybe_unbind(self):
        x, y = self.winfo_pointerxy()
        widget = self.winfo_containing(x, y)
        if widget is None:
            self.canvas.unbind_all("<MouseWheel>")
            return
        # Walk up the widget tree to see if we're still inside this
        # ScrollFrame.
        w = widget
        while w is not None:
            if w is self or w is self.canvas or w is self.inner:
                return  # still inside, keep binding
            w = w.master
        self.canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
