#!/usr/bin/env python3
"""Healer tab - scan one mod, fix what the scan found.

Owns its widgets and worker threading; the host app only provides the
notebook frame, game/plugins locations, and the shared BusyState. Never
imports compasse_gui (that way lies a cycle).
"""
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from gui_kit import ScrollFrame, _launch
from .engine import (
    apply_live,
    apply_plan,
    apply_recipe,
    checkup_plugin,
    core,
    game_ver_str,
    load_recipes,
    match_recipe,
    plan_fixes,
    plan_item_to_recipe_item,
    record_applied,
    recipe_label,
    recipe_status,
    recipes_dirs,
    run_load_test,
    verify_recipe_variant,
)

FONT = "Segoe UI"
MONO = "Consolas"
BG = "#f0f2f5"
CARD = "#ffffff"
INK = "#1f2937"
DIM = "#6b7280"
BAR = {"HEALTHY": "#22c55e", "FIXABLE": "#eab308", "RISKY": "#f97316",
       "BROKEN": "#ef4444", "UNKNOWN": "#9ca3af"}
HEAD = {"HEALTHY": "Looks healthy", "FIXABLE": "Fixable",
        "RISKY": "Might work", "BROKEN": "Needs the author",
        "UNKNOWN": "Not sure"}
HINT = {
    "none": "",
    "fix": "Press Fix below.",
    "try_first": "Try it in the game first.",
    "turn_off": "Turn it off to play, then ask the author for an update.",
}

class _NoWork:
    """Stand-in lock for _launch when the tab runs without a BusyState."""

    @staticmethod
    def release():
        pass

class FixCard(tk.Frame):
    """One fixable finding: a Fix button, or radio picks + Fix."""

    def __init__(self, parent, item, on_fix, **kw):
        super().__init__(parent, bg=CARD, relief="solid", bd=1, **kw)
        self.item = item
        self.on_fix = on_fix
        self.fixed = False
        self.picked = False
        self.choice = tk.IntVar(value=-1)

        body = tk.Frame(self, bg=CARD)
        body.pack(side="left", fill="both", expand=True, padx=12, pady=8)

        tk.Label(body, text=item.get("label", ""),
                 font=(FONT, 9), fg=INK, bg=CARD,
                 anchor="w", justify="left",
                 wraplength=420).pack(fill="x", pady=(0, 4))

        if item.get("kind") == "hook-pick":
            for m in item.get("matches", [])[:8]:
                tk.Radiobutton(
                    body, text=f"+0x{m:X}",
                    variable=self.choice, value=m,
                    font=(MONO, 9), fg=INK, bg=CARD,
                    selectcolor=CARD, activebackground=CARD, anchor="w",
                    command=self._on_pick).pack(fill="x", anchor="w")
            sug = item.get("selected")
            if sug is not None:
                try:
                    self.choice.set(sug)
                except Exception:
                    pass

        btnrow = tk.Frame(body, bg=CARD)
        btnrow.pack(fill="x", pady=(4, 0))
        if item.get("kind") != "flags":
            self.fix_btn = tk.Button(
                btnrow, text="Fix",
                font=(FONT, 9, "bold"),
                relief="raised", bd=1, padx=12, pady=2,
                bg="#fef08a", fg="#713f12",
                activebackground="#fde047", activeforeground="#422006",
                cursor="hand2", command=self._on_fix)
            self.fix_btn.pack(side="left")
        else:
            self.fix_btn = None
        self.status_lbl = tk.Label(btnrow, text="",
                                   font=(FONT, 9),
                                   fg=DIM, bg=CARD)
        self.status_lbl.pack(side="left", padx=(8, 0))

    def _on_pick(self):
        self.picked = True

    def _on_fix(self):
        if self.fix_btn is not None:
            try:
                self.fix_btn.config(state="disabled")
            except Exception:
                pass
        self.status_lbl.config(text="Fixing...")
        self.on_fix(self)

    def selection(self):
        """Chosen offset for pick cards (suggested counts when fixing
        this card directly; Fix-all needs an explicit click)."""
        v = self.choice.get()
        return v if v >= 0 else None

    def mark_fixed(self, success, message=""):
        self.fixed = success
        if self.fix_btn is not None:
            try:
                self.fix_btn.config(state="disabled")
            except Exception:
                pass
        self.status_lbl.config(
            text="Fixed" if success else f"Failed: {message}",
            fg="#16a34a" if success else "#dc2626")

    def mark_idle(self):
        if self.fixed:
            return
        if self.fix_btn is not None:
            try:
                self.fix_btn.config(state="normal")
            except Exception:
                pass
        self.status_lbl.config(text="")

    def set_working(self, working):
        if self.fixed:
            return
        if self.fix_btn is None:
            return
        try:
            self.fix_btn.config(state="disabled" if working else "normal")
        except Exception:
            pass

class HealerTab:
    def __init__(self, parent, ctx=None, game_exe=None, plugins_dir_fn=None,
                 work=None, extra_dirs_fn=None, extra_dlls_fn=None,
                 extra_sources_fn=None, game_dir_fn=None, **_ignored):
        if ctx is not None:
            if game_exe is None:
                game_exe = ctx.game_exe
            if plugins_dir_fn is None:
                plugins_dir_fn = ctx.plugins_dir_fn
            if work is None:
                work = ctx.work
            if extra_dirs_fn is None:
                extra_dirs_fn = self._dirs_from_ctx(ctx, extra_sources_fn)
            if game_dir_fn is None:
                game_dir_fn = getattr(ctx, "game_dir_fn", None)
        self.parent = parent
        self.game_exe = game_exe
        self._plugins_dir_fn = plugins_dir_fn
        self._extra_dirs_fn = extra_dirs_fn
        self._game_dir_fn = game_dir_fn
        self.work = work
        self._rep = None
        self._inputs = None
        self._plan = []
        self._cards = []
        self._mint_dead = set()
        self._last_fix = None
        self._scanning = False
        self._t0 = 0.0
        self._pct = 0
        self._timer_job = None
        self._build()
        if self.work is not None:
            try:
                self.work.listen(self._set_working)
            except Exception:
                pass

    @staticmethod
    def _dirs_from_ctx(ctx, extra_sources_fn=None):
        """Healer's lib-dirs slice of the shared extra-sources tuple."""
        fn = extra_sources_fn if extra_sources_fn is not None else getattr(
            ctx, "extra_sources_fn", None)
        if fn is None:
            return None

        def _dirs():
            try:
                src = fn()
            except Exception:
                return []
            try:
                return list(src[1])
            except Exception:
                return list(src) if isinstance(src, (list, tuple)) else []

        return _dirs

    @property
    def root(self):
        return self.parent.winfo_toplevel()

    def _run(self, fn):
        """Run fn in a worker; errors show via messagebox, lock releases after."""
        _launch(self.root, self.work if self.work is not None else _NoWork,
                fn)

    def _set_working(self, working, desc=""):
        state = "disabled" if working else "normal"
        for w in (self.scan_btn, self.fix_btn, self.export_btn,
                  self.browse_btn, self.browse_old_btn):
            try:
                w.config(state=state)
            except Exception:
                pass
        for c in self._cards:
            try:
                c.set_working(working)
            except Exception:
                pass

    def _build(self):
        top = tk.Frame(self.parent, bg=BG)
        top.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(top, text="Mod:", font=(FONT, 10),
                 fg=INK, bg=BG).pack(side="left")
        self.dll_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.dll_var,
                  width=38).pack(side="left", padx=(6, 4))
        self.browse_btn = ttk.Button(top, text="Browse...",
                                     command=self._browse)
        self.browse_btn.pack(side="left", padx=(0, 12))
        tk.Label(top, text="Old game (optional):", font=(FONT, 10),
                 fg=INK, bg=BG).pack(side="left")
        self.old_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.old_var,
                  width=28).pack(side="left", padx=(6, 4))
        self.browse_old_btn = ttk.Button(top, text="Browse...",
                                         command=self._browse_old)
        self.browse_old_btn.pack(side="left")

        row = tk.Frame(self.parent, bg=BG)
        row.pack(fill="x", padx=10, pady=(0, 4))
        self.scan_btn = ttk.Button(row, text="Scan",
                                   command=self.scan)
        self.scan_btn.pack(side="left", padx=(0, 6))
        self.fix_btn = ttk.Button(row, text="Fix",
                                  command=self.fix_all)
        self.fix_btn.pack(side="left")
        self.export_btn = ttk.Button(row, text="Export recipe",
                                     command=self.export_recipe)
        self.export_btn.pack(side="left", padx=(6, 0))
        self.status_lbl = tk.Label(row, text="", font=(FONT, 10, "bold"),
                                   fg=INK, bg=BG)
        self.status_lbl.pack(side="left", padx=(16, 0))

        prow = tk.Frame(self.parent, bg=BG)
        prow.pack(fill="x", padx=10, pady=(0, 4))
        self.prog = ttk.Progressbar(prow, mode="determinate",
                                    maximum=100, value=0)
        self.prog.pack(side="left", fill="x", expand=True)
        self.step_lbl = tk.Label(prow, text="", font=(FONT, 9),
                                 fg=DIM, bg=BG, anchor="w")
        self.step_lbl.pack(side="left", padx=(8, 0))

        body = tk.Frame(self.parent, bg=BG)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.bar = tk.Frame(body, bg="#9ca3af", width=4)
        self.bar.pack(side="left", fill="y")
        self.scroll = ScrollFrame(body, bg=CARD)
        self.scroll.pack(side="left", fill="both", expand=True)
        inner = self.scroll.inner
        self.head_var = tk.StringVar(
            value="Pick a mod, then press Scan.")
        self.head_lbl = tk.Entry(inner, textvariable=self.head_var,
                                 font=(FONT, 11, "bold"),
                                 fg=INK, bg=CARD, relief="flat",
                                 state="readonly", readonlybackground=CARD)
        self.head_lbl.pack(fill="x", padx=12, pady=(10, 2))
        self.out = tk.Text(inner, font=(MONO, 9), fg=INK, bg=CARD,
                           relief="flat", wrap="word", height=10)
        self.out.pack(fill="both", expand=True, padx=12, pady=(0, 4))
        self.out.config(state="disabled")
        self.plan_frame = tk.Frame(inner, bg=CARD)
        self.plan_frame.pack(fill="x", padx=12, pady=(0, 10))

    def _browse(self):
        init = ""
        try:
            if self._plugins_dir_fn:
                d = self._plugins_dir_fn()
                init = str(d) if d else ""
        except Exception:
            pass
        path = filedialog.askopenfilename(
            title="Select mod DLL",
            filetypes=[("DLL files", "*.dll"), ("All files", "*.*")],
            initialdir=init)
        if path:
            self.dll_var.set(path)
            self.scan()

    def _browse_old(self):
        path = filedialog.askopenfilename(
            title="Select old SkyrimSE.exe (optional)",
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")])
        if path:
            self.old_var.set(path)

    def _clear(self):
        self._rep = None
        self._plan = []
        for c in self._cards:
            try:
                c.destroy()
            except Exception:
                pass
        self._cards = []
        self._scanning = False
        if self._timer_job is not None:
            try:
                self.root.after_cancel(self._timer_job)
            except Exception:
                pass
            self._timer_job = None
        self.status_lbl.config(text="")
        self.step_lbl.config(text="")
        try:
            self.prog.config(value=0)
        except Exception:
            pass
        self.head_var.set("Pick a mod, then press Scan.")
        self.bar.config(bg="#9ca3af")
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        self.out.config(state="disabled")

    def _log_step(self, text, frac):
        if not self._scanning:
            return
        self._pct = int(frac * 100)
        try:
            self.prog.config(value=self._pct)
        except Exception:
            pass
        self.step_lbl.config(text=text)
        self.out.config(state="normal")
        self.out.insert("end", f"{text}\n")
        self.out.see("end")
        self.out.config(state="disabled")
        self._paint_status()

    def _paint_status(self):
        import time as _t
        secs = int(_t.monotonic() - self._t0)
        self.status_lbl.config(text=f"Working... {self._pct}% ({secs}s)")

    def _tick(self):
        if not self._scanning:
            return
        self._paint_status()
        try:
            self._timer_job = self.root.after(200, self._tick)
        except Exception:
            self._timer_job = None

    def _stop_clock(self):
        self._scanning = False
        if self._timer_job is not None:
            try:
                self.root.after_cancel(self._timer_job)
            except Exception:
                pass
            self._timer_job = None

    def _fit_text(self):
        try:
            n = int(self.out.count("1.0", "end", "displaylines")[0])
        except Exception:
            return
        try:
            self.out.config(height=min(max(n, 4), 40))
        except Exception:
            pass

    def _show(self, rep):
        self._rep = rep
        key = rep.get("verdict", "UNKNOWN")
        self.bar.config(bg=BAR.get(key, "#9ca3af"))
        title = rep.get("title") or HEAD.get(key, "")
        self.head_var.set(f"{rep.get('name', '')}: {title}")
        self.status_lbl.config(text=f"[{key}]")
        hint = HINT.get(rep.get("action", "none"), "")
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        for ln in rep.get("lines", []):
            self.out.insert("end", f"- {ln}\n")
        if hint:
            self.out.insert("end", f"\n{hint}\n")
        self.out.config(state="disabled")
        self._fit_text()
        self._build_plan(rep)

    def _build_plan(self, rep):
        for c in self._cards:
            try:
                c.destroy()
            except Exception:
                pass
        self._cards = []
        old = self.old_var.get().strip() or None
        try:
            has_old = bool(old and Path(old).is_file())
        except Exception:
            has_old = False
        self._plan = plan_fixes(rep, has_old_exe=has_old,
                                     skip_ids=self._mint_dead)
        self._maybe_recipe_card()
        for item in self._plan:
            try:
                card = FixCard(self.plan_frame, item, self._fix_card)
            except Exception:
                continue
            card.pack(fill="x", pady=(0, 6))
            self._cards.append(card)

    def _maybe_recipe_card(self):
        """One-press card when a recipe matches this mod + game."""
        try:
            dll_p, game, plug, _extra = self._inputs or (None,) * 4
        except (TypeError, ValueError):
            return
        if dll_p is None or game is None:
            return
        try:
            ver = game_ver_str(game)
            if ver is None:
                return
            recs = load_recipes(recipes_dirs(plug))
            rec = match_recipe(str(dll_p), ver, recs)
        except Exception:
            return
        if rec is None:
            return
        try:
            states = recipe_status(str(dll_p), rec)
        except Exception:
            return
        pending = [it for it, st in states if st == "pending"]
        if not pending:
            note = tk.Label(
                self.plan_frame,
                text=f"Known fix for your game ({ver}): already applied.",
                font=(FONT, 9), fg="#16a34a", bg=CARD,
                anchor="w", justify="left")
            note.pack(fill="x", padx=12, pady=(0, 6))
            self._cards.append(note)
            return
        card = tk.Frame(self.plan_frame, bg="#f0fdf4",
                        relief="solid", bd=1)
        body = tk.Frame(card, bg="#f0fdf4")
        body.pack(side="left", fill="both", expand=True, padx=12, pady=8)
        tk.Label(body,
                 text=f"Known fix for your game ({ver}): "
                      f"{recipe_label(rec)}",
                 font=(FONT, 9), fg=INK, bg="#f0fdf4",
                 anchor="w", justify="left",
                 wraplength=420).pack(fill="x", pady=(0, 4))
        btnrow = tk.Frame(body, bg="#f0fdf4")
        btnrow.pack(fill="x", pady=(4, 0))
        status = tk.Label(btnrow, text="", font=(FONT, 9),
                          fg=DIM, bg="#f0fdf4")
        btn = tk.Button(btnrow, text="Apply known fix",
                        font=(FONT, 9, "bold"),
                        relief="raised", bd=1, padx=12, pady=2,
                        bg="#bbf7d0", fg="#14532d",
                        activebackground="#86efac",
                        activeforeground="#052e16",
                        cursor="hand2")
        btn.pack(side="left")
        status.pack(side="left", padx=(8, 0))

        def _run():
            if self.work is not None \
                    and not self.work.acquire("Fixing..."):
                try:
                    self.root.after(
                        0, lambda: messagebox.showinfo(
                            "Please wait", "Another task is running."))
                except Exception:
                    pass
                return
            try:
                self.root.after(
                    0, lambda: btn.config(state="disabled"))
                self.root.after(
                    0, lambda: status.config(text="Fixing..."))
            except Exception:
                pass

            def _do():
                try:
                    got = self._inputs_or_msg()
                    if got is None:
                        return
                    dll_q, game_q, plug_q, extra_q, old_q = got
                    msgs, _info = apply_recipe(
                        dll_q, rec, plug_q, game_q, extra_q, old_q)
                except Exception as exc:
                    msg = str(exc)
                    self.root.after(
                        0, lambda m=msg: messagebox.showerror("Error", m))
                    return
                ok = any("fixed" in m or "already fine" in m
                         for m in msgs)
                self.root.after(
                    0, lambda: status.config(
                        text="Fixed - rescanning to verify."
                        if ok else "Nothing applied - see log.",
                        fg="#16a34a" if ok else "#dc2626"))
                for m in msgs:
                    self.root.after(0, lambda t=m: self._note(t))
                self.root.after(0, lambda: self.scan(auto_live=False))

            self._run(_do)

        try:
            btn.config(command=_run)
        except Exception:
            pass
        card.pack(fill="x", pady=(0, 6))
        self._cards.append(card)

    def _inputs_or_msg(self):
        try:
            dll_p, game, plug, extra = self._inputs or (None,) * 4
        except (TypeError, ValueError):
            dll_p, game, plug, extra = None, None, None, []
        if dll_p is None:
            messagebox.showinfo("Healer", "Scan the mod first.")
            return None
        old = self.old_var.get().strip() or None
        return dll_p, game, plug, extra, Path(old) if old else None

    def scan(self, auto_live=True):
        dll = self.dll_var.get().strip()
        if not dll:
            messagebox.showerror("Error", "Select a mod DLL first.")
            return
        dll_p = Path(dll)
        if not dll_p.is_file():
            messagebox.showerror("Error", f"Mod not found:\n{dll_p}")
            return
        if self.game_exe is None:
            messagebox.showerror(
                "Error", "Set the game first (Settings tab).")
            return
        plug = None
        try:
            plug = self._plugins_dir_fn() if self._plugins_dir_fn else None
        except Exception:
            plug = None
        if plug is None:
            plug = dll_p.parent
        extra = []
        try:
            extra = self._extra_dirs_fn() if self._extra_dirs_fn else []
        except Exception:
            extra = []
        old = self.old_var.get().strip() or None
        if old and not Path(old).is_file():
            messagebox.showerror("Error", f"Old game not found:\n{old}")
            return
        if self.work is not None and not self.work.acquire("Healer..."):
            messagebox.showinfo("Please wait", "Another task is running.")
            return
        import time as _t
        self._clear()
        self._scanning = True
        self._t0 = _t.monotonic()
        self._pct = 0
        try:
            self.prog.config(value=0)
        except Exception:
            pass
        self.step_lbl.config(text="Starting...")
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        self.out.config(state="disabled")
        self._paint_status()
        try:
            self._timer_job = self.root.after(200, self._tick)
        except Exception:
            self._timer_job = None
        game, old_p = self.game_exe, (Path(old) if old else None)
        self._inputs = (dll_p, game, plug, extra)

        def _step(text, frac):
            self.root.after(0, lambda: self._log_step(text, frac))

        def _finish_live(rep):
            self._stop_clock()
            try:
                self.prog.config(value=100)
            except Exception:
                pass
            self.step_lbl.config(text="")
            self._show(rep)

        def _do():
            try:
                rep = checkup_plugin(dll_p, game, plug, old_p,
                                          extra_dirs=extra, on_step=_step)
            except Exception as exc:
                msg = str(exc)
                self.root.after(
                    0, lambda m=msg: messagebox.showerror("Error", m))
                self.root.after(0, lambda m=msg: self._fail(m))
                return
            self.root.after(0, lambda: self._show(rep))
            merged = rep
            if auto_live:
                try:
                    self.root.after(0, lambda: self._log_step(
                        "Starting it isolated...", 0.96))
                    live = run_load_test(dll_p, game, plug)
                    merged = apply_live(rep, live)
                except Exception as exc:
                    msg = str(exc)
                    self.root.after(
                        0, lambda m=msg: self._note(
                            f"Live check failed: {m}"))
            self.root.after(0, lambda: _finish_live(merged))

        self._run(_do)

    def _stash_fix(self, dll_p, items, picks):
        """Remember applied items for one-press export.

        picks aligns with items: True for explicit user choices.
        A hook-pick present here was picked (unpicked ones are skipped
        before applying), so fix_all passes all True.
        """
        try:
            self._last_fix = {
                "dll": str(dll_p),
                "items": [(dict(it), bool(p)) for it, p in zip(items, picks)],
            }
        except Exception:
            self._last_fix = None

    def fix_all(self):
        got = self._inputs_or_msg()
        if got is None:
            return
        dll_p, game, plug, extra, old_p = got
        items = []
        for card, item in zip(self._cards, self._plan):
            if item.get("kind") == "flags":
                continue
            if item.get("kind") == "hook-pick" and not card.picked:
                continue
            if item.get("kind") == "hook-pick":
                item["selected"] = card.selection()
            items.append(item)
        if not items:
            messagebox.showinfo("Fix", "Nothing fixable - pick a candidate "
                                "first." if any(
                                    i.get("kind") == "hook-pick"
                                    for i in self._plan)
                                else "Nothing to fix.")
            return
        if self.work is not None and not self.work.acquire("Fixing..."):
            messagebox.showinfo("Please wait", "Another task is running.")
            return
        self._note("Fixing...")
        self._stash_fix(dll_p, items, [True] * len(items))

        def _remember(info):
            for i in (info or {}).get("mint_empty", []):
                try:
                    self._mint_dead.add(i)
                except Exception:
                    pass

        def _do():
            try:
                msgs, info = apply_plan(dll_p, plug, game, extra,
                                             old_p, items)
            except Exception as exc:
                msg = str(exc)
                self.root.after(
                    0, lambda m=msg: messagebox.showerror("Error", m))
                self.root.after(0, lambda m=msg: self._fail(m))
                return
            self.root.after(0, lambda i=info: _remember(i))
            for m in msgs:
                self.root.after(0, lambda t=m: self._note(t))
            self.root.after(0, lambda: self._note(
                "Done - rescanning to verify."))
            self.root.after(0, lambda: self.scan(auto_live=False))

        self._run(_do)

    def export_recipe(self):
        """One press: recipe from the tested fix, verified byte-identical.

        Uses what was just applied (no rescan, no reinstall) when it
        still matches this mod and its stored original; otherwise falls
        back to recording a fresh plan. Writes only if re-applying the
        recipe reproduces the fixed bytes exactly, in temp files.
        """
        got = self._inputs_or_msg()
        if got is None:
            return
        dll_p, game, plug, _extra, old_p = got
        if self.work is not None and not self.work.acquire("Exporting..."):
            messagebox.showinfo("Please wait", "Another task is running.")
            return
        self._note("Exporting recipe...")

        def _do():
            import hashlib as _hl
            import shutil as _sh
            import tempfile as _tf
            tmpdir = None
            try:
                ver = game_ver_str(game)
                if ver is None:
                    raise ValueError("game version unreadable")
                try:
                    bak = core.backup_path(dll_p)
                except Exception:
                    bak = None
                if bak is None:
                    raise ValueError(
                        "no stored original - reinstall a clean copy, "
                        "scan it, then export")
                clean = bak.read_bytes()
                try:
                    fixed = Path(dll_p).read_bytes()
                except OSError:
                    raise ValueError("cannot read the fixed mod")
                if clean == fixed:
                    raise ValueError("mod is unmodified - nothing to record")
                clean_hash = _hl.sha256(bytes(clean)).hexdigest()
                fixed_hash = _hl.sha256(bytes(fixed)).hexdigest()
                stash = self._last_fix or {}
                recipe_items = None
                label = f"Verified fix ({ver})"
                if stash.get("dll") == str(dll_p):
                    converted = []
                    for it, picked in stash.get("items") or []:
                        conv = plan_item_to_recipe_item(it, picked=picked)
                        if conv is not None:
                            converted.append(conv)
                    if converted:
                        recipe_items = converted
                if recipe_items is None:
                    tmpdir = Path(_tf.mkdtemp(prefix="recipe_exp_"))
                    src = tmpdir / dll_p.name
                    _sh.copy(bak, src)
                    rep = checkup_plugin(src, game, plug, old_p)
                    converted = []
                    for it in plan_fixes(
                            rep, has_old_exe=bool(old_p)):
                        conv = plan_item_to_recipe_item(it, picked=False)
                        if conv is not None:
                            converted.append(conv)
                    if not converted:
                        raise ValueError(
                            "nothing recordable for this mod - reinstall "
                            "a clean copy, scan it, then export")
                    recipe_items = converted
                    label = rep.get("title", "Known fix")
                dirs = recipes_dirs(plug)
                if not dirs:
                    raise ValueError("no recipes folder found")
                variant = {"game": ver, "label": label,
                           "items": recipe_items}
                ok, detail = verify_recipe_variant(clean, fixed, variant)
                if not ok:
                    raise ValueError(f"not saving: {detail}")
                dest = record_applied(
                    dll_p.stem, clean_hash, recipe_items, ver, dirs[0],
                    label=label, patched_hash=fixed_hash)
            except Exception as exc:
                msg = str(exc)
                self.root.after(
                    0, lambda m=msg: messagebox.showerror("Error", m))
                self.root.after(0, lambda m=msg: self._fail(m))
                return
            finally:
                try:
                    if tmpdir is not None:
                        _sh.rmtree(tmpdir, ignore_errors=True)
                except Exception:
                    pass
            self.root.after(
                0, lambda: self._note(f"Recipe saved + verified: {dest}"))

        self._run(_do)

    def _fix_card(self, card):
        got = self._inputs_or_msg()
        if got is None:
            card.mark_idle()
            return
        dll_p, game, plug, extra, old_p = got
        try:
            idx = self._cards.index(card)
            item = dict(self._plan[idx])
        except (ValueError, IndexError):
            return
        if item.get("kind") == "hook-pick":
            sel = card.selection()
            if sel is None:
                messagebox.showinfo("Fix", "Pick a candidate first.")
                card.mark_idle()
                return
            item["selected"] = sel
        if self.work is not None and not self.work.acquire("Fixing..."):
            messagebox.showinfo("Please wait", "Another task is running.")
            card.mark_idle()
            return
        picked = getattr(card, "picked", False) \
            if item.get("kind") == "hook-pick" else True
        self._stash_fix(dll_p, [item], [picked])

        def _remember(info):
            for i in (info or {}).get("mint_empty", []):
                try:
                    self._mint_dead.add(i)
                except Exception:
                    pass

        def _do():
            try:
                msgs, info = apply_plan(dll_p, plug, game, extra,
                                             old_p, [item])
            except Exception as exc:
                msg = str(exc)
                self.root.after(
                    0, lambda m=msg: messagebox.showerror("Error", m))
                self.root.after(0, lambda m=msg: self._fail(m))
                return
            self.root.after(0, lambda i=info: _remember(i))
            ok = any("fixed" in m or "Minted" in m for m in msgs)
            self.root.after(
                0, lambda: card.mark_fixed(ok, "; ".join(msgs)))
            for m in msgs:
                self.root.after(0, lambda t=m: self._note(t))
            self.root.after(0, lambda: self._note(
                "Done - rescanning to verify."))
            self.root.after(0, lambda: self.scan(auto_live=False))

        self._run(_do)

    def _fail(self, message):
        self._stop_clock()
        self.step_lbl.config(text="")
        self.status_lbl.config(text="")
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("end", f"Failed: {message}\n")
        self.out.config(state="disabled")

    def _note(self, text):
        self.out.config(state="normal")
        self.out.insert("end", f"\n{text}\n")
        self.out.see("end")
        self.out.config(state="disabled")
        self._fit_text()
        if self._rep is not None:
            self._rep["lines"] = self._rep.get("lines", []) + [text]
