#!/usr/bin/env python3
"""Porter tab. Scan one mod for hardcoded addresses and fix matches."""
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import engine
from .engine import (
    apply_fingerprints,
    apply_library,
    apply_profiles,
    core,
    filter_plausible,
    hits_text,
    is_packed_exe,
    plain_report,
    profile_dir,
    scan_dll,
    selftest,
)
from core.touched import remove_touched
try:
    from .engine import apply_row_proposal  # type: ignore
except ImportError:  # engine lane has not landed yet
    apply_row_proposal = None
from gui_kit import (
    BG,
    CARD_BG,
    FONT_FAMILY,
    FONT_MONO,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    ScrollFrame,
    _launch,
)

MATCH_WORD = {"exact-profile": "known fix", "library": "library match",
              "fingerprint": "code match", "human": "approved"}

class _NoWork:
    """Stand-in lock for _launch when the tab runs without a BusyState."""

    @staticmethod
    def release():
        pass

def _lib_for(exe_path, plugins_dir):
    """versionlib matching the exe version, or None."""
    try:
        ver = core.unpack_version(core.runtime_version_from_exe(exe_path))
    except Exception:
        return None
    if ver is None or plugins_dir is None:
        return None
    try:
        cands = sorted(Path(plugins_dir).glob("versionlib-*.bin"))
    except Exception:
        return None
    for path in cands:
        try:
            if core.extract_version_from_filename(path.name) == ver[:3]:
                lib = core.parse_library_any(str(path))
                if lib:
                    return lib
        except Exception:
            continue
    return None

def _row_text(row):
    n = len(row["sites"])
    place = "place" if n == 1 else "places"
    if row["proposal"] is not None:
        how = MATCH_WORD.get(row["basis"], row["basis"])
        return ("Matched (%s, %s): %d %s resolve to the new game version."
                % (row["kind"], how, n, place))
    return ("Needs a human look (%s): %d %s, no safe match found."
            % (row["kind"], n, place))

class PorterTab:
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
        self.parent = parent
        self.game_exe = game_exe
        self._plugins_dir_fn = plugins_dir_fn
        self._game_dir_fn = game_dir_fn if game_dir_fn is not None else (
            getattr(ctx, "game_dir_fn", None) if ctx is not None else None)
        self.work = work
        self._rows = []
        self._fix_open = True
        self._nofix_open = False
        self._name = ""
        self._scanning = False
        self._pct = 0
        self._t0 = 0.0
        self._timer_job = None
        self._details = tk.BooleanVar(value=False)
        self._build()
        if self.work is not None:
            try:
                self.work.listen(self._set_working)
            except Exception:
                pass

    @property
    def root(self):
        return self.parent.winfo_toplevel()

    def _run(self, fn):
        """Run fn in a worker; errors show via messagebox, lock releases after."""
        _launch(self.root, self.work if self.work is not None else _NoWork,
                fn)

    def _set_working(self, working, desc=""):
        state = "disabled" if working else "normal"
        for w in (self.scan_btn, self.selftest_btn, self.browse_btn,
                  self.browse_old_btn):
            try:
                w.config(state=state)
            except Exception:
                pass

    def _build(self):
        top = tk.Frame(self.parent, bg=BG)
        top.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(top, text="Mod:", font=(FONT_FAMILY, 10),
                 fg=TEXT_PRIMARY, bg=BG).pack(side="left")
        self.dll_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.dll_var,
                  width=38).pack(side="left", padx=(6, 4))
        self.browse_btn = ttk.Button(top, text="Browse...",
                                     command=self._browse)
        self.browse_btn.pack(side="left", padx=(0, 12))
        tk.Label(top, text="Old game (optional):", font=(FONT_FAMILY, 10),
                 fg=TEXT_PRIMARY, bg=BG).pack(side="left")
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
        self.selftest_btn = ttk.Button(row, text="Self-test",
                                       command=self.run_selftest)
        self.selftest_btn.pack(side="left")
        self.status_lbl = tk.Label(row, text="", font=(FONT_FAMILY, 10),
                                   fg=TEXT_PRIMARY, bg=BG)
        self.status_lbl.pack(side="left", padx=(16, 0))

        prow = tk.Frame(self.parent, bg=BG)
        prow.pack(fill="x", padx=10, pady=(0, 4))
        self.prog = ttk.Progressbar(prow, mode="determinate",
                                    maximum=100, value=0)
        self.prog.pack(side="left", fill="x", expand=True)
        self.step_lbl = tk.Label(prow, text="", font=(FONT_FAMILY, 9),
                                 fg=TEXT_SECONDARY, bg=BG, anchor="w")
        self.step_lbl.pack(side="left", padx=(8, 0))

        body = tk.Frame(self.parent, bg=BG)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.bar = tk.Frame(body, bg="#9ca3af", width=4)
        self.bar.pack(side="left", fill="y")
        self.scroll = ScrollFrame(body, bg=CARD_BG)
        self.scroll.pack(side="left", fill="both", expand=True)
        inner = self.scroll.inner
        self.head_var = tk.StringVar(
            value="Pick a mod, then press Scan.")
        tk.Entry(inner, textvariable=self.head_var,
                 font=(FONT_FAMILY, 11, "bold"),
                 fg=TEXT_PRIMARY, bg=CARD_BG, relief="flat",
                 state="readonly",
                 readonlybackground=CARD_BG).pack(
                     fill="x", padx=12, pady=(10, 2))
        self.rows_frame = tk.Frame(inner, bg=CARD_BG)
        self.rows_frame.pack(fill="x", padx=12, pady=(0, 4))
        det = tk.Checkbutton(inner, text="Show technical details",
                             variable=self._details,
                             font=(FONT_FAMILY, 9), fg=TEXT_SECONDARY,
                             bg=CARD_BG, activebackground=CARD_BG,
                             command=self._render)
        det.pack(anchor="w", padx=12, pady=(0, 4))
        self.out = tk.Text(inner, font=(FONT_MONO, 9), fg=TEXT_PRIMARY,
                           bg=CARD_BG, relief="flat", wrap="word",
                           height=6)
        self.out.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.out.config(state="disabled")

    def _old_init_dir(self):
        try:
            if self.game_exe:
                cand = Path(self.game_exe).resolve().parent / \
                    "OLDGAMEVERSIONS"
                if cand.is_dir():
                    return str(cand)
        except Exception:
            pass
        return ""

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
            title="Select old SkyrimSE.exe (unpacked copy)",
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")],
            initialdir=self._old_init_dir())
        if path:
            self.old_var.set(path)

    def _clear(self):
        self._rows = []
        self._fix_open = True
        self._nofix_open = False
        for c in self.rows_frame.winfo_children():
            try:
                c.destroy()
            except Exception:
                pass
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

    def _step(self, text, frac):
        if not self._scanning:
            return
        self._pct = int(frac * 100)
        self.root.after(0, lambda: self._paint(text))

    def _paint(self, text):
        try:
            self.prog.config(value=self._pct)
        except Exception:
            pass
        try:
            self.step_lbl.config(text=text)
        except Exception:
            pass

    def _tick(self):
        if not self._scanning:
            return
        import time as _t
        secs = int(_t.monotonic() - self._t0)
        try:
            self.status_lbl.config(
                text="Working... %d%% (%ds)" % (self._pct, secs))
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

    def _fail(self, message):
        self._stop_clock()
        self.step_lbl.config(text="")
        self.status_lbl.config(text="")
        self.head_var.set("Scan failed.")
        self.bar.config(bg="#9ca3af")
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("end", "%s\n" % message)
        self.out.config(state="disabled")

    def _apply_fn(self):
        fn = getattr(engine, "apply_row_proposal", None)
        if fn is None:
            fn = globals().get("apply_row_proposal")
        return fn

    def _toggle_fix(self):
        self._fix_open = not self._fix_open
        self._render()

    def _toggle_nofix(self):
        self._nofix_open = not self._nofix_open
        self._render()

    def _group_header(self, text, is_open, toggle):
        bar = tk.Frame(self.rows_frame, bg=CARD_BG)
        bar.pack(fill="x", pady=(0, 4))
        mark = "v" if is_open else ">"
        btn = ttk.Button(bar, text="%s %s" % (mark, text),
                         command=toggle)
        btn.pack(side="left")
        return bar

    def _fix_card(self, idx, row, show_hex, fix_fn):
        card = tk.Frame(self.rows_frame, bg=CARD_BG, relief="solid",
                        bd=1)
        dot = tk.Frame(card, bg="#22c55e", width=4)
        dot.pack(side="left", fill="y")
        body = tk.Frame(card, bg=CARD_BG)
        body.pack(side="left", fill="both", expand=True,
                  padx=10, pady=6)
        tk.Label(body, text=_row_text(row), font=(FONT_FAMILY, 9),
                 fg=TEXT_PRIMARY, bg=CARD_BG, anchor="w",
                 justify="left", wraplength=460).pack(fill="x")
        if show_hex:
            hexline = "%s -> %s [%s]" % (
                hex(row["value"]), hex(row["proposal"]),
                row["basis"])
            tk.Label(body, text=hexline, font=(FONT_MONO, 8),
                     fg=TEXT_SECONDARY, bg=CARD_BG,
                     anchor="w").pack(fill="x")
        status = ""
        if row.get("_working"):
            status = "Working..."
        elif row.get("fixed"):
            n = row.get("patched_sites", len(row["sites"]))
            status = "Fixed (%s places)." % n
        if status:
            tk.Label(body, text=status, font=(FONT_FAMILY, 9),
                     fg="#16a34a" if row.get("fixed") else TEXT_SECONDARY,
                     bg=CARD_BG, anchor="w").pack(fill="x")
        brow = tk.Frame(body, bg=CARD_BG)
        brow.pack(fill="x", pady=(4, 0))
        if row.get("fixed"):
            bak = row.get("backup_path") or ""
            ttk.Button(brow, text="Undo",
                       command=lambda i=idx: self._undo_row(i)).pack(
                           side="left")
            if bak:
                tk.Label(brow, text="Backup kept next to the mod.",
                         font=(FONT_FAMILY, 8), fg=TEXT_SECONDARY,
                         bg=CARD_BG).pack(side="left", padx=(8, 0))
        else:
            btn = ttk.Button(brow, text="Fix",
                             command=lambda i=idx: self._fix_row(i))
            btn.pack(side="left")
            if fix_fn is None or row.get("_working"):
                try:
                    btn.config(state="disabled")
                except Exception:
                    pass
        card.pack(fill="x", pady=(0, 6))

    def _nofix_card(self, row, show_hex):
        card = tk.Frame(self.rows_frame, bg=CARD_BG, relief="solid",
                        bd=1)
        dot = tk.Frame(card, bg="#eab308", width=4)
        dot.pack(side="left", fill="y")
        body = tk.Frame(card, bg=CARD_BG)
        body.pack(side="left", fill="both", expand=True,
                  padx=10, pady=6)
        tk.Label(body, text=_row_text(row), font=(FONT_FAMILY, 9),
                 fg=TEXT_PRIMARY, bg=CARD_BG, anchor="w",
                 justify="left", wraplength=460).pack(fill="x")
        tk.Label(body, text="Why: %s." % hits_text(row),
                 font=(FONT_FAMILY, 9),
                 fg=TEXT_SECONDARY, bg=CARD_BG, anchor="w",
                 justify="left", wraplength=460).pack(fill="x")
        if show_hex:
            hexline = "%s: %s." % (hex(row["value"]),
                                   hits_text(row))
            tk.Label(body, text=hexline, font=(FONT_MONO, 8),
                     fg=TEXT_SECONDARY, bg=CARD_BG,
                     anchor="w").pack(fill="x")
        card.pack(fill="x", pady=(0, 6))

    def _render(self):
        for c in self.rows_frame.winfo_children():
            try:
                c.destroy()
            except Exception:
                pass
        show_hex = bool(self._details.get())
        fix_fn = self._apply_fn()
        indexed = list(enumerate(self._rows))
        fixable = [(i, r) for i, r in indexed
                   if r["proposal"] is not None]
        unfix = [(i, r) for i, r in indexed
                 if r["proposal"] is None]
        self._group_header("Can fix (%d)" % len(fixable),
                           self._fix_open, self._toggle_fix)
        if self._fix_open:
            if fix_fn is None and fixable:
                tk.Label(self.rows_frame,
                         text="Auto-fix unavailable - engine update pending.",
                         font=(FONT_FAMILY, 9), fg=TEXT_SECONDARY,
                         bg=CARD_BG, anchor="w").pack(fill="x",
                                                      pady=(0, 6))
            for i, row in fixable:
                self._fix_card(i, row, show_hex, fix_fn)
        self._group_header("Can't fix automatically (%d)" % len(unfix),
                           self._nofix_open, self._toggle_nofix)
        if self._nofix_open:
            for _, row in unfix:
                self._nofix_card(row, show_hex)

    def _fix_row(self, idx):
        try:
            row = self._rows[idx]
        except Exception:
            return
        if row.get("proposal") is None:
            return
        if row.get("fixed") or row.get("_working"):
            return
        fix_fn = self._apply_fn()
        if fix_fn is None:
            messagebox.showinfo("Not available",
                                "Auto-fix unavailable - "
                                "engine update pending.")
            return
        dll = self.dll_var.get().strip()
        if not dll:
            messagebox.showerror("Error", "Select a mod DLL first.")
            return
        if self.work is not None and not self.work.acquire("Porter..."):
            messagebox.showinfo("Please wait", "Another task is running.")
            return
        row["_working"] = True
        self._render()

        def _do():
            try:
                res = engine.apply_row_proposal(dll, row)  # type: ignore
            except Exception as exc:
                msg = str(exc) or "Fix failed."
                self.root.after(
                    0, lambda m=msg: messagebox.showerror("Error", m))

                def _reset():
                    try:
                        row.pop("_working", None)
                    except Exception:
                        pass
                    self._render()
                self.root.after(0, _reset)
                return

            def _done():
                try:
                    row.pop("_working", None)
                except Exception:
                    pass
                ok = False
                try:
                    ok = bool(res.get("ok"))
                except Exception:
                    ok = False
                if ok:
                    row["fixed"] = True
                    try:
                        row["backup_path"] = res.get("backup_path")
                        row["patched_sites"] = res.get("patched_sites",
                                                       len(row["sites"]))
                    except Exception:
                        pass
                else:
                    msg = "Fix failed."
                    try:
                        msg = res.get("error") or msg
                    except Exception:
                        pass
                    messagebox.showerror("Error", msg)
                self._render()
            self.root.after(0, _done)

        self._run(_do)

    def _undo_row(self, idx):
        try:
            row = self._rows[idx]
        except Exception:
            return
        bak = row.get("backup_path")
        if not bak:
            messagebox.showinfo("Nothing to undo",
                                "No backup was kept for this row.")
            return
        dll = self.dll_var.get().strip()
        if not dll:
            messagebox.showerror("Error", "Select a mod DLL first.")
            return
        if self.work is not None and not self.work.acquire("Porter..."):
            messagebox.showinfo("Please wait", "Another task is running.")
            return
        row["_working"] = True
        self._render()

        def _do():
            try:
                import shutil as _sh
                _sh.copy2(str(bak), dll)
                try:
                    remove_touched(Path(dll).parent, dll)
                except Exception:
                    pass
            except Exception as exc:
                msg = str(exc) or "Undo failed."
                self.root.after(
                    0, lambda m=msg: messagebox.showerror("Error", m))

                def _reset():
                    try:
                        row.pop("_working", None)
                    except Exception:
                        pass
                    self._render()
                self.root.after(0, _reset)
                return

            def _done():
                try:
                    row.pop("_working", None)
                except Exception:
                    pass
                try:
                    row.pop("fixed", None)
                except Exception:
                    pass
                self._render()
            self.root.after(0, _done)

        self._run(_do)

    def _show(self, name, rows, note="", skipped=0):
        self._rows = rows
        self._fix_open = True
        self._nofix_open = False
        lines = plain_report(name, rows, note, skipped)
        self.head_var.set(lines[0] if lines else name)
        matched = sum(1 for r in rows if r["proposal"] is not None)
        if note:
            color = "#9ca3af"
        elif not rows or matched == len(rows):
            color = "#22c55e"
        else:
            color = "#eab308"
        self.bar.config(bg=color)
        self._render()
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("end", "Only matched rows can be patched - "
                              "unmatched rows stay report-only.\n")
        self.out.config(state="disabled")

    def scan(self):
        dll = self.dll_var.get().strip()
        if not dll:
            messagebox.showerror("Error", "Select a mod DLL first.")
            return
        dll_p = Path(dll)
        if not dll_p.is_file():
            messagebox.showerror("Error", "Mod not found:\n%s" % dll_p)
            return
        if self.game_exe is None:
            messagebox.showerror(
                "Error", "Set the game first (Settings tab).")
            return
        old = self.old_var.get().strip() or None
        if old and not Path(old).is_file():
            messagebox.showerror("Error", "Old game not found:\n%s" % old)
            return
        if self.work is not None and not self.work.acquire("Porter..."):
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
        try:
            self._timer_job = self.root.after(200, self._tick)
        except Exception:
            self._timer_job = None
        game, old_p = self.game_exe, (Path(old) if old else None)
        name = dll_p.name

        def _finish(rows, note, skipped=0):
            self._stop_clock()
            try:
                self.prog.config(value=100)
            except Exception:
                pass
            self.step_lbl.config(text="")
            self._show(name, rows, note, skipped)

        def _do():
            note = ""
            skipped = 0
            try:
                self._step("Reading the mod...", 0.05)
                dll_data = dll_p.read_bytes()
                self._step("Detecting hardcoded addresses...", 0.15)
                rows, note = scan_dll(dll_data)
                if note:
                    self.root.after(0, lambda: _finish([], note))
                    return
                self._step("Checking known fixes...", 0.3)
                plug = None
                try:
                    plug = self._plugins_dir_fn() \
                        if self._plugins_dir_fn else None
                except Exception:
                    plug = None
                try:
                    new_lib = _lib_for(str(game), plug)
                    old_lib = _lib_for(str(old_p), plug) \
                        if old_p is not None else None
                    apply_library(rows, old_lib, new_lib)
                except Exception:
                    pass
                try:
                    apply_profiles(rows, dll_data, profile_dir())
                except Exception:
                    pass
                if old_p is not None:
                    self._step("Reading the old game copy...", 0.4)
                    old_data, old_sections = core.load_exe_sections(
                        str(old_p))
                    if is_packed_exe(old_data):
                        note = ("Old game copy is still packed - unpack "
                                "it first. Showing detected addresses "
                                "without code matches.")
                        self.root.after(0, lambda: _finish(rows, note))
                        return
                    self._step("Dropping constants...", 0.5)
                    try:
                        kept, skipped = filter_plausible(
                            rows, old_data, old_sections)
                        rows = kept
                    except Exception:
                        pass
                    self._step("Reading the current game...", 0.6)
                    new_data, new_sections = core.load_exe_sections(
                        str(game))
                    self._step("Matching against new game code "
                               "(minutes on first run, seconds after)...",
                               0.7)

                    def _prog(frac):
                        self._step("Matching against new game code "
                                   "(%d%%)..." % int(frac * 100),
                                   0.7 + 0.25 * frac)

                    try:
                        import hashlib as _hl
                        dll_hash = _hl.sha256(bytes(dll_data)).hexdigest()
                    except Exception:
                        dll_hash = None
                    try:
                        _, complete = apply_fingerprints(
                            rows, old_data, old_sections,
                            new_data, new_sections,
                            dll_hash=dll_hash, on_step=_prog)
                    except Exception:
                        complete = True
                    if not complete:
                        note = ("Code matching ran out of time - "
                                "unmatched rows were left alone, never "
                                "guessed. Run again to retry.")
                    self._step("Dropping constants...", 0.9)
                    kept, skipped = filter_plausible(
                        rows, old_data, old_sections)
                    rows = kept
            except Exception as exc:
                msg = str(exc)
                self.root.after(
                    0, lambda m=msg: messagebox.showerror("Error", m))
                self.root.after(0, lambda m=msg: self._fail(m))
                return
            self.root.after(0, lambda: _finish(rows, note, skipped))

        self._run(_do)

    def run_selftest(self):
        if self.work is not None and not self.work.acquire("Porter..."):
            messagebox.showinfo("Please wait", "Another task is running.")
            return
        self._clear()
        self.head_var.set("Running built-in checks...")
        self.step_lbl.config(text="Starting...")

        def _do():
            try:
                passed, failed, lines = selftest()
            except Exception as exc:
                msg = str(exc)
                self.root.after(
                    0, lambda m=msg: messagebox.showerror("Error", m))
                self.root.after(0, lambda m=msg: self._fail(m))
                return

            def _show_res():
                self._stop_clock()
                try:
                    self.prog.config(value=100)
                except Exception:
                    pass
                self.step_lbl.config(text="")
                ok = not failed
                self.head_var.set(
                    "Self-test: %d passed, %d failed."
                    % (len(passed), len(failed)))
                self.bar.config(bg="#22c55e" if ok else "#ef4444")
                self.out.config(state="normal")
                self.out.delete("1.0", "end")
                for ln in lines:
                    self.out.insert("end", "%s\n" % ln)
                self.out.config(state="disabled")

            self.root.after(0, _show_res)

        self._run(_do)
