"""Surgeon tab: co-save plugin blocks with per-block Drop.

GUI lives here, engine in surgeon.engine, shared widgets in gui_kit.
"""
import tkinter as tk
import tkinter.ttk as ttk
from pathlib import Path
from tkinter import filedialog, messagebox

from gui_kit import (BG, BusyState, CARD_BG, FONT_FAMILY,
                     FONT_MONO, ScrollFrame, TEXT_PRIMARY,
                     TEXT_SECONDARY, _launch, _name_label)
from surgeon import engine

try:
    from gui_kit import BusyCard as _CardBase
except ImportError:  # BusyCard not yet merged; current base still works
    _CardBase = tk.Frame

SURGEON_BADGE_COLORS = {
    "core": {"bar": "#9ca3af"},
    "mod": {"bar": "#eab308"},
}

def _default_saves_dir():
    """Usual Saves folder, or None when it does not exist."""
    cand = (Path.home() / "Documents" / "My Games" / "Skyrim Special Edition"
            / "Saves")
    return cand if cand.exists() else None

class SurgeonCard(_CardBase):
    """A card for one co-save plugin block with a Drop button."""

    def __init__(self, parent, save_path, block, loc, fsize, on_drop, **kw):
        super().__init__(parent, bg=CARD_BG, relief="solid", bd=1, **kw)
        self.save_path = save_path
        self.block = block
        self.loc = loc or {"installed": [], "staged": []}
        self.fsize = fsize
        self.on_drop = on_drop
        self.dropped = False
        self._note = False
        uid = block["uid"]
        is_core = uid == 0

        colors = SURGEON_BADGE_COLORS["core" if is_core else "mod"]
        self.bar = tk.Frame(self, bg=colors["bar"], width=4)
        self.bar.pack(side="left", fill="y")

        body = tk.Frame(self, bg=CARD_BG)
        body.pack(side="left", fill="both", expand=True, padx=(0, 12), pady=10)

        title = f"{engine.uid_name(uid)} [0x{uid:08x}]"
        _name_label(body, title).pack(anchor="w")

        if not is_core:
            inst = self.loc["installed"]
            staged = self.loc["staged"]
            if inst:
                tk.Label(body, text="owned by installed: " + ", ".join(inst),
                         font=(FONT_FAMILY, 9),
                         fg=TEXT_SECONDARY, bg=CARD_BG,
                         anchor="w").pack(fill="x")
            elif staged:
                tk.Label(body, text="known mod, not deployed: "
                                    + ", ".join(s[:60] for s in staged[:2]),
                         font=(FONT_FAMILY, 9),
                         fg=TEXT_SECONDARY, bg=CARD_BG,
                         anchor="w", wraplength=380).pack(fill="x")
            else:
                tk.Label(body, text="unknown anywhere - true orphan, safe to drop",
                         font=(FONT_FAMILY, 9, "bold"),
                         fg="#b45309", bg=CARD_BG,
                         anchor="w", wraplength=380).pack(fill="x")

        total = sum(c["length"] for c in block["chunks"])
        share = f" ({100 * total // self.fsize}% of file)" if self.fsize else ""
        tk.Label(body, text=f"{len(block['chunks'])} chunk(s), {total} data bytes{share}",
                 font=(FONT_FAMILY, 9),
                 fg=TEXT_SECONDARY, bg=CARD_BG,
                 anchor="w").pack(fill="x")

        kinds = []
        for c in block["chunks"][:10]:
            t = engine.fcc(c["type"])
            kinds.append(t if t.isprintable() else f"0x{c['type']:08x}")
        if kinds:
            more = f" +{len(block['chunks']) - 10} more" if len(block["chunks"]) > 10 else ""
            tk.Label(body, text=" ".join(kinds) + more,
                     font=(FONT_MONO, 8),
                     fg=TEXT_SECONDARY, bg=CARD_BG,
                     anchor="w").pack(fill="x")

        desc = engine.describe_chunks(block)
        if desc:
            tk.Label(body, text="Holds: " + desc,
                     font=(FONT_FAMILY, 9),
                     fg=TEXT_SECONDARY, bg=CARD_BG,
                     anchor="w", wraplength=380).pack(fill="x")

        if is_core:
            tk.Label(body, text="SKSE core data - not droppable.",
                     font=(FONT_FAMILY, 9),
                     fg=TEXT_SECONDARY, bg=CARD_BG,
                     anchor="w").pack(fill="x", pady=(4, 0))
            self.drop_btn = None
        else:
            btn_frame = tk.Frame(body, bg=CARD_BG)
            btn_frame.pack(fill="x", pady=(4, 0))
            self.drop_btn = tk.Button(
                btn_frame,
                text="Drop block",
                font=(FONT_FAMILY, 9, "bold"),
                relief="raised", bd=1,
                padx=12, pady=4,
                bg="#fef08a", fg="#713f12",
                activebackground="#fde047", activeforeground="#422006",
                cursor="hand2",
                command=self._on_drop_click,
            )
            self.drop_btn.pack(side="left")

        self.status_lbl = tk.Label(body, text="",
                                   font=(FONT_FAMILY, 9),
                                   fg=TEXT_SECONDARY, bg=CARD_BG)
        self.status_lbl.pack(anchor="w")

    def _on_drop_click(self):
        self.on_drop(self)

    def _set_status(self, text, color=TEXT_SECONDARY):
        self.status_lbl.config(text=text, fg=color)

    def _lock_drop(self):
        if self.drop_btn:
            self.drop_btn.config(state="disabled")

    def mark_busy(self):
        self._lock_drop()
        self._set_status("Dropping...")

    def note(self, text):
        self._note = True
        self._set_status(text)

    def mark_dropped(self, success, message):
        self.dropped = True
        self._lock_drop()
        self._set_status(
            "Dropped \u2713" if success else ("Failed: " + message),
            "#16a34a" if success else "#dc2626",
        )

    def set_working(self, working):
        if working:
            self._snap = [(self.drop_btn, self.drop_btn.cget("state"))] \
                if self.drop_btn else []
            for w, _ in self._snap:
                try:
                    w.config(state="disabled")
                except Exception:
                    pass
        elif not self.dropped:
            for w, st in getattr(self, "_snap", []):
                try:
                    w.config(state=st)
                except Exception:
                    pass
            self._snap = []
            if getattr(self, "_note", False):
                self.status_lbl.config(text="")
                self._note = False

class SurgeonTab:
    """Tab listing co-save plugin blocks with per-block Drop."""

    def __init__(self, parent, ctx=None, game_exe=None, plugins_dir_fn=None,
                 work=None, extra_dlls_fn=None, extra_dirs_fn=None,
                 extra_sources_fn=None, game_dir_fn=None, **_ignored):
        if ctx is not None:
            if game_exe is None:
                game_exe = ctx.game_exe
            if plugins_dir_fn is None:
                plugins_dir_fn = ctx.plugins_dir_fn
            if work is None:
                work = ctx.work
            if extra_dlls_fn is None:
                extra_dlls_fn = self._dlls_from_ctx(ctx, extra_sources_fn)
        self.parent = parent
        self.game_exe = game_exe
        self._plugins_dir_fn = plugins_dir_fn
        self._extra_dlls_fn = extra_dlls_fn
        self.work = work or BusyState()
        self.cards = []
        self._save_path = None
        self._preview_img = None
        self._build()
        self.work.listen(self._set_working)

    @staticmethod
    def _dlls_from_ctx(ctx, extra_sources_fn=None):
        """Surgeon's DLL slice of the shared extra-sources tuple."""
        fn = extra_sources_fn if extra_sources_fn is not None else getattr(
            ctx, "extra_sources_fn", None)
        if fn is None:
            return None

        def _dlls():
            try:
                src = fn()
            except Exception:
                return []
            try:
                return list(src[0])
            except Exception:
                return list(src) if isinstance(src, (list, tuple)) else []

        return _dlls

    def _set_working(self, working, desc=""):
        state = "disabled" if working else "normal"
        self.list_btn.config(state=state)
        self.clear_btn.config(state=state)
        self.browse_btn.config(state=state)
        self.backup_btn.config(state=state)
        for c in self.cards:
            c.set_working(working)

    def _build(self):
        top = tk.Frame(self.parent, bg=BG)
        top.pack(fill="x", padx=10, pady=(10, 0))

        left = tk.Frame(top, bg=BG)
        left.pack(side="left", fill="both", expand=True)

        ctrl = tk.Frame(left, bg=BG)
        ctrl.pack(fill="x", pady=(0, 2))

        tk.Label(ctrl, text="Save (.skse):",
                 font=(FONT_FAMILY, 10), fg=TEXT_PRIMARY, bg=BG
                 ).pack(side="left")
        self.save_var = tk.StringVar()
        self.save_entry = ttk.Entry(ctrl, textvariable=self.save_var, width=40)
        self.save_entry.pack(side="left", padx=(6, 4))
        self.browse_btn = ttk.Button(ctrl, text="Browse...",
                                     command=self._browse_save)
        self.browse_btn.pack(side="left", padx=(0, 12))

        btn_frame = tk.Frame(left, bg=BG)
        btn_frame.pack(fill="x", pady=(2, 2))

        self.list_btn = ttk.Button(btn_frame, text="List blocks", command=self.list_blocks)
        self.list_btn.pack(side="left", padx=(0, 6))

        self.clear_btn = ttk.Button(btn_frame, text="Clear",
                                    command=self._clear_cards)
        self.clear_btn.pack(side="left")

        self.backup_var = tk.BooleanVar(value=True)
        self.backup_btn = tk.Checkbutton(
            btn_frame, text="Backup",
            variable=self.backup_var,
            font=(FONT_FAMILY, 9),
            fg=TEXT_PRIMARY, bg=BG, activebackground=BG,
            selectcolor=BG, cursor="hand2")
        self.backup_btn.pack(side="left", padx=(12, 0))

        info_frame = tk.Frame(left, bg=BG)
        info_frame.pack(fill="x", pady=(2, 0))
        self.info_head = tk.Label(info_frame, text="",
                                  font=(FONT_FAMILY, 10, "bold"),
                                  fg=TEXT_PRIMARY, bg=BG,
                                  anchor="w", justify="left")
        self.info_head.pack(fill="x")
        self.info_sub = tk.Label(info_frame, text="",
                                 font=(FONT_FAMILY, 9),
                                 fg=TEXT_SECONDARY, bg=BG,
                                 anchor="w", justify="left",
                                 wraplength=700)
        self.info_sub.pack(fill="x")

        self.preview_lbl = tk.Label(top, bg=BG)
        self.preview_lbl.pack(side="right", padx=(8, 0), anchor="n")

        self.sf = ScrollFrame(self.parent)
        self.sf.pack(fill="both", expand=True, padx=10, pady=(2, 4))

    def _browse_save(self):
        initial = _default_saves_dir()
        path = filedialog.askopenfilename(
            title="Select co-save (.skse)",
            filetypes=[("SKSE co-save", "*.skse"), ("All files", "*.*")],
            initialdir=str(initial) if initial else "",
        )
        if path:
            self.save_var.set(path)
            self.list_blocks()

    def _set_preview(self, ppm):
        if ppm is None:
            self.preview_lbl.config(image="", text="(no screenshot)",
                                    font=(FONT_FAMILY, 8),
                                    fg=TEXT_SECONDARY, bg=CARD_BG)
            self.preview_lbl.pack(side="right", padx=(8, 0), anchor="n")
            return
        try:
            self._preview_img = tk.PhotoImage(data=ppm)
        except tk.TclError:
            self.preview_lbl.config(image="", text="(preview unreadable)",
                                    font=(FONT_FAMILY, 8),
                                    fg=TEXT_SECONDARY, bg=CARD_BG)
            self.preview_lbl.pack(side="right", padx=(8, 0), anchor="n")
            return
        self.preview_lbl.config(image=self._preview_img, text="")
        self.preview_lbl.pack(side="right", padx=(8, 0), anchor="n")

    def list_blocks(self):
        save_path = self.save_var.get().strip()
        if not save_path:
            messagebox.showerror("Error", "Select a .skse co-save first.")
            return
        save_path = Path(save_path)
        if not save_path.exists():
            messagebox.showerror("Error", f"Save not found:\n{save_path}")
            return
        self._save_path = save_path
        self._run(lambda: self._do_list(save_path), "Reading save file...")

    def _do_list(self, save_path):
        self.root.after(0, self._clear_cards)
        try:
            header, blocks, trailing = engine.parse_cosave(save_path)
        except ValueError as exc:
            self.root.after(0, lambda: messagebox.showerror("Error", str(exc)))
            return
        # Phase 1 (fast): identity + preview now, block scan after.
        ver = header["runtimeVersion"]
        game = f"{ver >> 24}.{(ver >> 16) & 0xFF}.{((ver >> 4) & 0xFFF)}"
        pretty = engine.parse_save_filename(save_path.name)
        ess_info = engine.read_ess_info(save_path.with_suffix(".ess"))
        ppm = None
        if ess_info and ess_info.get("shot"):
            ppm = engine.ess_thumbnail(ess_info["shot"])
        self.root.after(0, lambda p=ppm: self._set_preview(p))
        if pretty:
            head = (f"{pretty['character']} - {pretty['label']}, "
                    f"{pretty['location']}, level {pretty['level']} - "
                    f"{pretty['date']}")
            if ess_info and ess_info.get("day") is not None:
                head += f" - Day {ess_info['day']}, {ess_info['time']}"
        else:
            head = save_path.name
        self.root.after(0, lambda h=head: self.info_head.config(text=h))
        self.root.after(0, lambda n=len(blocks): self.info_sub.config(
            text=f"game {game}, {n} block(s) - resolving owners..."))

        # Phase 2 (slow): per-block owner scans, cards, mod diff.
        fsize = save_path.stat().st_size
        plugdir = None
        if self._plugins_dir_fn is not None:
            plugdir = self._plugins_dir_fn()
        extra_dlls = self._extra_dlls_fn() if self._extra_dlls_fn else []
        any_known = False
        for b in blocks:
            if plugdir or extra_dlls:
                loc = engine.locate_uid(b["uid"], plugdir,
                                         extra_dlls=extra_dlls)
            else:
                loc = None
            if loc is not None and (loc["installed"] or loc["staged"]):
                any_known = True
            self.root.after(
                0,
                lambda block=b, lc=loc: self._add_card(block, lc, fsize),
            )
        sub = f"game {game}, {len(blocks)} block(s)"
        if plugdir is not None:
            plist = None
            for b in blocks:
                plist = engine.plugin_list_chunk(b, save_path)
                if plist is not None:
                    break
            if plist is not None:
                missing = engine.missing_mods(plist, plugdir.parent.parent)
                if missing:
                    sub += (f" - {len(missing)} save mod(s) missing now: "
                            + ", ".join(missing[:6]))
                    if len(missing) > 6:
                        sub += f" +{len(missing) - 6} more"
        if plugdir is not None and blocks and not any_known:
            sub += " - no blocks match known mods (different setup?)"
        if trailing:
            sub += f", {trailing} trailing bytes (left untouched)"
        self.root.after(0, lambda h=head: self.info_head.config(text=h))
        self.root.after(0, lambda t=sub: self.info_sub.config(text=t))

    def _add_card(self, block, loc, fsize):
        card = SurgeonCard(self.sf.inner, self._save_path, block, loc, fsize,
                           on_drop=self._drop_one)
        card.pack(fill="x", padx=4, pady=4)
        self.cards.append(card)
        if self.work.busy:
            card.set_working(True)

    def _drop_one(self, card):
        if not self.work.acquire("Updating save file..."):
            card.note("Please wait - still working...")
            return
        card.mark_busy()
        backup = self.backup_var.get()
        _launch(self.root, self.work,
                lambda: self._drop_worker(card, backup))

    def _drop_worker(self, card, backup):
        try:
            removed, left = engine.drop_plugin(card.save_path,
                                                card.block["uid"],
                                                backup=backup)
            msg = f"{removed} bytes removed, {left} left"
            if not backup:
                msg += " (NO BACKUP)"
            self.root.after(0, lambda: card.mark_dropped(True, msg))
            self.root.after(150, self.list_blocks)
        except ValueError as exc:
            self.root.after(0, lambda: card.mark_dropped(False, str(exc)))

    def _run(self, fn, desc="Working..."):
        if self.work.acquire(desc):
            _launch(self.root, self.work, fn)

    def _clear_cards(self):
        for c in self.cards:
            c.destroy()
        self.cards.clear()
        self.info_head.config(text="")
        self.info_sub.config(text="")
        self.preview_lbl.config(image="", text="")
        self.preview_lbl.pack_forget()
        self._preview_img = None

    @property
    def root(self):
        return self.parent.winfo_toplevel()
