#!/usr/bin/env python3
"""CompaSSE UI: per-mod cards for scan/fix."""
import os
import struct
import sys
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

# ---------------------------------------------------------------------------
# Core engine lives next to this file.
# ---------------------------------------------------------------------------
def _app_dir():
    """Return the directory of the running program (source or frozen exe)."""
    # Nuitka (onefile + standalone) keeps the real exe path in sys.argv[0].
    if "__compiled__" in globals():
        try:
            return Path(sys.argv[0]).resolve().parent
        except Exception:
            pass
    # PyInstaller-style frozen single-file exe.
    if getattr(sys, "frozen", False):
        try:
            return Path(sys.executable).resolve().parent
        except Exception:
            pass
    # Plain source run.
    return Path(__file__).resolve().parent


HERE = _app_dir()
sys.path.insert(0, str(HERE))
import compasse as core


def find_game_exe():
    """Locate SkyrimSE.exe in the same folder this tool lives in."""
    cand = HERE / "SkyrimSE.exe"
    return cand if cand.exists() else None


def plugins_dir_for(game_exe):
    """Derive the SKSE plugins folder from the game executable path."""
    game_dir = Path(game_exe).resolve().parent
    return game_dir / "Data" / "SKSE" / "Plugins"

# ---------------------------------------------------------------------------
# Theme constants
# ---------------------------------------------------------------------------
FONT_FAMILY = "Segoe UI"
FONT_MONO = "Consolas"
BG = "#f0f2f5"
CARD_BG = "#ffffff"
TEXT_PRIMARY = "#1f2937"
TEXT_SECONDARY = "#6b7280"
BADGE_COLORS = {
    "NEEDS_FIX": {"bar": "#eab308"},  # yellow = fixable
    "OK":        {"bar": "#22c55e"},  # green = fine
    "DANGEROUS": {"bar": "#ef4444"},  # red = not fixable with this tool
    "MANUAL":    {"bar": "#f97316"},
    "NOT_SKSE":  {"bar": "#9ca3af"},
}

# Address Library detection imports (Windows API / STL symbols)
_ADDR_LIB_IMPORTS = {
    "CreateFileMappingW", "MapViewOfFile",
    "istream", "_Fiopen",
}




# ===================================================================
# Classification helper
# ===================================================================

def _get_build_dt(dll_path):
    """Return the PE build timestamp as a datetime (UTC), or None."""
    try:
        with open(dll_path, "rb") as f:
            hdr = f.read(0x400)
        e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
        if e_lfanew + 24 > len(hdr):
            return None
        if hdr[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None
        timestamp = struct.unpack_from("<I", hdr, e_lfanew + 8)[0]
        if timestamp == 0:
            return None
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except Exception:
        return None


def _get_build_year(dll_path):
    """Read PE header timestamp to determine the compiler build year."""
    try:
        dt = _get_build_dt(dll_path)
        return dt.year if dt else None
    except Exception:
        return None


def _get_build_date_str(dll_path):
    """Full build date string like '2022 July 04'."""
    try:
        dt = _get_build_dt(dll_path)
        if dt is None:
            return None
        return dt.strftime("%Y %B %d").replace(" 0", " ")
    except Exception:
        return None


def _uses_address_library(info):
    """This plugin uses the Address Library?

    Checks the versionIndependence flag bit (authoritative, no third-party
    deps). This matches what SKSE itself checks at load.
    """
    vi = info.get("version_indep")
    return bool(vi and vi.get("has_addr", False))


def _rva_to_file_off(data, sections, rva):
    """Convert an RVA to a file offset using PE section table."""
    for _name, vaddr, vsize, rawoff, _rawsize in sections:
        if vaddr <= rva < vaddr + vsize:
            return rawoff + (rva - vaddr)
    return None


def _ver_str(vi):
    """Turn compatibleVersions[0] into '1.6.x' style string, or None."""
    try:
        rv = (vi or {}).get("runtime_ver")
        if not rv:
            return None
        b = rv.to_bytes(4, "little")
        return f"{b[3]}.{b[2]}.{b[1]}.{b[0]}"
    except Exception:
        return None


def classify(info, build_year):
    """Turn analyze_plugin output + build year into a verdict dict."""
    flag = info.get("flag")
    vi = info.get("version_indep")
    hooks = info.get("hooks", [])
    version = _ver_str(vi)

    def _base(cat, badge, key, why, fix_desc="", safe=False, needs_fix=False, items=None):
        return dict(cat=cat, badge=badge, key=key, why=why, fix_desc=fix_desc,
                    safe=safe, needs_fix=needs_fix, version=version,
                    build_year=build_year, fix_items=items or [])

    # Not an SKSE plugin at all
    if flag is None and vi is None:
        return _base("NOT_SKSE", "NOT SKSE", "NOT_SKSE",
                     "No SKSEPlugin_Version export found. This is not an SKSE plugin.")

    old = build_year is not None and build_year < 2025
    recent = build_year is not None and build_year >= 2025
    addrlib = _uses_address_library(info)
    flag_patch = flag is not None and flag.get("needs_patch", False)
    indep_patch = vi is not None and vi.get("needs_indep", False)
    has_unknown = vi is not None and vi.get("has_unknown", False)

    # Build the ordered list of individual fixes.
    items = []
    if flag_patch:
        items.append({
            "label": "CommonLibSSE old format (0 -> 2)",
            "description": "Updates the versionIndependenceEx flag so SKSE "
                           "accepts the Address Library format this plugin was built for.",
            "kind": "flag",
        })
    if indep_patch:
        vi_val = vi["indep_val"] if vi else 0
        target = core.KVI_TARGET
        cur = f"0x{vi_val:x}"
        new = f"0x{target:x}"
        if vi_val == target:
            # Flag value already correct; only Ex flag is stale (handled above).
            # Show as informational, not a separate fix.
            pass
        else:
            items.append({
                "label": f"Address Library outdated ({cur} -> {new})",
                "description": "Updates the versionIndependence flags so SKSE "
                               "knows the plugin is version-independent.",
                "kind": "addrlib",
            })
    if hooks:
        items.append({
            "label": f"Hook offsets ({len(hooks)})",
            "description": "Re-resolves the code hooks against the installed "
                           "Address Library for this game version.",
            "kind": "hooks",
        })

    # Build year undetermined: fall back to flag analysis
    if build_year is None:
        if flag_patch or indep_patch:
            return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                         "Cannot determine build year. Plugin needs flag patches "
                         "but safety is uncertain.",
                         "Review manually before patching.", False, True, items)
        return _base("OK", "OK", "OK",
                     "No patches needed. Build year unknown but flags look correct.")

    any_patch = flag_patch or indep_patch

    # Plugin needs patching
    if any_patch:
        if old and addrlib:
            parts = [
                f"Built {build_year} (old CommonLibSSE). "
                "Uses Address Library but SKSE rejects it due to "
                "outdated version flags.",
            ]
            fix_desc = "Patch the flags so SKSE accepts it."
            if hooks:
                fix_desc += f"  Also re-resolve {len(hooks)} hook offset(s)."
            return _base("NEEDS_FIX", "NEEDS FIX", "NEEDS_FIX",
                         "  ".join(parts), fix_desc, True, True, items)

        if recent and addrlib:
            why = (
                f"Built {build_year} (recent). Uses Address Library but SKSE "
                "still rejects it, likely missing version-independence flags "
                "needed to declare compatibility."
            )
            return _base("NEEDS_FIX", "NEEDS FIX", "NEEDS_FIX",
                         why, "Patch the flags so SKSE accepts it.", True, True, items)

        if old and not addrlib:
            return _base("DANGEROUS", "DANGEROUS", "DANGEROUS",
                         (f"Built {build_year} (old). Does not use Address Library. "
                          "Likely has hardcoded Skyrim addresses. "
                          "Auto-patching would break it."),
                         "Needs manual port or recompile with CommonLibNG.",
                         False, True, items)

        # recent + no addrlib, or other ambiguous
        return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                     (f"Built {build_year}. Does not declare Address Library usage. "
                      "Flags need patching but safety is unclear."),
                     "Review manually before patching.", False, True, items)

    # No patches needed based on flags
    if has_unknown:
        return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                     (f"Unknown versionIndependence flags "
                      f"(0x{vi['indep_val']:x}). Cannot verify safety."),
                     "Review manually.", False, False, [])

    return _base("OK", "OK", "OK",
                 "All flags and version info look correct. No action needed.")


# ===================================================================
# Scrollable frame (Canvas + inner Frame)
# ===================================================================

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


# ===================================================================
# Plugin card
# ===================================================================

class PluginCard(tk.Frame):
    """A card representing one scanned plugin with status + controls."""

    def __init__(self, parent, dll_path, info, verdict, on_fix_one, force_fix=False, **kw):
        super().__init__(parent, bg=CARD_BG, relief="solid", bd=1, **kw)
        self.dll_path = dll_path
        self.info = info
        self.verdict = verdict
        self.on_fix_one = on_fix_one
        self.force_fix = force_fix
        self.fixed = False
        self.fix_buttons = []

        colors = BADGE_COLORS[verdict["key"]]

        # ── Left accent bar ──
        self.bar = tk.Frame(self, bg=colors["bar"], width=4)
        self.bar.pack(side="left", fill="y")

        # ── Content area ──
        body = tk.Frame(self, bg=CARD_BG)
        body.pack(side="left", fill="both", expand=True, padx=(0, 12), pady=10)

        # Header row: name
        hdr = tk.Frame(body, bg=CARD_BG)
        hdr.pack(fill="x", pady=(0, 4))

        tk.Label(hdr, text=dll_path.name,
                 font=(FONT_FAMILY, 11, "bold"),
                 fg=TEXT_PRIMARY, bg=CARD_BG).pack(side="left")

        # Version / era line (secondary info)
        ver = verdict.get("version")
        bdate = verdict.get("build_date")
        yline = ""
        if bdate:
            yline += f"{bdate} - "
        if ver:
            yline += f"Skyrim SSE {ver}"
        if yline:
            tk.Label(body, text=yline,
                     font=(FONT_FAMILY, 9),
                     fg=TEXT_SECONDARY, bg=CARD_BG,
                     anchor="w").pack(fill="x", pady=(0, 2))

        # ── Controls (only when the plugin needs fixing, or forced in unsafe mode) ──
        if verdict["needs_fix"] or force_fix:
            fix_items = verdict.get("fix_items", [])

            if force_fix:
                # Unsafe mode: offer BOTH address fixes to every mod,
                # regardless of whether they currently need them.
                vi = info.get("version_indep") or {}
                flag_cur = (info.get("flag") or {}).get("flag_val", 0)
                indep_cur = vi.get("indep_val", 0)
                items = []
                if flag_cur != 2:
                    items.append({
                        "label": f"CommonLibSSE old format ({flag_cur} -> 2)",
                        "description": "Set the versionIndependenceEx flag so SKSE "
                                       "accepts the Address Library format.",
                        "kind": "flag",
                    })
                if indep_cur != core.KVI_TARGET:
                    items.append({
                        "label": f"Address Library outdated (0x{indep_cur:x} -> 0x{core.KVI_TARGET:x})",
                        "description": "Set the versionIndependence flags.",
                        "kind": "addrlib",
                    })
                if not items:
                    items = [{
                        "label": "All fixes already applied",
                        "description": "",
                        "kind": "all",
                    }]
                fix_items = items

            if fix_items:
                fw = tk.Frame(body, bg=CARD_BG)
                fw.pack(fill="x", pady=(6, 4))
                for it in fix_items:
                    b = tk.Button(
                        fw,
                        text=it['label'],
                        font=(FONT_FAMILY, 9, "bold"),
                        relief="raised", bd=1,
                        padx=12, pady=4,
                        bg="#fef08a", fg="#713f12",
                        activebackground="#fde047", activeforeground="#422006",
                        cursor="hand2",
                        command=lambda k=it["kind"]: self._on_fix_kind(k),
                    )
                    b.pack(fill="x", pady=2)
                    self.fix_buttons.append(b)

                # "Fix all" only when there are multiple distinct fixes
                if len(fix_items) > 1:
                    fab = tk.Button(
                        fw,
                        text="Fix all",
                        font=(FONT_FAMILY, 9, "bold"),
                        relief="raised", bd=1,
                        padx=12, pady=4,
                        bg="#fde047", fg="#422006",
                        activebackground="#facc15", activeforeground="#1a2e05",
                        cursor="hand2",
                        command=self._on_fix_click,
                    )
                    fab.pack(fill="x", pady=2)
                    self.fix_btn = fab
                    self.fix_buttons.append(fab)
                else:
                    self.fix_btn = None

            # Status row
            ctrls = tk.Frame(body, bg=CARD_BG)
            ctrls.pack(fill="x", pady=(4, 0))

            self.status_lbl = tk.Label(ctrls, text="",
                                       font=(FONT_FAMILY, 9),
                                       fg=TEXT_SECONDARY, bg=CARD_BG)
            self.status_lbl.pack(side="left")
        else:
            # Ribbon-only treatment: no extra text for healthy mods.
            self.fix_btn = None

    # ── Card actions ──────────────────────────────────────────────

    def _on_fix_kind(self, kind):
        self._disable_all_fix()
        self.status_lbl.config(text=f"Fixing {kind}\u2026")
        self.on_fix_one(self, kind=kind)

    def _on_fix_click(self):
        self._disable_all_fix()
        self.status_lbl.config(text="Fixing all\u2026")
        self.on_fix_one(self, kind="all")

    def _disable_all_fix(self):
        for b in self.fix_buttons:
            try:
                b.config(state="disabled")
            except Exception:
                pass
        try:
            self.fix_btn.config(state="disabled")
        except Exception:
            pass

    def mark_fixed(self, success, message):
        self.fixed = True
        self._disable_all_fix()
        self.status_lbl.config(
            text="Fixed \u2713" if success else ("Failed: " + message),
            fg="#16a34a" if success else "#dc2626",
        )

    def mark_noop(self, message):
        """Nothing was actually changed; don't lock the buttons."""
        self.status_lbl.config(text=message, fg=TEXT_SECONDARY)

    def mark_busy(self):
        self._disable_all_fix()
        self.status_lbl.config(text="Working\u2026")

    def mark_idle(self):
        if not self.fixed:
            try:
                self.fix_btn.config(state="normal")
            except Exception:
                pass
            for b in self.fix_buttons:
                try:
                    b.config(state="normal")
                except Exception:
                    pass
            self.status_lbl.config(text="")

    def included(self):
        """Return whether the plugin should be fixed."""
        if self.fixed:
            return False
        return self.force_fix or self.verdict["safe"]


# ===================================================================
# Main GUI
# ===================================================================

class AutoPorterGUI:
    def __init__(self, root):
        self.root = root
        root.title(f"CompaSSE v{core.VERSION}")
        root.geometry("920x720")
        root.minsize(700, 520)
        root.configure(bg=BG)

        # ── State ──
        self.game_exe = find_game_exe()
        self.busy = False
        self.cards: list[PluginCard] = []

        # Cached exe/addresslib (loaded lazily for fix operations)
        self._exe = None
        self._exe_sections = None
        self._addresslib = None

        self._build()

    # ──────────────────────────────────────────────────────────────
    # Layout
    # ──────────────────────────────────────────────────────────────

    def _build(self):
        # ── Auto-detected location hint ──
        pf = tk.Frame(self.root, bg=BG)
        pf.pack(fill="x", padx=10, pady=(10, 4))
        if self.game_exe:
            tk.Label(pf, text=f"Game: {self.game_exe.name}",
                     font=(FONT_FAMILY, 10, "bold"),
                     fg=TEXT_PRIMARY, bg=BG, anchor="w").pack(fill="x")
            self.plugins_hint = tk.Label(
                pf, text=f"Plugins: {plugins_dir_for(self.game_exe)}",
                font=(FONT_FAMILY, 9), fg=TEXT_SECONDARY, bg=BG, anchor="w")
            self.plugins_hint.pack(fill="x", pady=(0, 2))
        else:
            tk.Label(pf,
                     text="Place this tool in the same folder as SkyrimSE.exe.",
                     font=(FONT_FAMILY, 10),
                     fg="#dc2626", bg=BG, anchor="w").pack(fill="x")

        # ── Buttons ──
        bf = tk.Frame(self.root, bg=BG)
        bf.pack(fill="x", padx=10, pady=(4, 4))

        self.scan_btn = ttk.Button(bf, text="Scan", command=self.scan)
        self.scan_btn.pack(side="left", padx=(0, 6))

        ttk.Button(bf, text="Clear",
                   command=self.clear).pack(side="left")

        self.unsafe = tk.BooleanVar(value=False)
        self.unsafe_btn = tk.Checkbutton(
            bf, text="UNSAFE MODE",
            variable=self.unsafe,
            command=self._on_unsafe_toggle,
            font=(FONT_FAMILY, 9, "bold"),
            fg="#b91c1c", bg=BG, activebackground=BG,
            selectcolor=BG, cursor="hand2")
        self.unsafe_btn.pack(side="left", padx=(12, 0))

        # ── Summary bar ──
        sf = tk.Frame(self.root, bg=BG)
        sf.pack(fill="x", padx=10, pady=(4, 2))

        counts_row = tk.Frame(sf, bg=BG)
        counts_row.pack(fill="x")

        self.c_need = tk.Label(counts_row, text="",
                               font=(FONT_FAMILY, 10, "bold"),
                               fg="#c2410c", bg=BG, anchor="w")
        self.c_need.pack(side="left", padx=(0, 14))

        self.c_ok = tk.Label(counts_row, text="",
                             font=(FONT_FAMILY, 10),
                             fg="#047857", bg=BG, anchor="w")
        self.c_ok.pack(side="left", padx=(0, 14))

        self.c_other = tk.Label(counts_row, text="",
                                font=(FONT_FAMILY, 10),
                                fg=TEXT_SECONDARY, bg=BG, anchor="w")
        self.c_other.pack(side="left")

        # ── Scrollable card area ──
        self.sf = ScrollFrame(self.root)
        self.sf.pack(fill="both", expand=True, padx=10, pady=(2, 4))

        # ── Status bar ──
        self.status = ttk.Label(self.root, text="Ready", anchor="w")
        self.status.pack(fill="x", padx=10, pady=(0, 8))

    # ──────────────────────────────────────────────────────────────
    # Browse handlers
    # ──────────────────────────────────────────────────────────────

    def _plugins(self):
        """Return the plugins dir derived from the game exe next to the tool."""
        if not self.game_exe:
            return None
        return plugins_dir_for(self.game_exe)

    # ──────────────────────────────────────────────────────────────
    # Threading helpers
    # ──────────────────────────────────────────────────────────────

    def _run(self, fn):
        """Run *fn* in a background thread, disabling buttons while busy."""
        if self.busy:
            return
        self.busy = True
        self.scan_btn.config(state="disabled")
        self.status.config(text="Working\u2026")
        threading.Thread(target=self._worker, args=(fn,), daemon=True).start()

    def _worker(self, fn):
        try:
            fn()
        except Exception as exc:
            self.root.after(
                0, lambda: messagebox.showerror("Error", str(exc)))
        finally:
            self.root.after(0, self._done)

    def _done(self):
        self.busy = False
        self.scan_btn.config(state="normal")
        self.status.config(text="Done")

    # ──────────────────────────────────────────────────────────────
    # Scan
    # ──────────────────────────────────────────────────────────────

    def scan(self):
        plugins = self._plugins()
        if plugins is None:
            messagebox.showerror(
                "Error", "Place this tool in the same folder as SkyrimSE.exe.")
            return
        if not plugins.exists():
            messagebox.showerror(
                "Error", f"Plugins folder not found:\n{plugins}")
            return
        self._run(lambda: self._do_scan(plugins))

    def _do_scan(self, plugins):
        # Clear previous results
        self.root.after(0, self._clear_cards)
        self._exe = None
        self._exe_sections = None
        self._addresslib = None
        runtime_version = (core.runtime_version_from_exe(self.game_exe)
                           if self.game_exe else None)

        # Scan every DLL
        dlls = sorted(plugins.glob("*.dll"))
        counts = {}
        self._scan_data = []
        for dll in dlls:
            info = core.analyze_plugin(dll, runtime_version)
            info["_path"] = str(dll)          # stash for import detection
            build_year = _get_build_year(dll)
            build_date = _get_build_date_str(dll)
            v = classify(info, build_year)
            v["build_date"] = build_date
            v["hook_count"] = len(info.get("hooks", []))
            self._scan_data.append((dll, info, v))
            counts[v["cat"]] = counts.get(v["cat"], 0) + 1
            self.root.after(
                0,
                lambda d=dll, i=info, v=v: self._add_card(d, i, v),
            )

        # Update summary counts
        total = len(dlls)
        need = (counts.get("NEEDS_FIX", 0)
                + counts.get("DANGEROUS", 0)
                + counts.get("MANUAL", 0))
        ok_n = counts.get("OK", 0)
        other = counts.get("NOT_SKSE", 0)

        def _update_summary():
            self.c_need.config(
                text=f"{need} of {total} need attention" if need else "")
            self.c_ok.config(
                text=f"{ok_n} OK" if ok_n else "")
            parts = []
            if other:
                parts.append(f"{other} not SKSE")
            self.c_other.config(text="  \u2022  ".join(parts))

        self.root.after(0, _update_summary)

    def _add_card(self, dll, info, v):
        card = PluginCard(self.sf.inner, dll, info, v,
                          on_fix_one=self._fix_single,
                          force_fix=self.unsafe.get())
        ncol = 2
        row = len(self.cards) // ncol
        col = len(self.cards) % ncol
        card.grid(row=row, column=col, sticky="nsew",
                  padx=4, pady=4)
        self.sf.inner.grid_columnconfigure(0, weight=1, uniform="card")
        self.sf.inner.grid_columnconfigure(1, weight=1, uniform="card")
        self.cards.append(card)

    def _on_unsafe_toggle(self):
        # Rebuild cards from the last scan so every one shows fix buttons
        # when unsafe mode is on.
        for c in self.cards:
            c.destroy()
        self.cards.clear()
        for dll, info, v in getattr(self, "_scan_data", []):
            self._add_card(dll, info, v)

    def _clear_cards(self):
        for c in self.cards:
            c.destroy()
        self.cards.clear()
        self.c_need.config(text="")
        self.c_ok.config(text="")
        self.c_other.config(text="")

    # ──────────────────────────────────────────────────────────────
    # Fix Single
    # ──────────────────────────────────────────────────────────────

    def _fix_single(self, card, kind="all"):
        if not card.verdict["safe"] and kind == "all":
            if not messagebox.askyesno(
                "Warning",
                f"{card.dll_path.name} is classified as "
                f"{card.verdict['badge']}.\n\n"
                "Fixing it may break the plugin.  Continue?",
            ):
                card.mark_idle()
                return
        self._run(lambda: self._fix_single_worker(card, kind))

    def _fix_single_worker(self, card, kind):
        self._load_game_data()
        self._apply_fix(card, kind)

    # ──────────────────────────────────────────────────────────────
    # Fix engine helpers
    # ──────────────────────────────────────────────────────────────

    def _load_game_data(self):
        """Lazily load exe sections and address library for Layer 3 fixes."""
        if self._exe is not None and self._addresslib is not None:
            return
        if self.game_exe and self._exe is None:
            self._exe, self._exe_sections = core.load_exe_sections(
                str(self.game_exe))
        al_path = self._resolve_al()
        if al_path and al_path.exists() and self._addresslib is None:
            self._addresslib = core.parse_addresslib(str(al_path))

    def _apply_fix(self, card, kind="all"):
        """Run the requested fix kind for one card; post result to UI thread."""
        try:
            # Unsafe mode forces the flags; safe mode only patches when needed.
            force = getattr(card, "force_fix", False)
            changed = []
            if kind in ("all", "flag"):
                if force:
                    ok = core.patch_flag_force(card.dll_path)
                else:
                    ok = core.patch_flag(card.dll_path)
                if ok:
                    changed.append("flag -> 2" if force else "flag 0 -> 2")
            if kind in ("all", "addrlib"):
                if force:
                    ok = core.patch_version_independence_force(card.dll_path)
                else:
                    ok = core.patch_version_independence(card.dll_path)
                if ok:
                    changed.append("address lib flags")
            if kind in ("all", "hooks"):
                # Resolve hook offsets against the installed address library.
                self._load_game_data()
                if self._exe is not None and self._addresslib is not None:
                    rv = (core.runtime_version_from_exe(self.game_exe)
                          if self.game_exe else None)
                    info = core.analyze_plugin(card.dll_path, rv)
                    n = 0
                    for hook in info.get("hooks", []):
                        rel_id = hook.get("rel_id")
                        if rel_id not in self._addresslib:
                            continue
                        base = self._addresslib[rel_id]
                        old_off = hook.get("offset")
                        # Already correct?
                        if core.pattern_matches_at(
                                self._exe, self._exe_sections, base, old_off, hook.get("pattern")):
                            continue
                        # Find unique new offset near the old one.
                        matches = core.find_pattern_offsets(
                            self._exe, self._exe_sections, base,
                            hook.get("pattern"), old_off)
                        if len(matches) == 1:
                            core.patch_hook_offset(card.dll_path, hook, matches[0])
                            n += 1
                    if n:
                        changed.append(f"hooks patched ({n})")
                else:
                    changed.append("hooks skipped (no address library)")
            if changed:
                msg = "; ".join(changed)
                self.root.after(0, lambda: card.mark_fixed(True, msg))
            else:
                # Nothing actually changed - report honestly, keep buttons usable.
                already = "already up to date"
                if force and kind in ("flag", "addrlib"):
                    already = "already set to target"
                self.root.after(0, lambda: card.mark_noop(already))
        except Exception as exc:
            self.root.after(0, lambda: card.mark_fixed(False, str(exc)))

    # ─────────────────────────────────────────────────────────────
    # Clear
    # ─────────────────────────────────────────────────────────────

    def clear(self):
        self._clear_cards()
        self.status.config(text="Ready")

    # ──────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────

    def _resolve_al(self):
        """Return the first versionlib bin in the plugins folder."""
        plugins = self._plugins()
        if plugins and plugins.exists():
            bins = sorted(plugins.glob("versionlib-*.bin"))
            if bins:
                return bins[0]
        return None


# ===================================================================
# Entry point
# ===================================================================

def main():
    root = tk.Tk()
    app = AutoPorterGUI(root)
    # Auto-scan on startup if the game exe + plugins dir are present.
    if app.game_exe and app._plugins() and app._plugins().exists():
        root.after(100, app.scan)
    root.mainloop()


if __name__ == "__main__":
    main()
