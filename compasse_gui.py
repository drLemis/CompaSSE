#!/usr/bin/env python3
"""CompaSSE UI: per-mod cards for scan/fix."""
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
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
import skse_healer as healer
import skse_surgeon as surgeon


def find_game_exe():
    """Locate SkyrimSE.exe in the same folder this tool lives in."""
    cand = HERE / "SkyrimSE.exe"
    return cand if cand.exists() else None


def plugins_dir_for(game_exe):
    """Derive the SKSE plugins folder from the game executable path."""
    game_dir = Path(game_exe).resolve().parent
    return game_dir / "Data" / "SKSE" / "Plugins"


def game_version_line(game_exe):
    """'Game: SkyrimSE.exe (1.7.104)'; version omitted when unreadable."""
    name = Path(game_exe).name if game_exe else "SkyrimSE.exe"
    ver = core.unpack_version(core.runtime_version_from_exe(game_exe)) \
        if game_exe else None
    line = f"Game: {name}"
    return f"{line} ({ver[0]}.{ver[1]}.{ver[2]})" if ver else line

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


# ===================================================================
# Concurrency: one operation at a time, UI thread only
# ===================================================================

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

def _launch(root, work, fn):
    """Run fn in a worker; work.release() back on the UI thread."""
    def _worker():
        try:
            fn()
        except Exception as exc:
            root.after(0, lambda: messagebox.showerror("Error", str(exc)))
        finally:
            root.after(0, work.release)
    threading.Thread(target=_worker, daemon=True).start()


# ===================================================================
# Classification helper
# ===================================================================

def _get_build_dt(dll_path):
    """PE build timestamp as datetime (UTC), or None. Single impl in core."""
    return core.pe_build_dt(dll_path)


def _get_build_year(dll_path):
    """Build year, or None."""
    dt = _get_build_dt(dll_path)
    return dt.year if dt else None


def _get_build_date_str(dll_path):
    """Full build date string like '2022 July 04'."""
    dt = _get_build_dt(dll_path)
    if dt is None:
        return None
    return dt.strftime("%Y %B %d").replace(" 0", " ")


def classify(info, build_year, runtime_version=None, dll_path=None, id_set=None):
    """Turn analyze_plugin output + build year into a verdict dict.

    runtime_version (packed, from the user's game exe) enables the
    built-for-you branches: a plugin declaring the running version is
    judged against its own era, not current flag fashion.
    dll_path + id_set enable the xref check: real game addresses in
    the binary override flags claiming no Address Library.
    """
    flag = info.get("flag")
    vi = info.get("version_indep")
    rv = (vi or {}).get("runtime_ver")
    version = core._packed_to_ver(rv) if rv else None
    compat = (vi or {}).get("compat") or []
    _match = core.compat_match(compat, runtime_version)
    declares_running = _match == "exact"
    rev_match = _match == "rev"
    run_str = core._packed_to_ver(runtime_version) if runtime_version else None
    declared_tup = core.unpack_version(rv) if rv else None
    run_tup = core.unpack_version(runtime_version) if runtime_version else None
    crossed = core.crossed_cutoffs(declared_tup, run_tup)
    cross_note = ""
    if crossed:
        names = ", ".join(f"{a}.{b}.{c}" for a, b, c in crossed)
        cross_note = (f" Crosses structural break(s) {names}: even patched, "
                      "struct drift may still crash it - test in-game.")

    def _base(cat, badge, key, why, fix_desc="", safe=False, needs_fix=False, items=None):
        return dict(cat=cat, badge=badge, key=key, why=why, fix_desc=fix_desc,
                    safe=safe, needs_fix=needs_fix, version=version,
                    build_year=build_year, fix_items=items or [],
                    run_ver=run_str)

    # Not an SKSE plugin at all
    if flag is None and vi is None:
        return _base("NOT_SKSE", "NOT SKSE", "NOT_SKSE",
                     "No SKSEPlugin_Version export found. This is not an SKSE plugin.")

    old = build_year is not None and build_year < 2025
    recent = build_year is not None and build_year >= 2025
    # versionIndependence flag bits, matching SKSE's own check. Sigs count:
    # CommonLib treats addr OR sigs as version-independent.
    addrlib = bool(vi and (vi.get("has_addr", False)
                           or vi.get("has_sigs", False)))
    # Ex=0 is inert where V5 is unenforced (pre-1.7): don't flag or fix it.
    v5_here = core._v5_enforced(run_tup)
    flag_patch = flag is not None and flag.get("needs_patch", False) \
        and v5_here
    indep_patch = vi is not None and vi.get("needs_indep", False)
    has_unknown = vi is not None and vi.get("has_unknown", False)

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
    # Build year undetermined: fall back to flag analysis
    if build_year is None:
        if flag_patch or indep_patch:
            why = ("Cannot determine build year. Plugin needs flag patches "
                   "but safety is uncertain.")
            if crossed:
                why += cross_note
            return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                         why,
                         "Review manually before patching.", False, True, items)
        return _base("OK", "OK", "OK",
                     "No patches needed. Build year unknown but flags look correct.")

    any_patch = flag_patch or indep_patch

    # Plugin needs patching
    if any_patch:
        if declares_running:
            return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                         (f"Declares your game version ({run_str}) but predates "
                          "the current flag scheme. Try it unpatched first - "
                          "patch only if SKSE rejects it." + cross_note),
                         "Try loading first; patch on rejection.", False, True, items)

        if rev_match:
            return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                         (f"Made for your game version ({run_str}), only the "
                          "revision differs. Try it first - patch only if the "
                          "game rejects it." + cross_note),
                         "Try loading first; patch on rejection.",
                         False, True, items)

        if old and addrlib:
            parts = [
                f"Built {build_year} (old CommonLibSSE). "
                "Uses Address Library or signature scanning but SKSE "
                "rejects it due to outdated version flags.",
            ]
            if crossed:
                parts.append(cross_note.strip())
            fix_desc = "Patch the flags so SKSE accepts it."
            return _base("NEEDS_FIX", "NEEDS FIX", "NEEDS_FIX",
                         "  ".join(parts), fix_desc, True, True, items)

        if recent and addrlib:
            why = (
                f"Built {build_year} (recent). Uses Address Library or "
                "signature scanning but SKSE "
                "still rejects it, likely missing version-independence flags "
                "needed to declare compatibility."
            )
            if crossed:
                why += cross_note
            return _base("NEEDS_FIX", "NEEDS FIX", "NEEDS_FIX",
                         why, "Patch the flags so SKSE accepts it.", True, True, items)

        if old and not addrlib:
            xref = None
            if dll_path is not None and id_set:
                xref = core.count_xref_ids(dll_path, id_set)
            if xref:
                return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                             (f"Built {build_year} (old). Flags say no Address "
                              f"Library but {xref} game address(es) found - "
                              "flags may be misdeclared. Try it first - patch "
                              "only if the game rejects it."),
                             "Try loading first; patch on rejection.",
                             False, True, items)
            why = (f"Built {build_year} (old). Does not use Address Library. "
                   "Likely has hardcoded Skyrim addresses. "
                   "Auto-patching would break it.")
            if crossed and version:
                names = ", ".join(f"{a}.{b}.{c}" for a, b, c in crossed)
                why += (f" Built for {version}, {len(crossed)} structural "
                        f"break(s) since ({names}) - unfixable without a "
                        "source recompile. No patcher bridges that.")
            return _base("DANGEROUS", "DANGEROUS", "DANGEROUS",
                         why,
                         "Needs manual port or recompile with CommonLibNG. "
                         "Flag patches would only break it further.",
                         False, False, [])

        # recent + no addrlib, or other ambiguous
        why = (f"Built {build_year}. Does not declare Address Library usage. "
               "Flags need patching but safety is unclear.")
        if crossed:
            why += cross_note
        return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                     why,
                     "Review manually before patching.", False, True, items)

    # No patches needed based on flags
    if declares_running:
        if crossed:
            names = ", ".join(f"{a}.{b}.{c}" for a, b, c in crossed)
            return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                         (f"Declares your game version ({run_str}) but "
                          f"crosses structural break(s) ({names}): struct "
                          f"drift may still crash it - test in-game, patch "
                          f"only if SKSE rejects it."),
                         "Test in-game first; patch on rejection.",
                         False, False, items)
        return _base("OK", "OK", "OK",
                     f"Declares your game version ({run_str}). Built for it - leave it alone.")

    # Declares this game bar the revision: try unpatched first.
    if rev_match:
        return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                     (f"Made for your game version ({run_str}), only the "
                      "revision differs. Try it first - patch only if the "
                      "game rejects it."),
                     "Try loading first; patch on rejection.",
                     False, True, items)

    # Built for a game newer than the running one: flags can't bridge that.
    if declared_tup and run_tup and declared_tup > run_tup:
        behind = [c for c in core.STRUCTURAL_CUTOFFS
                  if run_tup < c <= declared_tup]
        names = ", ".join(f"{a}.{b}.{c}" for a, b, c in behind)
        why = (f"Built for a newer game ({version}) than yours ({run_str}). "
               "Patching its flags won't help.")
        if names:
            why += (f" It expects game changes from ({names}) "
                    "your game doesn't have.")
        why += " Ask the author for a version for your game."
        return _base("MANUAL", "MANUAL CHECK", "MANUAL", why,
                     "Needs a build for your game.", False, False, [])

    if has_unknown:
        return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                     (f"Unknown versionIndependence flags "
                      f"(0x{vi['indep_val']:x}). Cannot verify safety."),
                     "Review manually.", False, False, [])

    ok_why = ("All flags and version info look correct. Should load, "
              "but that doesn't guarantee it works in-game.")
    if crossed:
        ok_why += cross_note
    if (vi and vi.get("has_addr", False) and not vi.get("has_ex_v5", True)
            and vi.get("pre_cutoff", False) and not v5_here):
        ok_why += (" Note: flags predate the V5 scheme (inert on this "
                   "runtime); if a newer SKSE ever reports 'must be "
                   "recompiled', patch the flags.")
    return _base("OK", "OK", "OK", ok_why)


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

class PendingCard(tk.Frame):
    """A listed-but-unchecked DLL. One Scan button, no analysis yet."""

    def __init__(self, parent, dll_path, on_scan, **kw):
        super().__init__(parent, bg=CARD_BG, relief="solid", bd=1, **kw)
        self.dll_path = dll_path
        self.on_scan = on_scan

        self.bar = tk.Frame(self, bg="#9ca3af", width=4)
        self.bar.pack(side="left", fill="y")

        body = tk.Frame(self, bg=CARD_BG)
        body.pack(side="left", fill="both", expand=True, padx=(0, 12), pady=10)

        self.scan_btn = tk.Button(
            body, text="Scan",
            font=(FONT_FAMILY, 9, "bold"),
            relief="raised", bd=1, padx=12, pady=2,
            bg="#e0e7ff", fg="#3730a3",
            activebackground="#c7d2fe", activeforeground="#1e1b4b",
            cursor="hand2", command=self._on_scan_click)
        self.scan_btn.pack(side="right")

        self._font = tkfont.Font(font=NAME_FONT_SPEC)
        self._full_name = dll_path.name
        self._full_px = self._font.measure(self._full_name)
        self._tip = None
        short, cut = _ellipsize(self._font, self._full_name)
        self.name_lbl = tk.Label(body, text=short, font=NAME_FONT_SPEC,
                                 fg=TEXT_PRIMARY, bg=CARD_BG, anchor="w")
        self.name_lbl.pack(side="left", fill="x", expand=True)
        if cut:
            self._tip = _HoverTip(self.name_lbl, self._full_name)
        self.name_lbl.bind("<Configure>", self._on_name_resize, add="+")

    def _on_name_resize(self, event):
        if event.width <= 1:
            return
        cur = self.name_lbl.cget("text")
        if event.width >= self._full_px:
            if cur != self._full_name:
                self.name_lbl.config(text=self._full_name)
            return
        if self.name_lbl.winfo_reqwidth() <= event.width:
            return
        short, _ = _ellipsize(self._font, self._full_name, event.width)
        if short != cur:
            self.name_lbl.config(text=short)
            if self._tip is None:
                self._tip = _HoverTip(self.name_lbl, self._full_name)

    def _on_scan_click(self):
        self.on_scan(self)

    def set_working(self, working):
        try:
            self.scan_btn.config(state="disabled" if working else "normal")
        except Exception:
            pass


class PluginCard(tk.Frame):
    """A card representing one scanned plugin with status + controls."""

    def __init__(self, parent, dll_path, info, verdict, on_fix_one,
                 on_restore_one=None, force_fix=False, **kw):
        super().__init__(parent, bg=CARD_BG, relief="solid", bd=1, **kw)
        self.dll_path = dll_path
        self.info = info
        self.verdict = verdict
        self.on_fix_one = on_fix_one
        self.on_restore_one = on_restore_one
        self.force_fix = force_fix
        self.fixed = False
        self.fix_buttons = []
        self.undo_btn = None

        colors = BADGE_COLORS[verdict["key"]]

        # -- Left accent bar --
        self.bar = tk.Frame(self, bg=colors["bar"], width=4)
        self.bar.pack(side="left", fill="y")

        # -- Content area --
        body = tk.Frame(self, bg=CARD_BG)
        body.pack(side="left", fill="both", expand=True, padx=(0, 12), pady=10)

        # Header row: name
        hdr = tk.Frame(body, bg=CARD_BG)
        hdr.pack(fill="x", pady=(0, 4))

        _name_label(hdr, dll_path.name).pack(side="left")

        # Version / era line (secondary info)
        ver = verdict.get("version")
        bdate = verdict.get("build_date")
        run = verdict.get("run_ver")
        yline = ""
        if bdate:
            yline += f"{bdate} - "
        if ver:
            yline += f"Skyrim SSE {ver}"
        if run and run != ver:
            yline += f"  (your game: {run})"
        if yline:
            tk.Label(body, text=yline,
                     font=(FONT_FAMILY, 9),
                     fg=TEXT_SECONDARY, bg=CARD_BG,
                     anchor="w").pack(fill="x", pady=(0, 2))

        # Risk factor explanation
        why = verdict.get("why", "")
        if why:
            tk.Label(body, text=why,
                     font=(FONT_FAMILY, 9),
                     fg=TEXT_SECONDARY, bg=CARD_BG,
                     anchor="w", wraplength=380).pack(fill="x", pady=(0, 2))

        # Stale-hook pointer: Therapist never patches hooks, so this line
        # sends the user to the Healer tab. Bright red so it isn't missed.
        hook_note = verdict.get("hook_note", "")
        if hook_note:
            tk.Label(body, text=hook_note,
                     font=(FONT_FAMILY, 9, "bold"),
                     fg="#dc2626", bg=CARD_BG,
                     anchor="w", wraplength=380).pack(fill="x", pady=(0, 2))

        # PRO mode: expose all raw details
        if force_fix:
            details_lines = []
            flag = info.get("flag")
            vi = info.get("version_indep")
            hooks = info.get("hooks", [])
            if flag is not None:
                details_lines.append(f"versionIndependenceEx: 0x{flag['flag_val']:x}")
            if vi is not None:
                details_lines.append(f"versionIndependence: 0x{vi['indep_val']:x}")
                if vi.get("runtime_ver"):
                    rv = vi["runtime_ver"]
                    b = rv.to_bytes(4, "little")
                    details_lines.append(f"compatibleVersions: {b[3]}.{b[2]}.{b[1]}.{b[0]}")
            if hooks:
                for h in hooks:
                    pat = " ".join(f"{h['pattern'].get(k, '??'):02x}"
                                   for k in sorted(h['pattern'].keys()))
                    details_lines.append(
                        f"hook REL::ID={h['rel_id']} off=0x{h['offset']:x} "
                        f"len={h['pattern_len']} [{pat}]")
            if details_lines:
                tk.Label(body, text="\n".join(details_lines),
                         font=(FONT_MONO, 8),
                         fg=TEXT_SECONDARY, bg=CARD_BG,
                         anchor="w", justify="left").pack(fill="x", pady=(0, 2))

        # -- Controls (only when the plugin needs fixing, or forced in pro mode) --
        if verdict["needs_fix"] or force_fix:
            fix_items = verdict.get("fix_items", [])

            if force_fix:
                # PRO mode: offer BOTH address fixes to every mod,
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

        # -- Undo fix (only when a stored original exists) --
        if self.on_restore_one is not None \
                and core.backup_path(dll_path) is not None:
            self.undo_btn = tk.Button(
                body, text="Undo fix",
                font=(FONT_FAMILY, 9),
                relief="raised", bd=1, padx=12, pady=2,
                bg="#f3f4f6", fg=TEXT_SECONDARY,
                activebackground="#e5e7eb", activeforeground=TEXT_PRIMARY,
                cursor="hand2", command=self._on_undo_click)
            self.undo_btn.pack(fill="x", pady=(4, 0))

    # -- Card actions ----------------------------------------------

    def _on_undo_click(self):
        if self.undo_btn is not None:
            try:
                self.undo_btn.config(state="disabled")
            except Exception:
                pass
        if self.on_restore_one is not None:
            self.on_restore_one(self)

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

    def set_working(self, working):
        if self.undo_btn is not None:
            try:
                self.undo_btn.config(state="disabled" if working else "normal")
            except Exception:
                pass
        if not self.fix_buttons:
            return
        if working:
            self._disable_all_fix()
        else:
            self.mark_idle()

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
# Healer card (for stale pattern scan offsets)
# ===================================================================

HEALER_BADGE_COLORS = {
    "AUTO_FIXABLE": {"bar": "#22c55e"},
    "MANUAL_NEEDED": {"bar": "#f97316"},
    "FUNCTION_REWRITTEN": {"bar": "#ef4444"},
}


class HealerCard(tk.Frame):
    """A card representing one stale offset finding."""

    def __init__(self, parent, finding, exe_data, exe_sections, on_heal,
                 old_exe_data=None, old_exe_sections=None, **kw):
        super().__init__(parent, bg=CARD_BG, relief="solid", bd=1, **kw)
        self.finding = finding
        self.exe_data = exe_data
        self.exe_sections = exe_sections
        self.old_exe_data = old_exe_data
        self.old_exe_sections = old_exe_sections
        self.on_heal = on_heal
        self.fixed = False
        self._note = False
        self.selected_offset = finding.get("new_offset")

        auto_fix = finding.get("auto_fixable", False)
        has_reason = "reason" in finding
        has_candidates = "candidates" in finding
        if auto_fix:
            badge_key = "AUTO_FIXABLE"
        elif has_reason:
            badge_key = "FUNCTION_REWRITTEN"
        else:
            badge_key = "MANUAL_NEEDED"
        colors = HEALER_BADGE_COLORS[badge_key]

        # Left accent bar
        self.bar = tk.Frame(self, bg=colors["bar"], width=4)
        self.bar.pack(side="left", fill="y")

        # Content area
        body = tk.Frame(self, bg=CARD_BG)
        body.pack(side="left", fill="both", expand=True, padx=(0, 12), pady=10)

        # Header: plugin name
        dll_path = finding["dll_path"]
        _name_label(body, dll_path.name).pack(anchor="w")

        # ID + offset info
        id_val = finding["id_val"]
        func_rva = finding["func_rva"]
        old_off = finding["old_offset"]
        new_off = finding.get("new_offset")
        info_line = f"REL::ID {id_val}  (func RVA 0x{func_rva:X})"
        tk.Label(body, text=info_line,
                 font=(FONT_FAMILY, 9),
                 fg=TEXT_SECONDARY, bg=CARD_BG,
                 anchor="w").pack(fill="x")

        # Bytes at stale offset
        func_off = healer.rva_to_offset(func_rva, exe_sections)
        if func_off is not None:
            stale_bytes = healer.extract_bytes_at(exe_data, func_off + old_off, 16)
            if stale_bytes:
                stale_hex = stale_bytes.hex(" ")
                tk.Label(body, text=f"New binary at 0x{old_off:X}: {stale_hex}",
                         font=(FONT_MONO, 8),
                         fg=TEXT_SECONDARY, bg=CARD_BG,
                         anchor="w").pack(fill="x")

        # Old binary bytes (if available)
        if old_exe_data and old_exe_sections:
            old_func_off = healer.rva_to_offset(func_rva, old_exe_sections)
            if old_func_off is not None:
                old_bytes = healer.extract_bytes_at(old_exe_data, old_func_off + old_off, 16)
                if old_bytes:
                    old_hex = old_bytes.hex(" ")
                    tk.Label(body, text=f"Old binary at 0x{old_off:X}: {old_hex}",
                             font=(FONT_MONO, 8),
                             fg="#6366f1", bg=CARD_BG,
                             anchor="w").pack(fill="x")

        # Offset details
        if new_off is not None:
            detail = f"Offset: 0x{old_off:X} -> 0x{new_off:X}"
        else:
            detail = f"Offset: 0x{old_off:X} -> ?"
        tk.Label(body, text=detail,
                 font=(FONT_MONO, 9),
                 fg=TEXT_PRIMARY, bg=CARD_BG,
                 anchor="w").pack(fill="x")

        # Status / reason
        if "reason" in finding:
            status_text = finding["reason"]
        elif auto_fix and new_off is not None:
            status_text = "Auto-fixable"
        elif has_candidates:
            n = len(finding["candidates"])
            status_text = f"{n} candidates - select one below"
        else:
            status_text = "Needs manual investigation"
        tk.Label(body, text=status_text,
                 font=(FONT_FAMILY, 9),
                 fg=TEXT_SECONDARY, bg=CARD_BG,
                 anchor="w", wraplength=380).pack(fill="x", pady=(2, 4))

        # Candidate selection (when multiple CALL+MOV patterns found)
        self.candidate_var = tk.IntVar(value=-1)
        self.candidate_buttons = []
        if has_candidates and not auto_fix:
            candidates = finding["candidates"]
            closest = finding.get("closest_candidate")
            tk.Label(body, text="Candidate offsets:",
                     font=(FONT_FAMILY, 9, "bold"),
                     fg=TEXT_PRIMARY, bg=CARD_BG,
                     anchor="w").pack(fill="x", pady=(4, 2))

            cand_frame = tk.Frame(body, bg=CARD_BG)
            cand_frame.pack(fill="x")

            for idx, (coff, call_tgt) in enumerate(candidates):
                if func_off is not None:
                    cand_bytes = healer.extract_bytes_at(exe_data, func_off + coff, 8)
                    cand_hex = cand_bytes.hex(" ") if cand_bytes else "??"
                else:
                    cand_hex = "??"
                dist = coff - old_off
                label = f"0x{coff:X} ({dist:+d})  [{cand_hex}]"
                is_closest = (closest == coff)
                if is_closest:
                    label += "  <-- closest"

                rb = tk.Radiobutton(
                    cand_frame, text=label,
                    variable=self.candidate_var, value=coff,
                    font=(FONT_MONO, 8),
                    fg=TEXT_PRIMARY, bg=CARD_BG,
                    selectcolor=CARD_BG,
                    activebackground=CARD_BG,
                    anchor="w",
                    command=self._on_candidate_select,
                )
                rb.pack(fill="x", anchor="w")
                self.candidate_buttons.append(rb)

        # Action row
        btn_frame = tk.Frame(body, bg=CARD_BG)
        btn_frame.pack(fill="x", pady=(4, 0))

        if auto_fix and new_off is not None:
            # Direct heal button
            self.heal_btn = tk.Button(
                btn_frame,
                text="Heal",
                font=(FONT_FAMILY, 9, "bold"),
                relief="raised", bd=1,
                padx=12, pady=4,
                bg="#fef08a", fg="#713f12",
                activebackground="#fde047", activeforeground="#422006",
                cursor="hand2",
                command=self._on_heal_click,
            )
            self.heal_btn.pack(side="left")
        elif has_candidates:
            # Heal with selected candidate
            self.heal_btn = tk.Button(
                btn_frame,
                text="Heal with selected",
                font=(FONT_FAMILY, 9, "bold"),
                relief="raised", bd=1,
                padx=12, pady=4,
                bg="#e0e0e0", fg="#404040",
                activebackground="#d0d0d0", activeforeground="#202020",
                cursor="hand2",
                state="disabled",
                command=self._on_heal_click,
            )
            self.heal_btn.pack(side="left")
        else:
            self.heal_btn = None

        # Status label
        self.status_lbl = tk.Label(body, text="",
                                   font=(FONT_FAMILY, 9),
                                   fg=TEXT_SECONDARY, bg=CARD_BG)
        self.status_lbl.pack(anchor="w")

    def _on_candidate_select(self):
        sel = self.candidate_var.get()
        if sel >= 0 and self.heal_btn:
            self.heal_btn.config(state="normal", bg="#fef08a", fg="#713f12")

    def _on_heal_click(self):
        sel = self.candidate_var.get()
        if sel >= 0:
            self.selected_offset = sel
        if self.selected_offset is None:
            return
        patched = dict(self.finding)
        patched["new_offset"] = self.selected_offset
        self.on_heal(self, patched)

    def mark_busy(self):
        if self.heal_btn:
            self.heal_btn.config(state="disabled")
        self.status_lbl.config(text="Patching...")

    def note(self, text):
        self._note = True
        self.status_lbl.config(text=text, fg=TEXT_SECONDARY)

    def mark_fixed(self, success, message):
        self.fixed = True
        if self.heal_btn:
            self.heal_btn.config(state="disabled")
        self.status_lbl.config(
            text="Fixed \u2713" if success else ("Failed: " + message),
            fg="#16a34a" if success else "#dc2626",
        )

    def set_working(self, working):
        if working:
            self._snap = [(w, w.cget("state"))
                          for w in [self.heal_btn, *self.candidate_buttons]
                          if w is not None]
            for w, _ in self._snap:
                try:
                    w.config(state="disabled")
                except Exception:
                    pass
        elif not self.fixed:
            for w, st in getattr(self, "_snap", []):
                try:
                    w.config(state=st)
                except Exception:
                    pass
            self._snap = []
            if getattr(self, "_note", False):
                self.status_lbl.config(text="")
                self._note = False


# ===================================================================
# Healer Tab
# ===================================================================

class HealerTab:
    """Tab for detecting and fixing stale pattern scan offsets in SKSE plugins."""

    def __init__(self, parent, game_exe, plugins_dir_fn, work):
        self.parent = parent
        self.game_exe = game_exe
        self._plugins_dir_fn = plugins_dir_fn
        self.work = work
        self.cards = []
        self._exe_data = None
        self._exe_sections = None

        self._build()
        self.work.listen(self._set_working)

    def _set_working(self, working, desc=""):
        state = "disabled" if working else "normal"
        self.scan_btn.config(state=state)
        self.clear_btn.config(state=state)
        self.trans_btn.config(state=state)
        self.browse_plugin_btn.config(state=state)
        self.browse_old_btn.config(state=state)
        for c in self.cards:
            c.set_working(working)

    def _build(self):
        # Top controls
        ctrl = tk.Frame(self.parent, bg=BG)
        ctrl.pack(fill="x", padx=10, pady=(10, 4))

        # Plugin selector
        tk.Label(ctrl, text="Plugin:",
                 font=(FONT_FAMILY, 10), fg=TEXT_PRIMARY, bg=BG
                 ).pack(side="left")
        self.plugin_var = tk.StringVar()
        self.plugin_entry = ttk.Entry(ctrl, textvariable=self.plugin_var, width=40)
        self.plugin_entry.pack(side="left", padx=(6, 4))
        self.browse_plugin_btn = ttk.Button(
            ctrl, text="Browse...", command=self._browse_plugin)
        self.browse_plugin_btn.pack(side="left", padx=(0, 12))

        # Old game exe selector (optional)
        tk.Label(ctrl, text="Old game (optional):",
                 font=(FONT_FAMILY, 10), fg=TEXT_PRIMARY, bg=BG
                 ).pack(side="left")
        self.old_game_var = tk.StringVar()
        self.old_game_entry = ttk.Entry(ctrl, textvariable=self.old_game_var, width=40)
        self.old_game_entry.pack(side="left", padx=(6, 4))
        self.browse_old_btn = ttk.Button(
            ctrl, text="Browse...", command=self._browse_old_game)
        self.browse_old_btn.pack(side="left")

        # Buttons row
        btn_frame = tk.Frame(self.parent, bg=BG)
        btn_frame.pack(fill="x", padx=10, pady=(4, 4))

        self.scan_btn = ttk.Button(btn_frame, text="Scan", command=self.scan)
        self.scan_btn.pack(side="left", padx=(0, 6))

        self.clear_btn = ttk.Button(btn_frame, text="Clear",
                                    command=self._clear_cards)
        self.clear_btn.pack(side="left")

        self.trans_btn = ttk.Button(btn_frame, text="Build Translations",
                                    command=self.build_translations)
        self.trans_btn.pack(side="left", padx=(12, 0))

        # Summary
        self.summary_lbl = tk.Label(btn_frame, text="",
                                    font=(FONT_FAMILY, 10, "bold"),
                                    fg=TEXT_PRIMARY, bg=BG)
        self.summary_lbl.pack(side="left", padx=(16, 0))

        # Scrollable card area
        self.sf = ScrollFrame(self.parent)
        self.sf.pack(fill="both", expand=True, padx=10, pady=(2, 4))

    # -- Browse --

    def _browse_plugin(self):
        path = filedialog.askopenfilename(
            title="Select Plugin DLL",
            filetypes=[("DLL files", "*.dll"), ("All files", "*.*")],
            initialdir=str(self._plugins_dir_fn() or ""),
        )
        if path:
            self.plugin_var.set(path)
            self.scan()

    def _browse_old_game(self):
        path = filedialog.askopenfilename(
            title="Select Old SkyrimSE.exe (optional)",
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")],
        )
        if path:
            self.old_game_var.set(path)

    # -- Scan --

    def scan(self):
        plugin_path = self.plugin_var.get().strip()
        if not plugin_path:
            messagebox.showerror("Error", "Select a plugin DLL first.")
            return
        plugin_path = Path(plugin_path)
        if not plugin_path.exists():
            messagebox.showerror("Error", f"Plugin not found:\n{plugin_path}")
            return
        if self.game_exe is None:
            messagebox.showerror("Error", "Place this tool in the same folder as SkyrimSE.exe.")
            return
        plugins_dir = self._plugins_dir_fn()
        if plugins_dir is None or not plugins_dir.exists():
            messagebox.showerror("Error", "Plugins folder not found.")
            return

        old_game = self.old_game_var.get().strip()
        old_game_path = Path(old_game) if old_game else None
        if old_game_path and not old_game_path.exists():
            messagebox.showerror("Error", f"Old game exe not found:\n{old_game_path}")
            return

        self._run(lambda: self._do_scan(plugin_path, plugins_dir, old_game_path),
                  f"Checking {plugin_path.name}...")

    def _do_scan(self, plugin_path, plugins_dir, old_game_path):
        self.root.after(0, self._clear_cards)
        try:
            self._exe_data, self._exe_sections = healer.load_game_sections(self.game_exe)
            self._old_exe_data = None
            self._old_exe_sections = None
            if old_game_path:
                self._old_exe_data, self._old_exe_sections = healer.load_game_sections(old_game_path)
            findings, _, _, _ = healer.analyze_plugin(
                plugin_path, self.game_exe, plugins_dir, old_game_path)
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("Error", str(exc)))
            return

        for f in findings:
            self.root.after(
                0,
                lambda finding=f: self._add_card(finding),
            )

        n = len(findings)
        auto = sum(1 for f in findings if f.get("auto_fixable"))
        manual = n - auto
        if n == 0:
            self.root.after(0, lambda: self.summary_lbl.config(
                text="No stale offsets found"))
        else:
            parts = []
            if auto:
                parts.append(f"{auto} auto-fixable")
            if manual:
                parts.append(f"{manual} manual")
            self.root.after(0, lambda t=", ".join(parts): self.summary_lbl.config(
                text=f"{n} stale offset(s): {t}"))

    def _add_card(self, finding):
        card = HealerCard(self.sf.inner, finding,
                          self._exe_data, self._exe_sections,
                          on_heal=self._heal_one,
                          old_exe_data=self._old_exe_data,
                          old_exe_sections=self._old_exe_sections)
        card.pack(fill="x", padx=4, pady=4)
        self.cards.append(card)
        if self.work.busy:
            card.set_working(True)

    # -- Heal --

    def _heal_one(self, card, patched_finding=None):
        if not self.work.acquire(f"Patching {card.finding['dll_path'].name}..."):
            card.note("Please wait - still working...")
            return
        card.mark_busy()
        _launch(self.root, self.work,
                lambda: self._heal_worker(card, patched_finding))

    def _heal_worker(self, card, patched_finding=None):
        finding = patched_finding or card.finding
        dll_path = finding["dll_path"]
        try:
            ok = healer.heal_plugin(dll_path, finding, backup=True)
            msg = f"0x{finding['old_offset']:X} -> 0x{finding['new_offset']:X}" if ok else "patch failed"
            self.root.after(0, lambda: card.mark_fixed(ok, msg))
        except Exception as exc:
            self.root.after(0, lambda: card.mark_fixed(False, str(exc)))

    # -- Build Translations (global runtime data, slow) --

    def build_translations(self):
        if self.game_exe is None:
            messagebox.showerror(
                "Error", "Place this tool in the same folder as SkyrimSE.exe.")
            return
        plugins = self._plugins_dir_fn()
        if plugins is None or not plugins.exists():
            messagebox.showerror(
                "Error", f"Plugins folder not found:\n{plugins}")
            return
        self._run(lambda: self._do_build_translations(plugins),
                  "Updating helper data...")

    def _do_build_translations(self, plugins):
        try:
            game_ver = core.runtime_version_from_exe(self.game_exe)
            ver_count, total = core.build_translations(
                str(self.game_exe), plugins, game_version=game_ver)
            self.root.after(0, lambda: messagebox.showinfo(
                "Build Translations",
                f"Done.\n{ver_count} version(s), {total} entries.\n\n"
                f"Written to:\n{plugins / 'CompaSSE' / 'translation_table.bin'}"))
        except Exception as exc:
            self.root.after(
                0, lambda: messagebox.showerror("Error", str(exc)))

    # -- Helpers --

    def _run(self, fn, desc="Working..."):
        if self.work.acquire(desc):
            _launch(self.root, self.work, fn)

    def _clear_cards(self):
        for c in self.cards:
            c.destroy()
        self.cards.clear()
        self.summary_lbl.config(text="")

    @property
    def root(self):
        return self.parent.winfo_toplevel()


# ===================================================================
# Main GUI
# ===================================================================

def _window_icon():
    base = getattr(sys, "_MEIPASS", None) or str(Path(__file__).parent)
    ico = Path(base) / "compasse.ico"
    return str(ico) if ico.exists() else ""


SURGEON_BADGE_COLORS = {
    "core": {"bar": "#9ca3af"},
    "mod": {"bar": "#eab308"},
}


def _default_saves_dir():
    """Usual Saves folder, or None when it does not exist."""
    cand = (Path.home() / "Documents" / "My Games" / "Skyrim Special Edition"
            / "Saves")
    return cand if cand.exists() else None


class SurgeonCard(tk.Frame):
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

        title = f"{surgeon.uid_name(uid)} [0x{uid:08x}]"
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
            t = surgeon.fcc(c["type"])
            kinds.append(t if t.isprintable() else f"0x{c['type']:08x}")
        if kinds:
            more = f" +{len(block['chunks']) - 10} more" if len(block["chunks"]) > 10 else ""
            tk.Label(body, text=" ".join(kinds) + more,
                     font=(FONT_MONO, 8),
                     fg=TEXT_SECONDARY, bg=CARD_BG,
                     anchor="w").pack(fill="x")

        desc = surgeon.describe_chunks(block)
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

    def mark_busy(self):
        if self.drop_btn:
            self.drop_btn.config(state="disabled")
        self.status_lbl.config(text="Dropping...")

    def note(self, text):
        self._note = True
        self.status_lbl.config(text=text, fg=TEXT_SECONDARY)

    def mark_dropped(self, success, message):
        self.dropped = True
        if self.drop_btn:
            self.drop_btn.config(state="disabled")
        self.status_lbl.config(
            text="Dropped \u2713" if success else ("Failed: " + message),
            fg="#16a34a" if success else "#dc2626",
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

    def __init__(self, parent, plugins_dir_fn=None, work=None):
        self.parent = parent
        self._plugins_dir_fn = plugins_dir_fn
        self.work = work or BusyState()
        self.cards = []
        self._save_path = None
        self._preview_img = None
        self._build()
        self.work.listen(self._set_working)

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
            header, blocks, trailing = surgeon.parse_cosave(save_path)
        except ValueError as exc:
            self.root.after(0, lambda: messagebox.showerror("Error", str(exc)))
            return
        # Phase 1 (fast): identity + preview now, block scan after.
        ver = header["runtimeVersion"]
        game = f"{ver >> 24}.{(ver >> 16) & 0xFF}.{((ver >> 4) & 0xFFF)}"
        pretty = surgeon.parse_save_filename(save_path.name)
        ess_info = surgeon.read_ess_info(save_path.with_suffix(".ess"))
        ppm = None
        if ess_info and ess_info.get("shot"):
            ppm = surgeon.ess_thumbnail(ess_info["shot"])
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
        any_known = False
        for b in blocks:
            loc = surgeon.locate_uid(b["uid"], plugdir) if plugdir else None
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
                plist = surgeon.plugin_list_chunk(b, save_path)
                if plist is not None:
                    break
            if plist is not None:
                missing = surgeon.missing_mods(plist, plugdir.parent.parent)
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
            removed, left = surgeon.drop_plugin(card.save_path,
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


def count_stale_hooks(hooks, exe_data, exe_sections, addresslib):
    """How many detected hooks no longer match at their recorded offset.

    Triage only (this tab fixes flags): stale hooks are reported with a
    pointer to the Healer tab, never patched here. Unknown IDs are
    skipped - neither tab can fix those.
    """
    stale = 0
    for hook in hooks or []:
        try:
            base = (addresslib or {}).get(hook.get("rel_id"))
            if base is None:
                continue
            if not core.pattern_matches_at(
                    exe_data, exe_sections, base,
                    hook.get("offset"), hook.get("pattern")):
                stale += 1
        except Exception:
            continue
    return stale


class AutoPorterGUI:
    def __init__(self, root):
        self.root = root
        root.title(f"CompaSSE v{core.VERSION}")
        root.geometry("920x720")
        icon = _window_icon()
        if icon:
            try:
                root.iconbitmap(icon)
            except tk.TclError:
                pass
        root.minsize(700, 520)
        root.configure(bg=BG)

        # -- State --
        self.game_exe = find_game_exe()
        self.work = BusyState()
        self.cards = []
        self._ctx = None
        self._counts = {}
        self._scan_data = []

        self._build()
        self.work.listen(self._set_working)

    def _set_working(self, working, desc=""):
        state = "disabled" if working else "normal"
        self.scan_btn.config(state=state)
        self.clear_btn.config(state=state)
        self.restore_btn.config(state=state)
        self.pro_btn.config(state=state)
        self.rebuild_btn.config(state=state)
        for c in self.cards:
            c.set_working(working)
        self.root.title(f"CompaSSE v{core.VERSION} - {desc}" if working
                        else f"CompaSSE v{core.VERSION}")

    # --------------------------------------------------------------
    # Layout
    # --------------------------------------------------------------

    def _build(self):
        # -- Notebook (tabs) --
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=6, pady=(6, 0))

        # Tab 1: Therapist (flags and versions)
        self.tab_main = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_main, text="  Therapist  ")

        # Tab 2: Healer
        self.tab_healer = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_healer, text="  Healer  ")

        # Tab 3: Surgeon (co-save blocks)
        self.tab_surgeon = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_surgeon, text="  Surgeon  ")

        # -- Build main tab (existing UI, reparented to tab_main) --
        self._build_main_tab()

        # -- Build healer tab --
        self.healer_tab = HealerTab(
            self.tab_healer,
            game_exe=self.game_exe,
            plugins_dir_fn=self._plugins,
            work=self.work,
        )

        # -- Build surgeon tab --
        self.surgeon_tab = SurgeonTab(self.tab_surgeon,
                                      plugins_dir_fn=self._plugins,
                                      work=self.work)

    def _build_main_tab(self):
        parent = self.tab_main

        # -- Auto-detected location hint --
        pf = tk.Frame(parent, bg=BG)
        pf.pack(fill="x", padx=10, pady=(10, 4))
        if self.game_exe:
            tk.Label(pf, text=game_version_line(self.game_exe),
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

        # -- Buttons --
        bf = tk.Frame(parent, bg=BG)
        bf.pack(fill="x", padx=10, pady=(4, 4))

        self.scan_btn = ttk.Button(bf, text="Scan all", command=self.scan)
        self.scan_btn.pack(side="left", padx=(0, 6))

        self.clear_btn = ttk.Button(bf, text="Clear", command=self.clear)
        self.clear_btn.pack(side="left")

        self.restore_btn = ttk.Button(bf, text="Undo fixes", command=self.restore)
        self.restore_btn.pack(side="left", padx=(6, 0))

        self.pro_mode = tk.BooleanVar(value=False)
        self.pro_btn = tk.Checkbutton(
            bf, text="PRO MODE",
            variable=self.pro_mode,
            command=self._on_pro_toggle,
            font=(FONT_FAMILY, 9, "bold"),
            fg="#b91c1c", bg=BG, activebackground=BG,
            selectcolor=BG, cursor="hand2")
        self.pro_btn.pack(side="left", padx=(12, 0))

        # -- Data notice (hidden until a scan finds stale helper data) --
        self.notice_frame = tk.Frame(parent, bg="#fef3c7")
        self.notice_lbl = tk.Label(
            self.notice_frame, text="", font=(FONT_FAMILY, 9),
            fg="#713f12", bg="#fef3c7", anchor="w", justify="left")
        self.notice_lbl.pack(side="left", fill="x", expand=True,
                             padx=(10, 6), pady=6)
        self.rebuild_btn = tk.Button(
            self.notice_frame, text="Update now",
            font=(FONT_FAMILY, 9, "bold"),
            relief="raised", bd=1, padx=12, pady=2,
            bg="#fde047", fg="#422006",
            activebackground="#facc15", activeforeground="#1a2e05",
            cursor="hand2", command=self.rebuild_translations)
        self.rebuild_btn.pack(side="right", padx=(0, 10), pady=6)

        # -- Missing game-data notice (hidden unless no Address Library) --
        self.lib_frame = tk.Frame(parent, bg="#fee2e2")
        self.lib_lbl = tk.Label(
            self.lib_frame, text="", font=(FONT_FAMILY, 9),
            fg="#7f1d1d", bg="#fee2e2", anchor="w", justify="left")
        self.lib_lbl.pack(side="left", fill="x", expand=True,
                          padx=(10, 6), pady=6)

        # -- Summary bar --
        sf = tk.Frame(parent, bg=BG)
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

        # -- Scrollable card area --
        self.sf = ScrollFrame(parent)
        self.sf.pack(fill="both", expand=True, padx=10, pady=(2, 4))

    # --------------------------------------------------------------
    # Browse handlers
    # --------------------------------------------------------------

    def _plugins(self):
        """Return the plugins dir derived from the game exe next to the tool."""
        if not self.game_exe:
            return None
        return plugins_dir_for(self.game_exe)

    # --------------------------------------------------------------
    # Threading helpers
    # --------------------------------------------------------------

    def _run(self, fn, desc="Working..."):
        """Run fn in a background thread; all action buttons lock meanwhile."""
        if self.work.acquire(desc):
            _launch(self.root, self.work, fn)

    # --------------------------------------------------------------
    # Scan
    # --------------------------------------------------------------

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
        self._clear_cards()
        self._check_table_stamp(plugins)
        self._check_addresslib(plugins)
        self._ctx = None
        self._counts = {}
        self._scan_data = []
        self._run(lambda: self._do_scan(plugins), "Starting scan...")

    def list_dlls(self):
        """Instant file listing: one unchecked card per DLL, no analysis."""
        plugins = self._plugins()
        if plugins is None or not plugins.exists():
            return False
        self._clear_cards()
        self._ctx = None
        self._counts = {}
        self._scan_data = []
        for dll in sorted(plugins.glob("*.dll")):
            card = PendingCard(self.sf.inner, dll, on_scan=self._scan_single)
            self._place_card(card)
            self.cards.append(card)
        self._update_summary()
        return True

    def _place_card(self, card):
        ncol = 2
        row = len(self.cards) // ncol
        col = len(self.cards) % ncol
        card.grid(row=row, column=col, sticky="nsew", padx=4, pady=4)
        self.sf.inner.grid_columnconfigure(0, weight=1, uniform="card")
        self.sf.inner.grid_columnconfigure(1, weight=1, uniform="card")

    def _ensure_ctx(self, plugins):
        """One-time exe/library load shared by full and single scans."""
        if self._ctx is None:
            runtime_version = (core.runtime_version_from_exe(self.game_exe)
                               if self.game_exe else None)
            exe_data = exe_secs = addr_lib = None
            if self.game_exe is not None:
                try:
                    exe_data, exe_secs = core.load_exe_sections(str(self.game_exe))
                    game_ver = core.unpack_version(
                        core.runtime_version_from_exe(self.game_exe))
                    match = core.find_versionlib(plugins, game_ver) if game_ver else None
                    if match is not None:
                        addr_lib = core.parse_library_any(str(match))
                except Exception:
                    exe_data = exe_secs = addr_lib = None
            self._ctx = (runtime_version, exe_data, exe_secs, addr_lib)
        return self._ctx

    def _do_scan(self, plugins):
        runtime_version, exe_data, exe_secs, addr_lib = self._ensure_ctx(plugins)

        dlls = sorted(plugins.glob("*.dll"))
        total_mods = len(dlls)
        for i, dll in enumerate(dlls):
            self.root.after(
                0, lambda i=i, d=dll: self.work.set_desc(
                    f"Checking {d.name} ({i + 1}/{total_mods})"))
            try:
                info = core.analyze_plugin(dll, runtime_version, include_hooks=True)
            except OSError:
                continue
            build_year = _get_build_year(dll)
            build_date = _get_build_date_str(dll)
            v = classify(info, build_year, runtime_version, dll,
                         set(addr_lib) if addr_lib else None)
            v["build_date"] = build_date
            if exe_data is not None and addr_lib is not None:
                stale = count_stale_hooks(info.get("hooks"), exe_data,
                                          exe_secs, addr_lib)
                if stale:
                    v["hook_note"] = (f"{stale} stale hook offset(s) - go to the "
                                      "Healer tab to fix (or CLI --fix with old game files).")
            v["build_date"] = build_date
            self._scan_data.append((dll, info, v))
            self._counts[v["cat"]] = self._counts.get(v["cat"], 0) + 1
            self.root.after(
                0,
                lambda d=dll, i=info, v=v: self._add_scanned_card(d, i, v),
            )

        self.root.after(0, self._update_summary)

    def _check_table_stamp(self, plugins):
        """Warn when helper data doesn't match the game, offer rebuild."""
        self.notice_frame.pack_forget()
        if self.game_exe is None:
            return
        packed = core.runtime_version_from_exe(self.game_exe)
        game = core.unpack_version(packed) if packed else None
        if game is None:
            return
        game_str = f"{game[0]}.{game[1]}.{game[2]}"
        try:
            state, stamp = core.table_state(plugins, game_str)
        except Exception:
            return
        if state == "ok":
            return
        if state == "stale":
            text = (f"Helper data is for game {stamp}, but your game is "
                    f"{game_str}. Some old mods may not work until it is "
                    f"updated.")
            button = "Update now"
        elif state == "legacy":
            text = (f"Helper data is outdated and may not match game "
                    f"{game_str}. Some old mods may not work until it is "
                    f"updated.")
            button = "Update now"
        else:
            text = (f"Helper data is missing. Some old mods may not work "
                    f"until it is created.")
            button = "Create now"
        self.notice_lbl.config(text=text)
        self.rebuild_btn.config(text=button, state="normal")
        self.notice_frame.pack(fill="x", padx=10, pady=(4, 0))

    def _check_addresslib(self, plugins, game_ver=None):
        """Warn when no Address Library file matches the game. Returns found."""
        self.lib_frame.pack_forget()
        if game_ver is None:
            if self.game_exe is None:
                return False
            packed = core.runtime_version_from_exe(self.game_exe)
            game_ver = core.unpack_version(packed) if packed else None
        if game_ver is None:
            return False
        if core.find_versionlib(plugins, game_ver) is not None:
            return True
        game_str = f"{game_ver[0]}.{game_ver[1]}.{game_ver[2]}"
        self.lib_lbl.config(
            text=(f"No Address Library file for your game ({game_str}) in "
                  f"Plugins. Mods that need game addresses will fail at "
                  f"startup - install the all-in-one Address Library, "
                  f"then Scan again."))
        self.lib_frame.pack(fill="x", padx=10, pady=(4, 0))
        return False

    def rebuild_translations(self):
        plugins = self._plugins()
        if plugins is None:
            messagebox.showerror(
                "Error", "Place this tool in the same folder as SkyrimSE.exe.")
            return
        if not plugins.exists():
            messagebox.showerror(
                "Error", f"Plugins folder not found:\n{plugins}")
            return
        if not self.work.acquire("Updating helper data..."):
            return
        _launch(self.root, self.work, lambda: self._rebuild_worker(plugins))

    def _rebuild_worker(self, plugins):
        try:
            ver = core.runtime_version_from_exe(self.game_exe)
            core.build_translations(str(self.game_exe), plugins,
                                    game_version=ver)
        except Exception as exc:
            msg = str(exc)
            if "No old version bins" in msg:
                msg = ("Could not find older game data files. Make sure "
                       "Address Library is installed, then try again.")
            self.root.after(
                0, lambda: messagebox.showerror("Error", msg))
            self.root.after(
                0, lambda: self.rebuild_btn.config(state="normal"))
            return
        self.root.after(
            0, lambda: messagebox.showinfo(
                "Done", "Helper data is up to date for your game."))
        self.root.after(0, lambda: self.notice_frame.pack_forget())

    def _add_scanned_card(self, dll, info, v):
        card = PluginCard(self.sf.inner, dll, info, v,
                          on_fix_one=self._fix_single,
                          on_restore_one=self._restore_single,
                          force_fix=self.pro_mode.get())
        self._place_card(card)
        self.cards.append(card)
        if self.work.busy:
            card.set_working(True)
        self._update_summary()

    def _scan_single(self, card):
        if not self.work.acquire(f"Checking {card.dll_path.name}..."):
            return
        _launch(self.root, self.work,
                lambda: self._scan_single_worker(card))

    def _scan_single_worker(self, card):
        plugins = self._plugins()
        runtime_version, exe_data, exe_secs, addr_lib = self._ensure_ctx(plugins)
        try:
            info = core.analyze_plugin(card.dll_path, runtime_version,
                                       include_hooks=True)
        except OSError:
            return
        build_year = _get_build_year(card.dll_path)
        v = classify(info, build_year, runtime_version, card.dll_path,
                     set(addr_lib) if addr_lib else None)
        v["build_date"] = _get_build_date_str(card.dll_path)
        if exe_data is not None and addr_lib is not None:
            stale = count_stale_hooks(info.get("hooks"), exe_data,
                                      exe_secs, addr_lib)
            if stale:
                v["hook_note"] = (f"{stale} stale hook offset(s) - go to the "
                                  "Healer tab to fix (or CLI --fix with old game files).")
        dll, info = card.dll_path, info
        self.root.after(0, lambda: self._finish_single(card, dll, info, v))

    def _finish_single(self, card, dll, info, v):
        try:
            idx = self.cards.index(card)
        except ValueError:
            return
        card.destroy()
        new = PluginCard(self.sf.inner, dll, info, v,
                         on_fix_one=self._fix_single,
                         on_restore_one=self._restore_single,
                         force_fix=self.pro_mode.get())
        ncol = 2
        new.grid(row=idx // ncol, column=idx % ncol, sticky="nsew",
                 padx=4, pady=4)
        self.cards[idx] = new
        for i, (d, _, _) in enumerate(self._scan_data):
            if d == dll:
                self._scan_data[i] = (dll, info, v)
                break
        else:
            self._scan_data.append((dll, info, v))
        self._counts[v["cat"]] = self._counts.get(v["cat"], 0) + 1
        self._update_summary()

    def _update_summary(self):
        need = (self._counts.get("NEEDS_FIX", 0)
                + self._counts.get("DANGEROUS", 0)
                + self._counts.get("MANUAL", 0))
        ok_n = self._counts.get("OK", 0)
        other = self._counts.get("NOT_SKSE", 0)
        pending = sum(isinstance(c, PendingCard) for c in self.cards)
        total = len(self.cards)
        self.c_need.config(
            text=f"{need} of {total} need attention" if need else "")
        self.c_ok.config(
            text=f"{ok_n} OK" if ok_n else "")
        parts = []
        if other:
            parts.append(f"{other} not SKSE")
        if pending:
            parts.append(f"{pending} not checked yet")
        self.c_other.config(text="  \u2022  ".join(parts))

    def _on_pro_toggle(self):
        # Rebuild cards so every scanned one shows fix buttons when
        # pro mode is on. Unchecked cards stay unchecked.
        scanned = list(getattr(self, "_scan_data", []))
        pending = [c.dll_path for c in self.cards
                   if isinstance(c, PendingCard)]
        for c in self.cards:
            c.destroy()
        self.cards.clear()
        for dll in pending:
            card = PendingCard(self.sf.inner, dll, on_scan=self._scan_single)
            self._place_card(card)
            self.cards.append(card)
        for dll, info, v in scanned:
            card = PluginCard(self.sf.inner, dll, info, v,
                              on_fix_one=self._fix_single,
                              on_restore_one=self._restore_single,
                              force_fix=self.pro_mode.get())
            self._place_card(card)
            self.cards.append(card)
        if self.work.busy:
            for c in self.cards:
                c.set_working(True)
        self._update_summary()

    def _clear_cards(self):
        for c in self.cards:
            c.destroy()
        self.cards.clear()
        self.notice_frame.pack_forget()
        self.lib_frame.pack_forget()

    # --------------------------------------------------------------
    # Restore originals (undo fixes)
    # --------------------------------------------------------------

    def restore(self):
        plugins = self._plugins()
        if plugins is None:
            messagebox.showerror(
                "Error", "Place this tool in the same folder as SkyrimSE.exe.")
            return
        pairs = core.list_backups(plugins)
        if not pairs:
            messagebox.showinfo(
                "Nothing to undo", "No saved originals found.")
            return
        if not messagebox.askyesno(
            "Undo fixes",
            f"Restore {len(pairs)} original file(s)?\n\n"
            "This undoes all fixes.",
        ):
            return
        if not self.work.acquire(f"Restoring {len(pairs)} file(s)..."):
            messagebox.showinfo("Please wait", "Still working - try again.")
            return
        _launch(self.root, self.work, lambda: self._restore_worker(plugins))

    def _restore_worker(self, plugins):
        try:
            done = core.restore_backups(plugins)
        except Exception as exc:
            self.root.after(
                0, lambda: messagebox.showerror("Error", str(exc)))
            return
        self.root.after(0, lambda: self._finish_restore(done))

    def _finish_restore(self, done):
        self.list_dlls()
        messagebox.showinfo(
            "Done", f"Restored {done} file(s). Scan again to check them.")
        self.c_need.config(text="")
        self.c_ok.config(text="")
        self.c_other.config(text="")

    def _restore_single(self, card):
        if not self.work.acquire(f"Restoring {card.dll_path.name}..."):
            messagebox.showinfo("Please wait", "Still working - try again.")
            return
        _launch(self.root, self.work,
                lambda: self._restore_single_worker(card))

    def _restore_single_worker(self, card):
        try:
            ok = core.restore_one(card.dll_path)
        except Exception as exc:
            self.root.after(
                0, lambda: messagebox.showerror("Error", str(exc)))
            return
        dll = card.dll_path
        self.root.after(0, lambda: self._finish_single_restore(card, dll, ok))

    def _finish_single_restore(self, card, dll, ok):
        if not ok:
            messagebox.showinfo(
                "Nothing to undo", f"No saved original for {dll.name}.")
            return
        try:
            idx = self.cards.index(card)
        except ValueError:
            return
        card.destroy()
        new = PendingCard(self.sf.inner, dll, on_scan=self._scan_single)
        ncol = 2
        new.grid(row=idx // ncol, column=idx % ncol, sticky="nsew",
                 padx=4, pady=4)
        self.cards[idx] = new
        self._scan_data = [(d, i, v) for d, i, v in self._scan_data if d != dll]
        self._update_summary()

    # --------------------------------------------------------------
    # Fix Single
    # --------------------------------------------------------------

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
        if not self.work.acquire(f"Fixing {card.dll_path.name}..."):
            card.mark_noop("Please wait - still working...")
            return
        _launch(self.root, self.work,
                lambda: self._fix_single_worker(card, kind))

    def _fix_single_worker(self, card, kind):
        self._apply_fix(card, kind)

    # --------------------------------------------------------------
    # Fix engine helpers
    # --------------------------------------------------------------

    def _apply_fix(self, card, kind="all"):
        """Run the requested fix kind for one card; post result to UI thread.

        This tab covers flags and versions only. Hook offsets live in the
        Healer tab, which owns the old-exe ground truth they need.
        """
        try:
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

    def clear(self):
        self._clear_cards()

# ===================================================================
# Entry point
# ===================================================================

def main():
    root = tk.Tk()
    app = AutoPorterGUI(root)
    if app.game_exe and app._plugins() and app._plugins().exists():
        app.list_dlls()
        app._check_table_stamp(app._plugins())
        app._check_addresslib(app._plugins())
    root.mainloop()


if __name__ == "__main__":
    main()
