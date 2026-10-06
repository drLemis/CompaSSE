#!/usr/bin/env python3
"""CompaSSE GUI. Per-mod cards for scan and fix."""
import sys
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
import core
import therapist
import mod_sources as modsrc
import surgeon.tab as surgeon_tab
import healer
import healer.tab as healer_tab
import porter.tab as porter_tab
from gui_kit import (BG, BusyState, CARD_BG, FONT_FAMILY,
                     FONT_MONO, NAME_FONT_SPEC,
                     ScrollFrame, TEXT_PRIMARY, TEXT_SECONDARY,
                     _ellipsize, _HoverTip, _launch, _name_label)

# ---------------------------------------------------------------------------
# Core API shims: prefer the public names, fall back to the private ones
# while the parallel core lane lands. Each helper below keeps working
# whichever side of the rename this checkout is on.
# ---------------------------------------------------------------------------
try:
    from core import unpack_version as _unpack_version
except ImportError:  # pragma: no cover - old core without the public name
    _unpack_version = None

try:
    from core import v5_enforced as _v5_enforced_pub
except ImportError:  # pragma: no cover - old core without the public name
    _v5_enforced_pub = None

try:
    from core import built_before_1_7_99 as _built_before_pub
except ImportError:  # pragma: no cover - old core without the public name
    _built_before_pub = None

def _ver_str(packed):
    """'M.m.b.r' string for a packed version, via public unpack_version."""
    if _unpack_version is not None:
        tup = _unpack_version(packed)
        if tup is None:
            return None
        return f"{tup[0]}.{tup[1]}.{tup[2]}.{packed & 0xF}"
    return core._packed_to_ver(packed)

def _v5_here(running):
    """Whether the running game enforces the V5 flag scheme."""
    if _v5_enforced_pub is not None:
        return _v5_enforced_pub(running)
    return core._v5_enforced(running)

def _built_before_patch(dll_path):
    """Whether a DLL predates the 1.7.99 game update."""
    if _built_before_pub is not None:
        return _built_before_pub(dll_path)
    return core._built_before_1_7_99(dll_path)

def _set_btn_state(buttons, working):
    """Shared _set_working body: flip a button row disabled/normal."""
    state = "disabled" if working else "normal"
    for btn in buttons:
        try:
            btn.config(state=state)
        except Exception:
            pass

def find_game_exe():
    """SkyrimSE.exe next to this tool, else the remembered location."""
    cand = HERE / "SkyrimSE.exe"
    if cand.exists():
        return cand
    return core.saved_game_exe(HERE)

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

def find_recipe_hits(dlls, game_ver, recipes):
    """[(dll, recipe, pending)] for mods with applicable recipe steps.

    Pure header reads, no disassembly: safe to run at startup.
    """
    hits = []
    for dll in dlls or []:
        try:
            rec = healer.match_recipe(str(dll), game_ver, recipes)
            if rec is None:
                continue
            pend = sum(1 for _, s in healer.recipe_status(str(dll), rec)
                       if s == "pending")
            if pend:
                hits.append((dll, rec, pend))
        except Exception:
            continue
    return hits

# ===================================================================
# Classification helper
# ===================================================================

def _get_build_info(dll_path):
    """(build_year, date_str) from one PE stamp read; (None, None) if unreadable."""
    dt = core.pe_build_dt(dll_path)
    if dt is None:
        return (None, None)
    return (dt.year, dt.strftime("%Y %B %d").replace(" 0", " "))

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
    version = _ver_str(rv) if rv else None
    compat = (vi or {}).get("compat") or []
    _match = core.compat_match(compat, runtime_version)
    declares_running = _match == "exact"
    rev_match = _match == "rev"
    run_str = _ver_str(runtime_version) if runtime_version else None
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
                     "No SKSEPlugin_Version export found. This is probably not an SKSE plugin.")

    old = build_year is not None and build_year < 2025
    recent = build_year is not None and build_year >= 2025
    # versionIndependence flag bits, matching SKSE's own check. Sigs count:
    # CommonLib treats addr OR sigs as version-independent.
    addrlib = bool(vi and (vi.get("has_addr", False)
                           or vi.get("has_sigs", False)))
    # Ex=0 is inert where V5 is unenforced (pre-1.7): don't flag or fix it.
    v5_here = _v5_here(run_tup)
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
                xref = therapist.count_xref_ids(dll_path, id_set)
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

    has_addr_only = bool(vi and vi.get("has_addr", False))
    if (1, 7, 99) in crossed and has_addr_only and not any_patch:
        return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                     "Made for an older game. It loads but may still crash. "
                     "Turn it off to play, then ask the author for an update.",
                     "Turn it off to play; ask the author for an update.",
                     False, False, [])
    if (run_tup is not None and tuple(run_tup[:3]) >= (1, 7, 99)
            and declared_tup is None and has_addr_only and not any_patch
            and dll_path is not None
            and _built_before_patch(dll_path)):
        return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                     "Made before the latest game update. It loads but may "
                     "still crash. Turn it off to play, then ask the author "
                     "for an update.",
                     "Turn it off to play; ask the author for an update.",
                     False, False, [])
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

# Max cards on one page. Embedded widgets past 32767px stop rendering.
# https://www.tcl-lang.org/man/tcl8.6/TkLib/CanvTkwin.htm
# Who the hell uses SHORT for the canvas size?!
PAGE_SIZE = 50

class PagerBar(tk.Frame):
    """Prev/Next controls for long card lists. Hidden while 1 page."""

    def __init__(self, parent, on_prev, on_next, **kw):
        bg = kw.pop("bg", BG)
        super().__init__(parent, bg=bg, **kw)
        self.prev_btn = ttk.Button(self, text="< Prev", command=on_prev)
        self.prev_btn.pack(side="left")
        self.info_lbl = tk.Label(self, text="", font=(FONT_FAMILY, 9),
                                 fg=TEXT_SECONDARY, bg=bg)
        self.info_lbl.pack(side="left", expand=True)
        self.next_btn = ttk.Button(self, text="Next >", command=on_next)
        self.next_btn.pack(side="right")

    def set(self, page, pages, total):
        if pages <= 1:
            self.pack_forget()
            return
        self.pack(fill="x", padx=10, pady=(0, 4))
        self.info_lbl.config(
            text=f"Page {page + 1} of {pages} - {total} items")
        self.prev_btn.config(state="disabled" if page <= 0 else "normal")
        self.next_btn.config(
            state="disabled" if page + 1 >= pages else "normal")

# ===================================================================
# Plugin card
# ===================================================================

class PendingCard(tk.Frame):
    """A listed-but-unchecked DLL. Scan button, plus fix when known."""

    def __init__(self, parent, dll_path, on_scan, on_recipe=None,
                 recipe=None, **kw):
        super().__init__(parent, bg=CARD_BG, relief="solid", bd=1, **kw)
        self.dll_path = dll_path
        self.on_scan = on_scan
        self.on_recipe = on_recipe
        self.recipe = recipe

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

        self.fix_btn = None
        if recipe is not None and on_recipe is not None:
            self.fix_btn = tk.Button(
                body, text="fix",
                font=(FONT_FAMILY, 9, "bold"),
                relief="raised", bd=1, padx=12, pady=2,
                bg="#bbf7d0", fg="#14532d",
                activebackground="#86efac", activeforeground="#052e16",
                cursor="hand2", command=self._on_fix_click)
            self.fix_btn.pack(side="right", padx=(0, 6))

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

    def _on_fix_click(self):
        if self.on_recipe is None:
            return
        try:
            if self.fix_btn is not None:
                self.fix_btn.config(state="disabled")
        except Exception:
            pass
        self.on_recipe(self)

    def _on_scan_click(self):
        self.on_scan(self)

    def set_working(self, working):
        try:
            self.scan_btn.config(state="disabled" if working else "normal")
        except Exception:
            pass
        try:
            if self.fix_btn is not None:
                self.fix_btn.config(state="disabled" if working else "normal")
        except Exception:
            pass

class PluginCard(tk.Frame):
    """A card representing one scanned plugin with status + controls."""

    def __init__(self, parent, dll_path, info, verdict, on_fix_one,
                 on_restore_one=None, force_fix=False, on_healer=None,
                 recipe=None, recipe_pending=0, on_recipe=None,
                 skip_state=None, on_skip_toggle=None, **kw):
        super().__init__(parent, bg=CARD_BG, relief="solid", bd=1, **kw)
        self.dll_path = dll_path
        self.info = info
        self.verdict = verdict
        self.on_fix_one = on_fix_one
        self.on_restore_one = on_restore_one
        self.on_healer = on_healer
        self.on_skip_toggle = on_skip_toggle
        self.force_fix = force_fix
        self.recipe = recipe
        self.on_recipe = on_recipe
        self.fixed = False
        self.fix_buttons = []
        self.kind_buttons = {}
        self._done_kinds = set()
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
                        command=lambda: None,
                    )
                    b.config(command=lambda k=it["kind"], btn=b:
                             self._on_fix_kind(k, btn))
                    b.pack(fill="x", pady=2)
                    self.fix_buttons.append(b)
                    self.kind_buttons[it["kind"]] = b

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

        # -- Known fix (no scan needed; recipe carries its own checks) --
        self.recipe_btn = None
        if recipe is not None and (recipe_pending or 0) > 0 \
                and on_recipe is not None:
            rw = tk.Frame(body, bg=CARD_BG)
            rw.pack(fill="x", pady=(6, 0))
            tk.Label(rw, text="Known fix for your game - one press.",
                     font=(FONT_FAMILY, 9),
                     fg="#14532d", bg=CARD_BG,
                     anchor="w").pack(fill="x", pady=(0, 2))
            self.recipe_btn = tk.Button(
                rw, text="Apply known fix",
                font=(FONT_FAMILY, 9, "bold"),
                relief="raised", bd=1, padx=12, pady=4,
                bg="#bbf7d0", fg="#14532d",
                activebackground="#86efac", activeforeground="#052e16",
                cursor="hand2",
                command=self._on_recipe_click,
            )
            self.recipe_btn.pack(fill="x", pady=2)
            self.fix_buttons.append(self.recipe_btn)

        # -- Deep check (sends the mod to the Healer tab) --
        if self.on_healer is not None:
            self.healer_btn = tk.Button(
                body, text="Check in Healer",
                font=(FONT_FAMILY, 9),
                relief="raised", bd=1, padx=12, pady=2,
                bg="#e0e7ff", fg="#3730a3",
                activebackground="#c7d2fe", activeforeground="#1e1b4b",
                cursor="hand2", command=self._on_healer_click)
            self.healer_btn.pack(fill="x", pady=(4, 0))
        else:
            self.healer_btn = None

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

        # -- Skip auto-load (only for plugins SKSE itself skips: no
        # version data, so CompaSSE would try them at startup instead.
        # Checked = leave it alone, exactly like no CompaSSE at all.)
        self.skip_var = None
        self.skip_box = None
        if skip_state is not None and self.on_skip_toggle is not None:
            self.skip_var = tk.BooleanVar(value=bool(skip_state))
            self.skip_box = tk.Checkbutton(
                body, text="Don't auto-load this plugin",
                variable=self.skip_var,
                font=(FONT_FAMILY, 9),
                fg=TEXT_SECONDARY, bg=CARD_BG, activebackground=CARD_BG,
                anchor="w", command=self._on_skip_toggle)
            self.skip_box.pack(fill="x", pady=(4, 0))

    # -- Card actions ----------------------------------------------

    def _on_skip_toggle(self):
        if self.on_skip_toggle is not None and self.skip_var is not None:
            self.on_skip_toggle(self, bool(self.skip_var.get()))

    # -- Card actions ----------------------------------------------

    def _on_healer_click(self):
        if self.on_healer is not None:
            self.on_healer(self)

    def _on_undo_click(self):
        if self.undo_btn is not None:
            try:
                self.undo_btn.config(state="disabled")
            except Exception:
                pass
        if self.on_restore_one is not None:
            self.on_restore_one(self)

    def _on_fix_kind(self, kind, btn=None):
        try:
            if btn is not None:
                btn.config(state="disabled")
        except Exception:
            pass
        self.status_lbl.config(text=f"Fixing {kind}\u2026")
        self.on_fix_one(self, kind=kind)

    def _on_recipe_click(self):
        if self.on_recipe is None:
            return
        self._disable_all_fix()
        self.on_recipe(self)

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
        if self.skip_box is not None:
            try:
                self.skip_box.config(state="disabled" if working else "normal")
            except Exception:
                pass
        if not self.fix_buttons:
            return
        if working:
            self._disable_all_fix()
        else:
            self.mark_idle()

    def mark_one_done(self, kind, message):
        """One fix landed; siblings stay usable, no rescan needed."""
        try:
            self._done_kinds.add(kind)
        except Exception:
            pass
        try:
            btn = self.kind_buttons.get(kind)
            if btn is not None:
                btn.config(state="disabled")
        except Exception:
            pass
        self.status_lbl.config(text=f"Fixed \u2713 {message}", fg="#16a34a")

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
            try:
                for kind in self._done_kinds:
                    btn = self.kind_buttons.get(kind)
                    if btn is not None:
                        btn.config(state="disabled")
            except Exception:
                pass
            self.status_lbl.config(text="")

def _window_icon():
    base = getattr(sys, "_MEIPASS", None) or str(Path(__file__).parent)
    ico = Path(base) / "compasse.ico"
    return str(ico) if ico.exists() else ""

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
            if not therapist.pattern_matches_at(
                    exe_data, exe_sections, base,
                    hook.get("offset"), hook.get("pattern")):
                stale += 1
        except Exception:
            continue
    return stale

class SettingsTab:
    """Rightmost tab: where the game and the mod manager live."""

    def __init__(self, parent, work=None, game_exe_fn=None, mo_ini_fn=None,
                 on_pick_game=None, on_pick_mods=None, on_clear_mods=None):
        self.parent = parent
        self.work = work or BusyState()
        self._game_exe_fn = game_exe_fn
        self._mo_ini_fn = mo_ini_fn
        self._on_pick_game = on_pick_game
        self._on_pick_mods = on_pick_mods
        self._on_clear_mods = on_clear_mods
        self._build()
        self.work.listen(self._set_working)
        self.refresh()

    def _set_working(self, working, desc=""):
        _set_btn_state(
            (self.game_btn, self.mo_btn, self.mo_clear_btn), working)

    def _build(self):
        box = tk.Frame(self.parent, bg=BG)
        box.pack(fill="x", padx=10, pady=(10, 0))

        tk.Label(box, text="Game:",
                 font=(FONT_FAMILY, 10, "bold"),
                 fg=TEXT_PRIMARY, bg=BG, anchor="w").pack(fill="x")
        grow = tk.Frame(box, bg=BG)
        grow.pack(fill="x", pady=(0, 2))
        self.game_var = tk.StringVar()
        ttk.Entry(grow, textvariable=self.game_var, state="readonly",
                  width=60).pack(side="left", fill="x", expand=True)
        self.game_btn = ttk.Button(grow, text="Browse...",
                                   command=self._pick_game)
        self.game_btn.pack(side="left", padx=(6, 0))

        tk.Label(box, text="Mod Organizer:",
                 font=(FONT_FAMILY, 10, "bold"),
                 fg=TEXT_PRIMARY, bg=BG, anchor="w").pack(fill="x", pady=(8, 0))
        tk.Label(box, text="Where your MO2 mods live. Skip this if you "
                           "install mods by hand.",
                 font=(FONT_FAMILY, 9),
                 fg=TEXT_SECONDARY, bg=BG, anchor="w").pack(fill="x")
        mrow = tk.Frame(box, bg=BG)
        mrow.pack(fill="x", pady=(0, 2))
        self.mo_var = tk.StringVar()
        ttk.Entry(mrow, textvariable=self.mo_var, state="readonly",
                  width=60).pack(side="left", fill="x", expand=True)
        self.mo_btn = ttk.Button(mrow, text="Browse...",
                                 command=self._pick_mods)
        self.mo_btn.pack(side="left", padx=(6, 0))
        self.mo_clear_btn = ttk.Button(mrow, text="Clear",
                                       command=self._clear_mods)
        self.mo_clear_btn.pack(side="left", padx=(6, 0))

    def _pick_game(self):
        if self._on_pick_game:
            self._on_pick_game()

    def _pick_mods(self):
        if self._on_pick_mods:
            self._on_pick_mods()

    def _clear_mods(self):
        if self._on_clear_mods:
            self._on_clear_mods()

    def refresh(self):
        game = self._game_exe_fn() if self._game_exe_fn else None
        self.game_var.set(str(game) if game else "Not set")
        mo = self._mo_ini_fn() if self._mo_ini_fn else None
        self.mo_var.set(str(mo) if mo else "Not set")

    @property
    def root(self):
        return self.parent.winfo_toplevel()

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
        self.page = 0

        self._build()
        self.work.listen(self._set_working)

    def _set_working(self, working, desc=""):
        _set_btn_state(
            (self.scan_btn, self.clear_btn, self.restore_btn,
             self.pro_btn, self.rebuild_btn), working)
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

        try:
            from tools import TOOLS, ToolContext
        except Exception:
            try:
                from core.tools import (TOOLS, ToolContext,
                                        register_tool)
                from therapist.tab import TherapistTab
            except Exception:
                self._build_legacy_tabs()
                return
            register_tool("therapist", "  Therapist  ",
                          lambda parent, ctx: TherapistTab(parent, ctx=ctx))
            register_tool("healer", "  Healer  ",
                          lambda parent, ctx: healer_tab.HealerTab(parent, ctx=ctx))
            register_tool("surgeon", "  Surgeon  ",
                          lambda parent, ctx: surgeon_tab.SurgeonTab(parent, ctx=ctx))
            register_tool("porter", "  Porter  ",
                          lambda parent, ctx: porter_tab.PorterTab(parent, ctx=ctx))

        ctx = ToolContext(
            game_exe=self.game_exe,
            plugins_dir_fn=self._plugins,
            work=self.work,
            extra_sources_fn=self.get_plugin_sources,
            game_dir_fn=self._game_dir)
        self._tool_ctx = ctx

        # -- Build every registered tool tab; Settings stays last --
        self._tool_frames = {}
        self._tool_tabs = {}
        for spec in list(TOOLS):
            frame = tk.Frame(self.notebook, bg=BG)
            self.notebook.add(frame, text=spec.title)
            self._tool_frames[spec.name] = frame
            self._tool_tabs[spec.name] = spec.factory(frame, ctx)

        self.tab_main = self._tool_frames["therapist"]
        self.tab_healer = self._tool_frames["healer"]
        self.tab_surgeon = self._tool_frames["surgeon"]
        self.tab_porter = self._tool_frames["porter"]
        self.therapist_tab = self._tool_tabs["therapist"]
        self.healer_tab = self._tool_tabs["healer"]
        self.surgeon_tab = self._tool_tabs["surgeon"]
        self.porter_tab = self._tool_tabs["porter"]

        self.tab_settings = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_settings, text="  Settings  ")

        # -- Build main tab (existing UI, reparented to tab_main) --
        self._build_main_tab()

        # -- Build settings tab --
        self.settings_tab = SettingsTab(
            self.tab_settings,
            work=self.work,
            game_exe_fn=lambda: self.game_exe,
            mo_ini_fn=lambda: core.saved_mo2_ini(HERE, self._game_dir()),
            on_pick_game=self.locate_game_exe,
            on_pick_mods=self.locate_mod_manager,
            on_clear_mods=self.clear_mod_manager)

    def _build_legacy_tabs(self):
        # Fallback when core.tools is unavailable: the previous explicit
        # wiring, kept so old checkouts still launch.
        # Tab 1: Therapist (flags and versions)
        self.tab_main = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_main, text="  Therapist  ")

        # Tab 2: Healer (one-mod check-up and fix)
        self.tab_healer = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_healer, text="  Healer  ")

        # Tab 3: Surgeon (co-save blocks)
        self.tab_surgeon = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_surgeon, text="  Surgeon  ")

        # Tab 4: Porter (hardcoded game addresses, scan + fix)
        self.tab_porter = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_porter, text="  Porter  ")

        # Settings stays last: every future tab is added before it.
        self.tab_settings = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_settings, text="  Settings  ")

        # -- Build main tab (existing UI, reparented to tab_main) --
        self._build_main_tab()

        # -- Build surgeon tab --
        self.surgeon_tab = surgeon_tab.SurgeonTab(
            self.tab_surgeon,
            plugins_dir_fn=self._plugins,
            work=self.work,
            extra_dlls_fn=lambda: self.get_plugin_sources()[0])

        # -- Build Healer tab --
        self.healer_tab = healer_tab.HealerTab(
            self.tab_healer,
            game_exe=self.game_exe,
            plugins_dir_fn=self._plugins,
            work=self.work,
            extra_dirs_fn=lambda: self.get_plugin_sources()[1])

        # -- Build Porter tab --
        self.porter_tab = porter_tab.PorterTab(
            self.tab_porter,
            game_exe=self.game_exe,
            plugins_dir_fn=self._plugins,
            work=self.work)

        # -- Build settings tab --
        self.settings_tab = SettingsTab(
            self.tab_settings,
            work=self.work,
            game_exe_fn=lambda: self.game_exe,
            mo_ini_fn=lambda: core.saved_mo2_ini(HERE, self._game_dir()),
            on_pick_game=self.locate_game_exe,
            on_pick_mods=self.locate_mod_manager,
            on_clear_mods=self.clear_mod_manager)

    def _build_main_tab(self):
        parent = self.tab_main

        # -- Auto-detected location hint --
        pf = tk.Frame(parent, bg=BG)
        pf.pack(fill="x", padx=10, pady=(10, 4))
        if self.game_exe:
            self.game_lbl = tk.Label(
                pf, text=game_version_line(self.game_exe),
                font=(FONT_FAMILY, 10, "bold"),
                fg=TEXT_PRIMARY, bg=BG, anchor="w")
            self.game_lbl.pack(fill="x")
            self.plugins_hint = tk.Label(
                pf, text=f"Plugins: {plugins_dir_for(self.game_exe)}",
                font=(FONT_FAMILY, 9), fg=TEXT_SECONDARY, bg=BG, anchor="w")
            self.plugins_hint.pack(fill="x", pady=(0, 2))
        else:
            self.game_lbl = tk.Label(
                pf, text="No game found. Open the Settings tab.",
                font=(FONT_FAMILY, 10),
                fg="#dc2626", bg=BG, anchor="w")
            self.game_lbl.pack(fill="x")
            self.plugins_hint = tk.Label(
                pf, text="", font=(FONT_FAMILY, 9),
                fg=TEXT_SECONDARY, bg=BG, anchor="w")
            self.plugins_hint.pack(fill="x", pady=(0, 2))

        # -- Buttons --
        bf = tk.Frame(parent, bg=BG)
        bf.pack(fill="x", padx=10, pady=(4, 4))

        self.scan_btn = ttk.Button(bf, text="Scan all", command=self.scan)
        self.scan_btn.pack(side="left", padx=(0, 6))

        self.clear_btn = ttk.Button(bf, text="Refresh", command=self.refresh)
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

        # -- Pager (hidden while 1 page) --
        self.pager = PagerBar(parent, self._page_prev, self._page_next)

    # --------------------------------------------------------------
    # Browse handlers
    # --------------------------------------------------------------

    def _plugins(self):
        """Return the plugins dir derived from the game exe next to the tool."""
        if not self.game_exe:
            return None
        return plugins_dir_for(self.game_exe)

    def _game_dir(self):
        if self.game_exe is None:
            return None
        try:
            return Path(self.game_exe).resolve().parent
        except OSError:
            return None

    def _open_settings(self):
        try:
            self.notebook.select(self.tab_settings)
        except Exception:
            pass

    def get_plugin_sources(self):
        """All DLLs to scan: game folder plus any VFS manager mods."""
        real = self._plugins()
        real_dlls = []
        if real is not None:
            try:
                if real.exists():
                    real_dlls = sorted(real.glob("*.dll"))
            except OSError:
                real_dlls = []
        game_dir = self._game_dir()
        mo_dlls, mo_bins, mo_label = modsrc.collect_for_game(
            game_dir, ini_path=core.saved_mo2_ini(HERE, game_dir)) \
            if game_dir is not None else ([], [], "")
        dlls = list(real_dlls)
        seen = set()
        for d in dlls:
            try:
                seen.add(str(d.resolve()).lower())
            except OSError:
                seen.add(str(d).lower())
        for d in mo_dlls:
            try:
                key = str(d.resolve()).lower()
            except OSError:
                key = str(d).lower()
            if key not in seen:
                seen.add(key)
                dlls.append(d)
        lib_dirs = []
        if real is not None:
            try:
                if real.exists():
                    lib_dirs.append(real)
            except OSError:
                pass
        for b in mo_bins:
            parent = b.parent
            if parent not in lib_dirs:
                try:
                    if parent.exists():
                        lib_dirs.append(parent)
                except OSError:
                    pass
        for d in mo_dlls:
            parent = d.parent
            if parent not in lib_dirs:
                try:
                    if parent.exists():
                        lib_dirs.append(parent)
                except OSError:
                    pass
        label = mo_label if mo_dlls else ""
        return sorted(dlls), lib_dirs, label

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
            if messagebox.askyesno(
                    "No game found",
                    "CompaSSE does not know where your game is.\n\n"
                    "Open Settings to point it at SkyrimSE.exe?"):
                self._open_settings()
            return
        dlls, lib_dirs, label = self.get_plugin_sources()
        if not dlls:
            if messagebox.askyesno(
                    "No mods found",
                    f"Could not find any mods.\n\nLooked in:\n{plugins}"
                    "\nAnd your mod manager (nothing enabled found)."
                    "\n\nIf your mods live in Mod Organizer, open "
                    "Settings to point CompaSSE at it?"):
                self._open_settings()
            return
        self._clear_cards()
        if label:
            try:
                self.plugins_hint.config(
                    text=f"Plugins: {plugins}  ({label})")
            except Exception:
                pass
        self._check_table_stamp(plugins)
        self._check_addresslib(lib_dirs)
        self._ctx = None
        self._counts = {}
        self._scan_data = []
        self.page = 0
        fast = self._recipe_fast_ok()
        self._run(lambda: self._do_scan(dlls, lib_dirs, fast),
                  "Starting scan...")

    def locate_game_exe(self):
        """Point CompaSSE at SkyrimSE.exe once; it is remembered."""
        path = filedialog.askopenfilename(
            title="Select SkyrimSE.exe",
            filetypes=[("SkyrimSE.exe", "SkyrimSE.exe"),
                       ("Executables", "*.exe"),
                       ("All files", "*.*")],
        )
        if not path:
            return
        if not Path(path).is_file():
            messagebox.showerror("Error", "That file could not be read.")
            return
        if not core.save_game_exe(HERE, path):
            messagebox.showerror("Error", "Could not remember that location.")
            return
        self.game_exe = Path(path)
        try:
            self.healer_tab.game_exe = self.game_exe
        except Exception:
            pass
        try:
            self.porter_tab.game_exe = self.game_exe
        except Exception:
            pass
        self._refresh_header()
        self.list_dlls()

    def clear_mod_manager(self):
        """Forget the Mod Organizer location; refresh the quick list."""
        core.clear_mo2_ini(HERE)
        self._refresh_header()
        self.list_dlls()

    def _refresh_header(self):
        if self.game_exe:
            self.game_lbl.config(text=game_version_line(self.game_exe),
                                 fg=TEXT_PRIMARY)
            self.plugins_hint.config(
                text=f"Plugins: {plugins_dir_for(self.game_exe)}")
        else:
            self.game_lbl.config(text="No game found. Open the Settings tab.",
                                 fg="#dc2626")
            self.plugins_hint.config(text="")
        try:
            self.settings_tab.refresh()
        except Exception:
            pass

    def locate_mod_manager(self):
        """Point CompaSSE at ModOrganizer.ini once; it is remembered."""
        if not self.game_exe or self._game_dir() is None:
            messagebox.showerror(
                "Error", "Set the game first, then point at Mod Organizer.")
            return
        path = filedialog.askopenfilename(
            title="Select ModOrganizer.ini",
            filetypes=[("ModOrganizer.ini", "ModOrganizer.ini"),
                       ("All files", "*.*")],
        )
        if not path:
            return
        if modsrc.parse_instance(path) is None:
            messagebox.showerror(
                "Error", "That file is not a Mod Organizer setup.")
            return
        if not core.save_mo2_ini(HERE, path):
            messagebox.showerror("Error", "Could not remember that location.")
            return
        self._refresh_header()
        self.list_dlls()

    def _pending_card(self, dll, rec=None, pend=0):
        """Unchecked card, with a fix button when a recipe applies."""
        if rec is not None and pend:
            return PendingCard(self.sf.inner, dll,
                               on_scan=self._scan_single,
                               on_recipe=self._apply_recipe_single,
                               recipe=rec)
        return PendingCard(self.sf.inner, dll, on_scan=self._scan_single)

    def list_dlls(self):
        """Instant file listing: one unchecked card per DLL, no analysis."""
        plugins = self._plugins()
        if plugins is None:
            return False
        dlls, _lib_dirs, label = self.get_plugin_sources()
        if not dlls:
            return False
        self._clear_cards()
        if label:
            try:
                self.plugins_hint.config(
                    text=f"Plugins: {plugins}  ({label})")
            except Exception:
                pass
        self._ctx = None
        self._counts = {}
        self._scan_data = []
        game_ver, recipes = self._recipe_ctx()
        hits = {}
        if game_ver and recipes:
            for d, rec, pend in find_recipe_hits(dlls, game_ver, recipes):
                hits[str(d).lower()] = (rec, pend)
        for dll in dlls:
            try:
                rec, pend = hits.get(str(dll).lower(), (None, 0))
            except Exception:
                rec, pend = None, 0
            card = self._pending_card(dll, rec, pend)
            self.cards.append(card)
        self.page = 0
        self.render_page()
        return True

    def _page_count(self):
        return max(1, (len(self.cards) + PAGE_SIZE - 1) // PAGE_SIZE)

    def render_page(self):
        """Grid only the current page; the rest stay built but hidden."""
        pages = self._page_count()
        self.page = min(self.page, pages - 1)
        lo = self.page * PAGE_SIZE
        for i, card in enumerate(self.cards):
            if lo <= i < lo + PAGE_SIZE:
                self._place_card(card, i - lo)
            else:
                card.grid_forget()
        self.sf.canvas.yview_moveto(0)
        self._update_summary()

    def _page_prev(self):
        if self.page > 0:
            self.page -= 1
            self.render_page()

    def _page_next(self):
        if self.page + 1 < self._page_count():
            self.page += 1
            self.render_page()

    def _place_card(self, card, idx):
        ncol = 2
        row = idx // ncol
        col = idx % ncol
        card.grid(row=row, column=col, sticky="nsew", padx=4, pady=4)
        self.sf.inner.grid_columnconfigure(0, weight=1, uniform="card")
        self.sf.inner.grid_columnconfigure(1, weight=1, uniform="card")

    def _ensure_ctx(self, lib_dirs=None):
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
                    if lib_dirs is None:
                        plugins = self._plugins()
                        lib_dirs = [plugins] if plugins is not None else []
                    match = core.find_versionlib_in_dirs(lib_dirs, game_ver) \
                        if game_ver else None
                    if match is not None:
                        addr_lib = core.parse_library_any(str(match))
                except Exception:
                    exe_data = exe_secs = addr_lib = None
            self._ctx = (runtime_version, exe_data, exe_secs, addr_lib)
        return self._ctx

    def _recipe_ctx(self):
        """(game_ver, recipes) once per scan; per-mod match is header reads."""
        try:
            ver = healer.game_ver_str(str(self.game_exe)) \
                if self.game_exe else None
            plug = self._plugins()
            return ver, healer.load_recipes(healer.recipes_dirs(plug))
        except Exception:
            return None, []

    def _recipe_for(self, dll, game_ver, recipes):
        """(recipe, pending_count) for one mod, or (None, 0)."""
        if not game_ver or not recipes:
            return None, 0
        try:
            rec = healer.match_recipe(str(dll), game_ver, recipes)
            if rec is None:
                return None, 0
            pend = sum(1 for _, s in healer.recipe_status(str(dll), rec)
                       if s == "pending")
            return rec, pend
        except Exception:
            return None, 0

    def _recipe_fast_ok(self):
        """Recipe-first scanning: everything except pro mode.

        Call on the UI thread; the flag must not be read from workers.
        """
        try:
            return not bool(self.pro_mode.get())
        except Exception:
            return False

    def _quick_verdict(self, dll, runtime_version, addr_lib, rec, pend):
        """Light verdict for a recipe hit: no hook disassembly.

        Returns (info, v) with the recipe attached and the card marked
        as needing attention, or (None, None) when unreadable.
        """
        try:
            info = therapist.analyze_plugin(dll, runtime_version,
                                       include_hooks=False)
        except OSError:
            return None, None
        build_year, build_date = _get_build_info(dll)
        v = classify(info, build_year, runtime_version, dll,
                     set(addr_lib) if addr_lib else None)
        v["build_date"] = build_date
        v["recipe"] = rec
        v["recipe_pending"] = pend
        v["cat"] = "NEEDS_FIX"
        why = v.get("why", "")
        add = "Known fix available - no deep scan needed."
        v["why"] = (why + " " + add).strip() if why else add
        return info, v

    def _do_scan(self, dlls, lib_dirs=None, recipe_first=False):
        runtime_version, exe_data, exe_secs, addr_lib = self._ensure_ctx(lib_dirs)
        game_ver, recipes = self._recipe_ctx()

        total_mods = len(dlls)
        for i, dll in enumerate(dlls):
            self.root.after(
                0, lambda i=i, d=dll: self.work.set_desc(
                    f"Checking {d.name} ({i + 1}/{total_mods})"))
            rec, pend = self._recipe_for(dll, game_ver, recipes)
            if recipe_first and rec is not None and pend:
                info, v = self._quick_verdict(
                    dll, runtime_version, addr_lib, rec, pend)
                if info is None:
                    continue
            else:
                try:
                    info = therapist.analyze_plugin(dll, runtime_version,
                                               include_hooks=True)
                except OSError:
                    continue
                build_year, build_date = _get_build_info(dll)
                v = classify(info, build_year, runtime_version, dll,
                             set(addr_lib) if addr_lib else None)
                v["build_date"] = build_date
                if exe_data is not None and addr_lib is not None:
                    stale = count_stale_hooks(info.get("hooks"), exe_data,
                                              exe_secs, addr_lib)
                    if stale:
                        v["hook_note"] = (f"{stale} stale hook offset(s) - go to the "
                                          "Healer tab to fix (or CLI --fix with old game files).")
                v["recipe"] = rec
                v["recipe_pending"] = pend
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

    def _check_addresslib(self, lib_dirs, game_ver=None):
        """Warn when no Address Library file matches the game. Returns found."""
        self.lib_frame.pack_forget()
        if game_ver is None:
            if self.game_exe is None:
                return False
            packed = core.runtime_version_from_exe(self.game_exe)
            game_ver = core.unpack_version(packed) if packed else None
        if game_ver is None:
            return False
        if isinstance(lib_dirs, (str, Path)):
            lib_dirs = [lib_dirs]
        if core.find_versionlib_in_dirs(lib_dirs, game_ver) is not None:
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
            if messagebox.askyesno(
                    "No game found",
                    "CompaSSE does not know where your game is.\n\n"
                    "Open Settings to point it at SkyrimSE.exe?"):
                self._open_settings()
            return
        _dlls, lib_dirs, _label = self.get_plugin_sources()
        try:
            plugins.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        if not plugins.exists():
            messagebox.showerror(
                "Error", f"Could not use folder:\n{plugins}")
            return
        if not self.work.acquire("Updating helper data..."):
            return
        extra = [d for d in lib_dirs if d != plugins]
        _launch(self.root, self.work,
                lambda: self._rebuild_worker(plugins, extra))

    def _rebuild_worker(self, plugins, extra_dirs=None):
        try:
            ver = core.runtime_version_from_exe(self.game_exe)
            core.build_translations(str(self.game_exe), plugins,
                                    game_version=ver,
                                    extra_lib_dirs=extra_dirs)
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

    def _make_card(self, dll, info, v, rec=None, pend=0):
        """One per-mod card with every tab action wired."""
        return PluginCard(self.sf.inner, dll, info, v,
                          on_fix_one=self._fix_single,
                          on_restore_one=self._restore_single,
                          on_healer=self._send_to_healer,
                          force_fix=self.pro_mode.get(),
                          recipe=rec, recipe_pending=pend,
                          on_recipe=self._apply_recipe_single,
                          skip_state=self._skip_state_for(dll),
                          on_skip_toggle=self._toggle_skip)

    def _add_scanned_card(self, dll, info, v):
        card = self._make_card(dll, info, v,
                               rec=v.get("recipe"),
                               pend=v.get("recipe_pending", 0))
        self.cards.append(card)
        pos = len(self.cards) - 1
        lo = self.page * PAGE_SIZE
        if lo <= pos < lo + PAGE_SIZE:
            self._place_card(card, pos - lo)
        if self.work.busy:
            card.set_working(True)
        self._update_summary()

    def _scan_single(self, card):
        if not self.work.acquire(f"Checking {card.dll_path.name}..."):
            return
        fast = self._recipe_fast_ok()
        _launch(self.root, self.work,
                lambda: self._scan_single_worker(card, fast))

    def _scan_single_worker(self, card, recipe_first=False):
        _dlls, lib_dirs, _label = self.get_plugin_sources()
        runtime_version, exe_data, exe_secs, addr_lib = self._ensure_ctx(lib_dirs)
        game_ver, recipes = self._recipe_ctx()
        rec, pend = self._recipe_for(card.dll_path, game_ver, recipes)
        if recipe_first and rec is not None and pend:
            info, v = self._quick_verdict(
                card.dll_path, runtime_version, addr_lib, rec, pend)
            if info is None:
                return
            dll = card.dll_path
            self.root.after(0, lambda: self._finish_single(card, dll, info, v))
            return
        try:
            info = therapist.analyze_plugin(card.dll_path, runtime_version,
                                       include_hooks=True)
        except OSError:
            return
        build_year, build_date = _get_build_info(card.dll_path)
        v = classify(info, build_year, runtime_version, card.dll_path,
                     set(addr_lib) if addr_lib else None)
        v["build_date"] = build_date
        if exe_data is not None and addr_lib is not None:
            stale = count_stale_hooks(info.get("hooks"), exe_data,
                                      exe_secs, addr_lib)
            if stale:
                v["hook_note"] = (f"{stale} stale hook offset(s) - go to the "
                                  "Healer tab to fix.")
        dll, info = card.dll_path, info
        self.root.after(0, lambda: self._finish_single(card, dll, info, v))

    def _send_to_healer(self, card):
        """Reroute a mod to the Healer tab, prefilled, scan started."""
        try:
            self.notebook.select(self.tab_healer)
        except Exception:
            pass
        try:
            self.healer_tab.dll_var.set(str(card.dll_path))
        except Exception:
            return
        try:
            self.healer_tab.scan()
        except Exception:
            pass

    def _finish_single(self, card, dll, info, v):
        for i, (d, _, _) in enumerate(self._scan_data):
            if d == dll:
                self._scan_data[i] = (dll, info, v)
                break
        else:
            self._scan_data.append((dll, info, v))
        self._counts[v["cat"]] = self._counts.get(v["cat"], 0) + 1
        try:
            idx = self.cards.index(card)
        except ValueError:
            self._update_summary()
            return
        card.destroy()
        game_ver, recipes = self._recipe_ctx()
        rec, pend = self._recipe_for(dll, game_ver, recipes)
        v["recipe"] = rec
        v["recipe_pending"] = pend
        new = self._make_card(dll, info, v, rec=rec, pend=pend)
        ncol = 2
        pos = idx - self.page * PAGE_SIZE
        new.grid(row=pos // ncol, column=pos % ncol, sticky="nsew",
                 padx=4, pady=4)
        self.cards[idx] = new
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
        self.pager.set(self.page, self._page_count(), total)

    def _on_pro_toggle(self):
        # Rebuild cards so every scanned one shows fix buttons when
        # pro mode is on. Unchecked cards stay unchecked.
        scanned = list(getattr(self, "_scan_data", []))
        pending = [c.dll_path for c in self.cards
                   if isinstance(c, PendingCard)]
        for c in self.cards:
            c.destroy()
        self.cards.clear()
        game_ver, recipes = self._recipe_ctx()
        hits = {}
        if game_ver and recipes:
            for d, rec, pend in find_recipe_hits(pending, game_ver,
                                                 recipes):
                hits[str(d).lower()] = (rec, pend)
        for dll in pending:
            try:
                rec, pend = hits.get(str(dll).lower(), (None, 0))
            except Exception:
                rec, pend = None, 0
            card = self._pending_card(dll, rec, pend)
            self.cards.append(card)
        for dll, info, v in scanned:
            card = self._make_card(dll, info, v,
                                   rec=v.get("recipe"),
                                   pend=v.get("recipe_pending", 0))
            self.cards.append(card)
        if self.work.busy:
            for c in self.cards:
                c.set_working(True)
        self.render_page()

    def _clear_cards(self):
        for c in self.cards:
            c.destroy()
        self.cards.clear()
        self.pager.set(0, 1, 0)
        self.notice_frame.pack_forget()
        self.lib_frame.pack_forget()

    # --------------------------------------------------------------
    # Legacy skip-list (Therapist per-card checkbox)
    # --------------------------------------------------------------

    def _skip_state_for(self, dll):
        """True/False when the card gets a skip checkbox, else None.

        Only versionless plugins qualify: SKSE skips them, so CompaSSE
        would try them at startup instead. Needs the plugins folder.
        """
        try:
            plugins = self._plugins()
        except Exception:
            return None
        if plugins is None:
            return None
        try:
            if not core.is_versionless_plugin(dll):
                return None
        except Exception:
            return None
        try:
            year = core.pe_build_year(dll)
        except Exception:
            year = None
        try:
            return bool(core.is_legacy_skipped(plugins, dll.name, year))
        except Exception:
            return False

    def _toggle_skip(self, card, skipped):
        plugins = self._plugins()
        if plugins is None:
            messagebox.showinfo(
                "No game found", "CompaSSE does not know where your game is.")
            try:
                card.skip_var.set(not skipped)
            except Exception:
                pass
            return
        try:
            year = core.pe_build_year(card.dll_path)
        except Exception:
            year = None
        try:
            if skipped:
                core.add_legacy_skip(
                    plugins, card.dll_path.name, year,
                    "added from Therapist, no version data")
            else:
                core.remove_legacy_skip(plugins, card.dll_path.name, year)
        except Exception as exc:
            messagebox.showerror("Error", str(exc))
            try:
                card.skip_var.set(not skipped)
            except Exception:
                pass

    # --------------------------------------------------------------
    # Restore originals (undo fixes)
    # --------------------------------------------------------------

    def restore(self):
        plugins = self._plugins()
        if plugins is None:
            if messagebox.askyesno(
                    "No game found",
                    "CompaSSE does not know where your game is.\n\n"
                    "Open Settings to point it at SkyrimSE.exe?"):
                self._open_settings()
            return
        dlls, lib_dirs, _label = self.get_plugin_sources()
        plugin_dirs = ([plugins] if plugins is not None else []) + lib_dirs
        pairs = core.list_backups_all(plugin_dirs, dlls)
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
        _launch(self.root, self.work,
                lambda: self._restore_worker(plugin_dirs, dlls))

    def _restore_worker(self, plugin_dirs, dlls=None):
        try:
            done = core.restore_backups_all(plugin_dirs, dlls)
            try:
                for dll_path, _ in core.list_backups_all(plugin_dirs, dlls):
                    try:
                        core.remove_touched(Path(dll_path).parent, dll_path)
                    except Exception:
                        pass
            except Exception:
                pass
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
            if ok:
                try:
                    core.remove_touched(Path(card.dll_path).parent,
                                        card.dll_path)
                except Exception:
                    pass
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
        self._scan_data = [(d, i, v) for d, i, v in self._scan_data
                           if d != dll]
        try:
            idx = self.cards.index(card)
        except ValueError:
            self._update_summary()
            return
        card.destroy()
        game_ver, recipes = self._recipe_ctx()
        rec, pend = self._recipe_for(dll, game_ver, recipes)
        new = self._pending_card(dll, rec, pend)
        ncol = 2
        pos = idx - self.page * PAGE_SIZE
        new.grid(row=pos // ncol, column=pos % ncol, sticky="nsew",
                 padx=4, pady=4)
        self.cards[idx] = new
        self._scan_data = [(d, i, v) for d, i, v in self._scan_data
                           if d != dll]
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

    def _mark_card(self, card, ok, text):
        """Report a single-card fix; pending cards lack mark methods."""
        try:
            if ok:
                card.mark_fixed(ok, text)
            else:
                card.mark_noop(text)
        except Exception:
            pass

    def _fix_single_worker(self, card, kind):
        self._apply_fix(card, kind)

    def _apply_recipe_single(self, card):
        rec = getattr(card, "recipe", None)
        if rec is None:
            return
        if not self.work.acquire(
                f"Applying known fix to {card.dll_path.name}..."):
            self._mark_card(card, False, "Please wait - still working...")
            return

        def _do():
            try:
                try:
                    plug = self._plugins()
                except Exception:
                    plug = None
                game = str(self.game_exe) if self.game_exe else None
                msgs, _info = healer.apply_recipe(
                    card.dll_path, rec, plug, game, None, None)
            except Exception as exc:
                msg = str(exc)
                self.root.after(
                    0, lambda m=msg: self._mark_card(card, False, m))
                return
            ok = any("fixed" in m for m in msgs)
            text = "; ".join(msgs) if msgs else "nothing to do"
            self.root.after(0, lambda: self._mark_card(card, ok, text))
            self.root.after(0, lambda: self._scan_single(card))

        _launch(self.root, self.work, _do)

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
                    ok = therapist.patch_flag_force(card.dll_path)
                else:
                    ok = therapist.patch_flag(card.dll_path)
                if ok:
                    changed.append("flag -> 2" if force else "flag 0 -> 2")
            if kind in ("all", "addrlib"):
                if force:
                    ok = therapist.patch_version_independence_force(card.dll_path)
                else:
                    ok = therapist.patch_version_independence(card.dll_path)
                if ok:
                    changed.append("address lib flags")
            if changed:
                msg = "; ".join(changed)
                if kind == "all":
                    self.root.after(0, lambda: card.mark_fixed(True, msg))
                else:
                    self.root.after(
                        0, lambda: card.mark_one_done(kind, msg))
            else:
                # Nothing actually changed - report honestly, keep buttons usable.
                already = "already up to date"
                if force and kind in ("flag", "addrlib"):
                    already = "already set to target"
                self.root.after(0, lambda: card.mark_noop(already))
        except Exception as exc:
            self.root.after(0, lambda: card.mark_fixed(False, str(exc)))

    def refresh(self):
        """Re-list mods: the same fast surface scan as on opening."""
        if self._plugins() is None:
            if messagebox.askyesno(
                    "No game found",
                    "CompaSSE does not know where your game is.\n\n"
                    "Open Settings to point it at SkyrimSE.exe?"):
                self._open_settings()
            return
        if not self.list_dlls():
            messagebox.showinfo(
                "No mods found",
                "No mod DLLs found in the plugins folder.")

# ===================================================================
# Entry point
# ===================================================================

def main():
    root = tk.Tk()
    app = AutoPorterGUI(root)
    if app.game_exe and app._plugins():
        if app.list_dlls():
            _dlls, lib_dirs, _label = app.get_plugin_sources()
            app._check_table_stamp(app._plugins())
            app._check_addresslib(lib_dirs)
    root.mainloop()

if __name__ == "__main__":
    main()
