#!/usr/bin/env python3
"""CompaSSE UI: per-mod cards for scan/fix."""
import sys
import threading
import tkinter as tk
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


def classify(info, build_year, runtime_version=None):
    """Turn analyze_plugin output + build year into a verdict dict.

    runtime_version (packed, from the user's game exe) enables the
    built-for-you branches: a plugin declaring the running version is
    judged against its own era, not current flag fashion.
    """
    flag = info.get("flag")
    vi = info.get("version_indep")
    hooks = info.get("hooks", [])
    rv = (vi or {}).get("runtime_ver")
    version = core._packed_to_ver(rv) if rv else None
    compat = (vi or {}).get("compat") or []
    declares_running = (runtime_version is not None
                        and runtime_version in compat)
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
    # versionIndependence flag bit: authoritative, matches SKSE's own check.
    addrlib = bool(vi and vi.get("has_addr", False))
    flag_patch = flag is not None and flag.get("needs_patch", False)
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

        if old and addrlib:
            parts = [
                f"Built {build_year} (old CommonLibSSE). "
                "Uses Address Library but SKSE rejects it due to "
                "outdated version flags.",
            ]
            if crossed:
                parts.append(cross_note.strip())
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
            if crossed:
                why += cross_note
            return _base("NEEDS_FIX", "NEEDS FIX", "NEEDS_FIX",
                         why, "Patch the flags so SKSE accepts it.", True, True, items)

        if old and not addrlib:
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
                         "Needs manual port or recompile with CommonLibNG.",
                         False, True, items)

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
        return _base("OK", "OK", "OK",
                     f"Declares your game version ({run_str}). Built for it - leave it alone.")

    if has_unknown:
        return _base("MANUAL", "MANUAL CHECK", "MANUAL",
                     (f"Unknown versionIndependence flags "
                      f"(0x{vi['indep_val']:x}). Cannot verify safety."),
                     "Review manually.", False, False, [])

    return _base("OK", "OK", "OK",
                 "All flags and version info look correct. Should load, "
                 "but that doesn't guarantee it works in-game.")


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
        self.hooks_scanned = bool(info.get("hooks_scanned", False))
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

        # ── Controls (only when the plugin needs fixing, or forced in pro mode) ──
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
        tk.Label(body, text=dll_path.name,
                 font=(FONT_FAMILY, 11, "bold"),
                 fg=TEXT_PRIMARY, bg=CARD_BG).pack(anchor="w")

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
        if self.heal_btn:
            self.heal_btn.config(state="disabled")
        self.status_lbl.config(text="Patching...")
        patched = dict(self.finding)
        patched["new_offset"] = self.selected_offset
        self.on_heal(self, patched)

    def mark_fixed(self, success, message):
        self.fixed = True
        if self.heal_btn:
            self.heal_btn.config(state="disabled")
        self.status_lbl.config(
            text="Fixed \u2713" if success else ("Failed: " + message),
            fg="#16a34a" if success else "#dc2626",
        )


# ===================================================================
# Healer Tab
# ===================================================================

class HealerTab:
    """Tab for detecting and fixing stale pattern scan offsets in SKSE plugins."""

    def __init__(self, parent, game_exe, plugins_dir_fn):
        self.parent = parent
        self.game_exe = game_exe
        self._plugins_dir_fn = plugins_dir_fn
        self.cards = []
        self.busy = False
        self._exe_data = None
        self._exe_sections = None

        self._build()

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
        ttk.Button(ctrl, text="Browse...", command=self._browse_plugin
                   ).pack(side="left", padx=(0, 12))

        # Old game exe selector (optional)
        tk.Label(ctrl, text="Old game (optional):",
                 font=(FONT_FAMILY, 10), fg=TEXT_PRIMARY, bg=BG
                 ).pack(side="left")
        self.old_game_var = tk.StringVar()
        self.old_game_entry = ttk.Entry(ctrl, textvariable=self.old_game_var, width=40)
        self.old_game_entry.pack(side="left", padx=(6, 4))
        ttk.Button(ctrl, text="Browse...", command=self._browse_old_game
                   ).pack(side="left")

        # Buttons row
        btn_frame = tk.Frame(self.parent, bg=BG)
        btn_frame.pack(fill="x", padx=10, pady=(4, 4))

        self.scan_btn = ttk.Button(btn_frame, text="Scan", command=self.scan)
        self.scan_btn.pack(side="left", padx=(0, 6))

        ttk.Button(btn_frame, text="Clear", command=self._clear_cards).pack(side="left")

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

        # Status bar
        self.status = ttk.Label(self.parent, text="Ready", anchor="w")
        self.status.pack(fill="x", padx=10, pady=(0, 8))

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

        self._run(lambda: self._do_scan(plugin_path, plugins_dir, old_game_path))

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

    # -- Heal --

    def _heal_one(self, card, patched_finding=None):
        self._run(lambda: self._heal_worker(card, patched_finding))

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
        self._run(lambda: self._do_build_translations(plugins))

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

    def _run(self, fn):
        if self.busy:
            return
        self.busy = True
        self.scan_btn.config(state="disabled")
        self.trans_btn.config(state="disabled")
        self.status.config(text="Working\u2026")
        threading.Thread(target=self._worker, args=(fn,), daemon=True).start()

    def _worker(self, fn):
        try:
            fn()
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("Error", str(exc)))
        finally:
            self.root.after(0, self._done)

    def _done(self):
        self.busy = False
        self.scan_btn.config(state="normal")
        self.trans_btn.config(state="normal")
        self.status.config(text="Done")

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
        # ── Notebook (tabs) ──
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=6, pady=(6, 0))

        # Tab 1: Address Library (existing functionality)
        self.tab_main = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_main, text="  Address Library  ")

        # Tab 2: Healer
        self.tab_healer = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_healer, text="  Healer  ")

        # ── Build main tab (existing UI, reparented to tab_main) ──
        self._build_main_tab()

        # ── Build healer tab ──
        self.healer_tab = HealerTab(
            self.tab_healer,
            game_exe=self.game_exe,
            plugins_dir_fn=self._plugins,
        )

    def _build_main_tab(self):
        parent = self.tab_main

        # ── Auto-detected location hint ──
        pf = tk.Frame(parent, bg=BG)
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
        bf = tk.Frame(parent, bg=BG)
        bf.pack(fill="x", padx=10, pady=(4, 4))

        self.scan_btn = ttk.Button(bf, text="Scan", command=self.scan)
        self.scan_btn.pack(side="left", padx=(0, 6))

        ttk.Button(bf, text="Clear",
                   command=self.clear).pack(side="left")

        self.pro_mode = tk.BooleanVar(value=False)
        self.pro_btn = tk.Checkbutton(
            bf, text="PRO MODE",
            variable=self.pro_mode,
            command=self._on_pro_toggle,
            font=(FONT_FAMILY, 9, "bold"),
            fg="#b91c1c", bg=BG, activebackground=BG,
            selectcolor=BG, cursor="hand2")
        self.pro_btn.pack(side="left", padx=(12, 0))

        # ── Summary bar ──
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

        # ── Scrollable card area ──
        self.sf = ScrollFrame(parent)
        self.sf.pack(fill="both", expand=True, padx=10, pady=(2, 4))

        # ── Status bar ──
        self.status = ttk.Label(parent, text="Ready", anchor="w")
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
        self.root.after(0, self._clear_cards)
        self._exe = None
        self._exe_sections = None
        self._addresslib = None
        runtime_version = (core.runtime_version_from_exe(self.game_exe)
                           if self.game_exe else None)

        dlls = sorted(plugins.glob("*.dll"))
        counts = {}
        self._scan_data = []
        for dll in dlls:
            try:
                info = core.analyze_plugin(dll, runtime_version, include_hooks=False)
            except OSError:
                continue
            build_year = _get_build_year(dll)
            build_date = _get_build_date_str(dll)
            v = classify(info, build_year, runtime_version)
            v["build_date"] = build_date
            self._scan_data.append((dll, info, v))
            counts[v["cat"]] = counts.get(v["cat"], 0) + 1
            self.root.after(
                0,
                lambda d=dll, i=info, v=v: self._add_card(d, i, v),
            )

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
                          force_fix=self.pro_mode.get())
        ncol = 2
        row = len(self.cards) // ncol
        col = len(self.cards) % ncol
        card.grid(row=row, column=col, sticky="nsew",
                  padx=4, pady=4)
        self.sf.inner.grid_columnconfigure(0, weight=1, uniform="card")
        self.sf.inner.grid_columnconfigure(1, weight=1, uniform="card")
        self.cards.append(card)

    def _on_pro_toggle(self):
        # Rebuild cards from the last scan so every one shows fix buttons
        # when pro mode is on.
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
            if kind in ("all", "hooks") or not getattr(card, "hooks_scanned", True):
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
                        if core.pattern_matches_at(
                                self._exe, self._exe_sections, base, old_off, hook.get("pattern")):
                            continue
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
                card.hooks_scanned = True
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
        self.status.config(text="Ready")

    # ──────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────

    def _resolve_al(self):
        """Return the versionlib matching the game exe, else first found.

        A stale-version lib maps IDs to wrong RVAs, poisoning every hook
        fix - same rule as the healer's loader.
        """
        plugins = self._plugins()
        if not plugins or not plugins.exists():
            return None
        bins = sorted(plugins.glob("versionlib-*.bin"))
        if not bins:
            return None
        if self.game_exe:
            game_ver = core.unpack_version(core.runtime_version_from_exe(self.game_exe))
            if game_ver:
                for b in bins:
                    if core.extract_version_from_filename(b.name) == game_ver:
                        return b
        return bins[0]


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
