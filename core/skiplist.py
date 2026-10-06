"""Skip list for versionless plugins."""
from pathlib import Path
from core.config import (CONFIG_NAME, SKIP_SECTION, SKIP_LEGACY,
                         _shim_dir, config_path, read_section,
                         write_section)
from core.pe import find_export_rva, find_pe_sections, pe_build_dt

LEGACY_SKIP_NAME = SKIP_LEGACY

LEGACY_SKIP_HEADER = (
    "; Versionless plugins the legacy loader must not run.",
    "; One entry per line: filename [| year=YYYY] [| note].",
    "';', '#' and [sections] start comments/sections and are skipped.",
    "; With a year, only that build is skipped; without, every build matches.",
    "; These load what SKSE itself refuses; a faulting one takes the game down.",
)

def _parse_skip_entry(line):
    """Parse one skip line. None if blank."""
    text = (line or "").strip()
    if not text or text[0] in ";#['\"":
        return None
    import re as _re
    parts = [p.strip() for p in text.split("|")]
    name = parts[0] if parts else ""
    if not name or len(name) > 260:
        return None
    year = None
    notes = []
    for seg in parts[1:]:
        m = _re.fullmatch(r"year\s*=\s*(\d{4})", seg, _re.IGNORECASE)
        if m and year is None:
            year = int(m.group(1))
        elif seg:
            notes.append(seg)
    return (name, year, " | ".join(notes))

def _format_skip_entry(name, year=None, note=""):
    """Format one skip line."""
    clean = " ".join(str(note or "").replace("|", "/").split())
    line = str(name or "").strip()
    if year:
        line += f" | year={int(year)}"
    if clean:
        line += f" | {clean}"
    return line

def _split_lines(lines):
    """(header, entries) from raw section lines."""
    header, entries, seen = [], [], False
    for line in lines:
        parsed = _parse_skip_entry(line)
        if parsed is None:
            if not seen:
                header.append(line)
            continue
        seen = True
        entries.append(parsed)
    return (header, entries)

def read_legacy_skip(ini_path):
    """Read the skip file. Missing file gives ([], [])."""
    ini_path = Path(ini_path)
    if ini_path.name == CONFIG_NAME:
        try:
            lines = ini_path.read_text(
                encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ([], [])
        out, cur = [], None
        for ln in lines:
            s = ln.strip()
            if len(s) >= 3 and s.startswith("[") and s.endswith("]"):
                cur = s[1:-1].strip().lower()
                continue
            if cur == SKIP_SECTION:
                out.append(ln)
        return _split_lines(out)
    try:
        with open(ini_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return ([], [])
    return _split_lines(lines)

def _write_unified(plugins_dir, entries, header):
    if not header:
        header = list(LEGACY_SKIP_HEADER)
    lines = list(header) + [_format_skip_entry(n, y, t)
                            for n, y, t in entries or []]
    shim = _shim_dir(plugins_dir)
    try:
        write_section(shim, SKIP_SECTION, lines)
    except OSError:
        return False
    return True

def write_legacy_skip(ini_path, entries, header=None):
    """Write the skip file. Keeps the header."""
    ini_path = Path(ini_path)
    if ini_path.name == CONFIG_NAME:
        shim = ini_path.parent
        plugins = shim.parent if shim.name.lower() == "compasse" else shim
        if header is None:
            header, _ = read_legacy_skip(ini_path)
        return _write_unified(plugins, entries, header)
    if header is None:
        header, _ = read_legacy_skip(ini_path)
    if not header:
        header = list(LEGACY_SKIP_HEADER)
    body = "\r\n".join(header + [_format_skip_entry(n, y, t)
                                 for n, y, t in entries or []])
    with open(ini_path, "w", encoding="utf-8", newline="") as f:
        f.write(body + "\r\n")

def legacy_skip_path(plugins_dir):
    """Unified config path for a plugins folder."""
    return config_path(plugins_dir)

def _read_plugins(plugins_dir):
    """(header, entries) with legacy fallback."""
    return _split_lines(read_section(plugins_dir, SKIP_SECTION))

def is_legacy_skipped(plugins_dir, dll_name, year=None):
    """True if this DLL build is skipped."""
    _, entries = _read_plugins(plugins_dir)
    want = str(dll_name or "").lower()
    for name, pinned, _note in entries:
        if name.lower() != want:
            continue
        if pinned is None or year is None or pinned == year:
            return True
    return False

def add_legacy_skip(plugins_dir, dll_name, year=None, note=""):
    """Skip one build. Skips all builds if year is None."""
    header, entries = _read_plugins(plugins_dir)
    want = str(dll_name or "").strip()
    entries = [(n, y, t) for n, y, t in entries
               if n.lower() != want.lower() or y != year]
    entries.append((want, year, " ".join(str(note or "").split())))
    _write_unified(plugins_dir, entries, header)

def remove_legacy_skip(plugins_dir, dll_name, year=None):
    """Remove skip entries for one DLL."""
    header, entries = _read_plugins(plugins_dir)
    want = str(dll_name or "").strip().lower()
    if year is None:
        kept = [(n, y, t) for n, y, t in entries if n.lower() != want]
    else:
        kept = [(n, y, t) for n, y, t in entries
                if n.lower() != want or y != year]
    if len(kept) != len(entries):
        _write_unified(plugins_dir, kept, header)
    return len(entries) - len(kept)

def pe_build_year(dll_path):
    """Build year from the PE stamp. None if missing."""
    dt = pe_build_dt(dll_path)
    return dt.year if dt is not None else None

def is_versionless_plugin(dll_path):
    """True if the DLL has Query and Load but no Version export."""
    try:
        with open(dll_path, "rb") as f:
            data = f.read()
    except OSError:
        return False
    sections = find_pe_sections(data)
    if not sections:
        return False
    if find_export_rva(data, sections, b"SKSEPlugin_Version") is not None:
        return False
    return (find_export_rva(data, sections, b"SKSEPlugin_Query") is not None
            and find_export_rva(data, sections, b"SKSEPlugin_Load") is not None)
