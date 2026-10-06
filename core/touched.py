"""Track which DLLs the user allowed CompaSSE to fix."""
from pathlib import Path

from core.config import (TOUCHED_SECTION, TOUCHED_LEGACY, _shim_dir,
                         config_path, prelude_lines, read_section,
                         write_section)

TOUCHED_NAME = TOUCHED_LEGACY
_SHIM_DIR = "CompaSSE"
_SELF = "!compasse.dll"

def touched_path(plugins_dir):
    """Ledger path for a plugins folder."""
    return config_path(plugins_dir)

def _token(line):
    """Lowercased name from one ledger line. None if blank."""
    s = line.strip()
    if not s or s.startswith(";") or s.startswith("#") \
            or s.startswith("["):
        return None
    head = s.split("|", 1)[0]
    parts = head.split()
    if not parts:
        return None
    return parts[0].lower()

def read_touched(plugins_dir):
    """Names in the ledger. Empty if missing."""
    out = set()
    for line in read_section(plugins_dir, TOUCHED_SECTION,
                             include_prelude=True):
        tok = _token(line)
        if tok:
            out.add(tok)
    return out

def add_touched(shim_plugins_dir, dll_path):
    """Record one fixed DLL. True if listed."""
    try:
        name = Path(dll_path).name
    except Exception:
        return False
    if not name or name.lower() == _SELF:
        return False
    key = name.lower()
    if key in read_touched(shim_plugins_dir):
        return True
    lines = [ln for ln in read_section(shim_plugins_dir, TOUCHED_SECTION)
             if _token(ln) != key]
    lines.append(name)
    return write_section(shim_plugins_dir, TOUCHED_SECTION, lines)

def remove_touched(shim_plugins_dir, dll_path):
    """Remove one DLL from the ledger. True if removed."""
    try:
        key = Path(dll_path).name.lower()
    except Exception:
        return False
    if not key:
        return False
    lines = read_section(shim_plugins_dir, TOUCHED_SECTION)
    kept = [ln for ln in lines if _token(ln) != key]
    pre = [ln for ln in prelude_lines(shim_plugins_dir)
           if _token(ln) != key]
    if len(kept) == len(lines) and pre == prelude_lines(shim_plugins_dir):
        return False
    return write_section(shim_plugins_dir, TOUCHED_SECTION, kept,
                          prelude=pre)

def seed_from_backups(shim_plugins_dir):
    """Record DLLs that have backups. Returns the added count."""
    shim = _shim_dir(shim_plugins_dir)
    try:
        baks = sorted((shim / "backups").glob("*.bak"))
    except OSError:
        return 0
    current = read_touched(shim)
    added = 0
    for bak in baks:
        stem = bak.name
        if stem.lower().endswith(".bak"):
            stem = stem[:-4]
        if not stem:
            continue
        key = stem.lower()
        if key == _SELF or key in current:
            continue
        if add_touched(shim, stem):
            current.add(key)
            added += 1
    return added

def prune_missing(shim_plugins_dir):
    """Drop entries for missing DLLs. Returns the removed count."""
    p = Path(shim_plugins_dir)
    if p.name.lower() == _SHIM_DIR.lower():
        plugins = p.parent
    else:
        plugins = p
    try:
        present = {q.name.lower() for q in plugins.iterdir()
                   if q.is_file()}
    except OSError:
        return 0
    lines = read_section(shim_plugins_dir, TOUCHED_SECTION)
    kept, dropped = [], 0
    for line in lines:
        tok = _token(line)
        if tok is not None and tok not in present:
            dropped += 1
            continue
        kept.append(line)
    pre = [ln for ln in prelude_lines(shim_plugins_dir)
           if _token(ln) is None or _token(ln) in present]
    dropped += sum(1 for _ in prelude_lines(shim_plugins_dir)) - len(pre)
    if not dropped:
        return 0
    if not write_section(shim_plugins_dir, TOUCHED_SECTION, kept,
                          prelude=pre):
        return 0
    return dropped
