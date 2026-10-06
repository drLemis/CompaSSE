"""One shim config file for the CompaSSE folder.

!CompaSSE.ini holds the two plain lists the shim reads at game start:
[touched] for consented DLL basenames, [legacy_skip] for versionless
mods the legacy loader must not run. Lines outside a known section
count as [touched], so old touched.ini content pastes in cleanly.

Old separate files still work when !CompaSSE.ini is missing. When it
exists, it wins and they are ignored. First write migrates them in
and removes them, so edits never land in a file nobody reads.
"""
from pathlib import Path

CONFIG_NAME = "!CompaSSE.ini"
TOUCHED_SECTION = "touched"
SKIP_SECTION = "legacy_skip"

TOUCHED_LEGACY = "touched.ini"
SKIP_LEGACY = "legacy-skip.ini"

_SHIM_DIR = "CompaSSE"

DEFAULT_TEXT = """\
; CompaSSE shim config - consent list and legacy skip list.
; One entry per line. ';', '#' and unknown [sections] are skipped.
; The exe appends here on every fix; the shim reads it at game start.
; A missing file means legacy mode (serve all).

[touched]
; DLL basenames you allowed CompaSSE to fix.

[legacy_skip]
; Versionless mods the legacy loader must not run.
; name.dll [| year=YYYY] [| note]. A pinned year skips only that build.
"""

def _shim_dir(plugins_dir):
    """CompaSSE sidecar folder for a plugins folder."""
    p = Path(plugins_dir)
    if p.name.lower() == _SHIM_DIR.lower():
        return p
    return p / _SHIM_DIR

def config_path(plugins_dir):
    """Unified config path for a plugins folder."""
    return _shim_dir(plugins_dir) / CONFIG_NAME

def _section_of(line):
    """Lowercased section name for [header] lines. None otherwise."""
    s = line.strip()
    if len(s) >= 3 and s.startswith("[") and s.endswith("]"):
        return s[1:-1].strip().lower() or None
    return None

def _read_lines(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

def read_section(plugins_dir, section, include_prelude=False):
    """Raw lines of one section. Falls back to the legacy file.

    With include_prelude, pre-section lines count as touched too, so
    old touched.ini content pastes in cleanly. Writers always use
    strict section lines; the prelude passes through untouched.
    """
    shim = _shim_dir(plugins_dir)
    unified = shim / CONFIG_NAME
    if unified.is_file():
        lines = _read_lines(unified)
        if lines is None:
            return []
        out = []
        cur = None
        for line in lines:
            sect = _section_of(line)
            if sect is not None and line.strip().startswith("["):
                cur = sect
                continue
            if cur is None:
                if include_prelude and section == TOUCHED_SECTION:
                    out.append(line)
                continue
            if cur == section:
                out.append(line)
        return out
    legacy = shim / (TOUCHED_LEGACY if section == TOUCHED_SECTION
                      else SKIP_LEGACY)
    lines = _read_lines(legacy)
    return lines if lines is not None else []

def _is_entry(line):
    s = line.strip()
    return bool(s) and s[0] not in ";#['\""

def _migrate_lines(shim, section):
    """Entry lines from the legacy file, for folding into unified."""
    legacy = shim / (TOUCHED_LEGACY if section == TOUCHED_SECTION
                      else SKIP_LEGACY)
    lines = _read_lines(legacy)
    if not lines:
        return []
    return [ln for ln in lines if _is_entry(ln)]

def prelude_lines(plugins_dir):
    """Raw pre-section lines of the unified file. [] otherwise."""
    lines = _read_lines(_shim_dir(plugins_dir) / CONFIG_NAME)
    if not lines:
        return []
    out = []
    for line in lines:
        sect = _section_of(line)
        if sect is not None and line.strip().startswith("["):
            break
        out.append(line)
    return out

def write_section(plugins_dir, section, entry_lines, prelude=None):
    """Rewrite one section, preserving the rest. Migrates legacy files.

    prelude replaces the pre-section block when given (prune uses it
    to drop stale pasted entries). Otherwise the prelude passes
    through untouched.
    """
    other = SKIP_SECTION if section == TOUCHED_SECTION else TOUCHED_SECTION
    shim = _shim_dir(plugins_dir)
    try:
        shim.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    unified = shim / CONFIG_NAME
    if unified.is_file():
        lines = _read_lines(unified)
        if lines is None:
            return False
    else:
        lines = DEFAULT_TEXT.splitlines()
    have = {ln.strip().lower() for ln in entry_lines}
    folded = [ln for ln in _migrate_lines(shim, section)
              if ln.strip().lower() not in have]
    if folded:
        entry_lines = list(entry_lines) + folded
    other_have = set()
    out, cur, done, other_done = [], None, False, False
    seen = set()
    pre = []
    for line in lines:
        sect = _section_of(line)
        if sect is not None and line.strip().startswith("["):
            if cur is None:
                out.extend(prelude if prelude is not None else pre)
            if cur == section and not done:
                out.extend(entry_lines)
                done = True
            if cur == other and not other_done:
                extra = [ln for ln in _migrate_lines(shim, other)
                         if ln.strip().lower() not in other_have]
                out.extend(extra)
                other_done = True
            cur = sect
            seen.add(sect)
            out.append(line)
            continue
        if cur is None:
            pre.append(line)
            continue
        if cur == section:
            continue
        if cur == other:
            other_have.add(line.strip().lower())
            out.append(line)
            continue
        out.append(line)
    if cur is None:
        out.extend(prelude if prelude is not None else pre)
    if cur == other and not other_done:
        out.extend(ln for ln in _migrate_lines(shim, other)
                   if ln.strip().lower() not in other_have)
    if cur == section and not done:
        out.extend(entry_lines)
        done = True
    if not done and section not in seen:
        if out and out[-1].strip():
            out.append("")
        out.append("[%s]" % section)
        out.extend(entry_lines)
    try:
        unified.write_text("\n".join(out) + "\n", encoding="utf-8")
    except OSError:
        return False
    for legacy in (TOUCHED_LEGACY, SKIP_LEGACY):
        try:
            (shim / legacy).unlink()
        except OSError:
            pass
    return True
