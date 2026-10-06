"""Store and restore original files."""
import os
from pathlib import Path
import shutil
import tempfile

def _backup(src_path):
    """Copy the file to CompaSSE/backups. Skips if present."""
    parent = src_path.parent
    out_dir = parent / "CompaSSE" / "backups"
    out_dir.mkdir(parents=True, exist_ok=True)
    bak = out_dir / (src_path.name + ".bak")
    if not bak.exists():
        shutil.copy2(src_path, bak)
    return bak

def backup_bytes(path, data):
    """Back up the file, then write new bytes."""
    _backup(Path(path))
    dest = Path(path)
    fd, tmp_name = tempfile.mkstemp(dir=str(dest.parent),
                                     prefix=dest.name + ".",
                                     suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_name, dest)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise

def backup_path(dll_path):
    """Backup path for one DLL. None if missing."""
    bak = Path(dll_path).parent / "CompaSSE" / "backups" \
        / (Path(dll_path).name + ".bak")
    return bak if bak.exists() else None

def restore_one(dll_path):
    """Restore one file from backup. True if restored."""
    bak = backup_path(dll_path)
    if bak is None:
        return False
    shutil.copy2(bak, dll_path)
    return True

def list_backups(plugins_dir):
    """Pairs of (dll, backup) with a stored original."""
    out_dir = Path(plugins_dir) / "CompaSSE" / "backups"
    if not out_dir.is_dir():
        return []
    return [(Path(plugins_dir) / b.name[:-4], b)
            for b in sorted(out_dir.glob("*.bak"))]

def list_backups_all(plugin_dirs, dlls=None):
    """Backups across all plugin folders."""
    pairs = []
    seen = set()
    for d in plugin_dirs or []:
        if d is None:
            continue
        for dll_path, bak in list_backups(d):
            try:
                key = str(Path(bak).resolve()).lower()
            except OSError:
                key = str(bak).lower()
            if key not in seen:
                seen.add(key)
                pairs.append((dll_path, bak))
    for dll in dlls or []:
        try:
            bak = backup_path(dll)
        except OSError:
            bak = None
        if bak is None:
            continue
        try:
            key = str(Path(bak).resolve()).lower()
        except OSError:
            key = str(bak).lower()
        if key not in seen:
            seen.add(key)
            pairs.append((Path(dll), bak))
    return sorted(pairs, key=lambda p: p[0].name.lower())

def restore_backups_all(plugin_dirs, dlls=None):
    """Restore all backups. Returns the restored count."""
    done = 0
    for dll_path, _ in list_backups_all(plugin_dirs, dlls):
        if restore_one(dll_path):
            done += 1
    return done
