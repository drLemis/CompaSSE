#!/usr/bin/env python3
"""Extra mod sources when real Data is empty (MO2 now, more later)."""
import configparser
import os
from pathlib import Path


def _strip_bytearray(value):
    value = (value or "").strip()
    if value.startswith("@ByteArray(") and value.endswith(")"):
        value = value[len("@ByteArray("):-1]
    return value.replace("\\\\", "\\")


def _resolve(raw, base_dir):
    if not raw:
        return None
    text = _strip_bytearray(raw).strip().strip('"')
    if not text:
        return None
    text = text.replace("%BASE_DIR%", str(base_dir))
    text = os.path.expandvars(text)
    path = Path(text)
    if not path.is_absolute():
        path = base_dir / path
    return path


def _read_ini(ini_path):
    parser = configparser.RawConfigParser()
    parser.optionxform = lambda optionstr: optionstr  # keep key case
    try:
        parser.read(ini_path, encoding="utf-8")
    except Exception:
        return None
    return parser


def _get(parser, *sections_keys):
    for section, key in sections_keys:
        try:
            if parser.has_option(section, key):
                return parser.get(section, key)
        except Exception:
            continue
    return None


def parse_instance(ini_path):
    """(mods_dir, profiles_dir, overwrite_dir, profile) or None."""
    ini_path = Path(ini_path)
    parser = _read_ini(ini_path)
    if parser is None:
        return None
    base_raw = _get(parser, ("Settings", "base_directory"))
    if base_raw:
        base_dir = _resolve(base_raw, ini_path.parent) or ini_path.parent
    else:
        base_dir = ini_path.parent
    mods_raw = _get(parser, ("General", "mod_directory"), ("Settings", "mod_directory"))
    prof_raw = _get(parser, ("General", "profiles_directory"),
                    ("Settings", "profiles_directory"))
    over_raw = _get(parser, ("General", "overwrite_directory"),
                    ("Settings", "overwrite_directory"))
    mods_dir = _resolve(mods_raw, base_dir) if mods_raw else base_dir / "mods"
    prof_dir = _resolve(prof_raw, base_dir) if prof_raw else base_dir / "profiles"
    over_dir = _resolve(over_raw, base_dir) if over_raw else base_dir / "overwrite"
    prof_raw_val = _get(parser, ("General", "selected_profile"))
    profile = _strip_bytearray(prof_raw_val) if prof_raw_val else ""
    profile = profile.strip()
    if not profile:
        profile = _newest_profile(prof_dir)
    return mods_dir, prof_dir, over_dir, profile


def _newest_profile(profiles_dir):
    try:
        cands = [p for p in Path(profiles_dir).iterdir() if p.is_dir()]
    except OSError:
        return ""
    if not cands:
        return ""
    cands.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0].name


def _ini_matches_game(ini_path, game_dir):
    parser = _read_ini(ini_path)
    if parser is None:
        return False
    game_raw = _get(parser, ("General", "gamePath"), ("General", "game_path"))
    if game_raw:
        resolved = _resolve(game_raw, Path(ini_path).parent)
        if resolved is not None and game_dir is not None:
            try:
                if resolved.resolve() == Path(game_dir).resolve():
                    return True
            except OSError:
                pass
            if str(resolved).lower().rstrip("\\/") == str(game_dir).lower().rstrip("\\/"):
                return True
            return False
    name_raw = _get(parser, ("General", "gameName"), ("General", "game_name"))
    if name_raw:
        name = _strip_bytearray(name_raw).lower()
        if "skyrim" in name:
            return True
    return False


def candidate_inis(game_dir):
    """Likely ModOrganizer.ini locations, most specific first."""
    out = []
    # No process scan by design: opening other processes trips AV heuristics.
    if game_dir is not None:
        game_dir = Path(game_dir)
        out.append(game_dir / "ModOrganizer.ini")
        parent = game_dir.parent
        out.append(parent / "ModOrganizer.ini")
    try:
        local = Path(os.environ.get("LOCALAPPDATA", "")) / "ModOrganizer"
        if local.is_dir():
            for child in sorted(local.iterdir()):
                if child.is_dir():
                    cand = child / "ModOrganizer.ini"
                    if cand.is_file():
                        out.append(cand)
    except OSError:
        pass
    seen = set()
    uniq = []
    for p in out:
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return [p for p in uniq if p.is_file()]


def find_instances(game_dir):
    """Parsed MO2 instances matching this game."""
    found = []
    for ini in candidate_inis(game_dir):
        try:
            if game_dir is not None and not _ini_matches_game(ini, game_dir):
                continue
        except Exception:
            continue
        parsed = parse_instance(ini)
        if parsed is None:
            continue
        mods_dir, prof_dir, over_dir, profile = parsed
        found.append({"ini": ini, "mods_dir": mods_dir,
                      "profiles_dir": prof_dir, "overwrite_dir": over_dir,
                      "profile": profile})
    return found


def active_mod_names(profiles_dir, profile):
    """Enabled mod names from modlist.txt, top priority last."""
    base = Path(profiles_dir) / profile / "modlist.txt" if profile else None
    if base is None or not base.is_file():
        try:
            cands = [p for p in Path(profiles_dir).iterdir() if p.is_dir()]
        except OSError:
            return []
        for cand in cands:
            alt = cand / "modlist.txt"
            if alt.is_file():
                base = alt
                break
        else:
            return []
    names = []
    try:
        text = base.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in text:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("+"):
            name = line[1:].strip()
            if name:
                names.append(name)
    return names


def _dlls_in_mod(mod_root):
    out = []
    for cand in (Path(mod_root) / "SKSE" / "Plugins",
                 Path(mod_root) / "Data" / "SKSE" / "Plugins"):
        try:
            if cand.is_dir():
                out.extend(sorted(cand.glob("*.dll")))
        except OSError:
            continue
    return out


def _bins_in_mod(mod_root):
    out = []
    for cand in (Path(mod_root) / "SKSE" / "Plugins",
                 Path(mod_root) / "Data" / "SKSE" / "Plugins"):
        try:
            if cand.is_dir():
                out.extend(sorted(cand.glob("versionlib-*.bin")))
                out.extend(sorted(cand.glob("version-*.bin")))
        except OSError:
            continue
    return out


def collect_mo2(game_dir, ini_path=None):
    """(dlls, bins, label): active MO2 mods for this game, or ([], [], '').

    No settings I/O here: the caller passes the picked ini explicitly.
    """
    instances = []
    seen_ini = set()

    def _add(ini):
        ini = Path(ini)
        try:
            key = str(ini.resolve()).lower()
        except OSError:
            key = str(ini).lower()
        if key in seen_ini:
            return
        try:
            if not ini.is_file():
                return
        except OSError:
            return
        parsed = parse_instance(ini)
        if parsed is None:
            return
        seen_ini.add(key)
        mods_dir, prof_dir, over_dir, profile = parsed
        instances.append({"ini": ini, "mods_dir": mods_dir,
                          "profiles_dir": prof_dir,
                          "overwrite_dir": over_dir, "profile": profile})

    if ini_path is not None:
        _add(ini_path)
    for inst in find_instances(game_dir):
        try:
            key = str(Path(inst["ini"]).resolve()).lower()
        except OSError:
            key = str(inst["ini"]).lower()
        if key not in seen_ini:
            seen_ini.add(key)
            instances.append(inst)
    dlls = []
    bins = []
    label = ""
    seen = set()
    for inst in instances:
        mods_dir = inst["mods_dir"]
        try:
            if not mods_dir.is_dir():
                continue
        except OSError:
            continue
        names = active_mod_names(inst["profiles_dir"], inst["profile"])
        if not names:
            continue
        for name in names:
            mod_root = mods_dir / name
            for dll in _dlls_in_mod(mod_root):
                try:
                    key = str(dll.resolve()).lower()
                except OSError:
                    key = str(dll).lower()
                if key not in seen:
                    seen.add(key)
                    dlls.append(dll)
            for b in _bins_in_mod(mod_root):
                try:
                    key = str(b.resolve()).lower()
                except OSError:
                    key = str(b).lower()
                if key not in seen:
                    seen.add(key)
                    bins.append(b)
        try:
            over = inst["overwrite_dir"]
            if over.is_dir():
                for dll in _dlls_in_mod(over):
                    try:
                        key = str(dll.resolve()).lower()
                    except OSError:
                        key = str(dll).lower()
                    if key not in seen:
                        seen.add(key)
                        dlls.append(dll)
                for b in _bins_in_mod(over):
                    try:
                        key = str(b.resolve()).lower()
                    except OSError:
                        key = str(b).lower()
                    if key not in seen:
                        seen.add(key)
                        bins.append(b)
        except OSError:
            pass
        if dlls or bins:
            label = f"{inst['profile']} ({len(names)} mods)"
            break
    return dlls, bins, label


def collect_kortex(game_dir):
    """Kortex VFS owner lookup lives here when someone reports it."""
    return [], [], ""


def collect_amethyst_vfs(game_dir):
    """Amethyst VFS (Linux opt-in) owner lookup lives here if needed."""
    return [], [], ""


def collect_for_game(game_dir, ini_path=None):
    """Union across VFS managers: (dlls, bins, label)."""
    dlls, bins, label = collect_mo2(game_dir, ini_path=ini_path)
    if dlls or bins:
        return dlls, bins, f"Mod Organizer ({label})" if label else "Mod Organizer"
    for probe in (collect_kortex, collect_amethyst_vfs):
        try:
            dlls, bins, label = probe(game_dir)
        except Exception:
            continue
        if dlls or bins:
            return dlls, bins, label
    return [], [], ""
