"""Saved paths for game exe and mod manager."""
from pathlib import Path

SETTINGS_NAME = "CompaSSE.ini"

def _settings_file(app_dir):
    if app_dir is None:
        return None
    return Path(app_dir) / SETTINGS_NAME

def _valid_file(text):
    cand = Path((text or "").strip())
    try:
        if text and text.strip() and cand.is_file():
            return cand
    except OSError:
        pass
    return None

def _read_settings(path):
    import configparser
    parser = configparser.RawConfigParser()
    parser.optionxform = lambda optionstr: optionstr
    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return {}
    if not parser.has_section("Paths"):
        return {}
    return {k: v for k, v in parser.items("Paths")}

def load_settings(app_dir, game_dir=None):
    """{"game": Path, "mo2": Path} for remembered locations (valid files only)."""
    path = _settings_file(app_dir)
    vals = _read_settings(path) if path is not None else {}
    out = {}
    for key in ("game", "mo2"):
        found = _valid_file(vals.get(key, ""))
        if found is not None:
            out[key] = found
    if path is not None:
        legacy = {}
        old_game = Path(app_dir) / "CompaSSE-game.ini"
        try:
            has_old_game = old_game.is_file()
        except OSError:
            has_old_game = False
        if "game" not in out and has_old_game:
            try:
                found = _valid_file(old_game.read_text(
                    encoding="utf-8", errors="replace"))
            except OSError:
                found = None
            if found is not None:
                legacy["game"] = str(found)
                out["game"] = found
        old_mo2 = None
        if game_dir is not None:
            old_mo2 = Path(game_dir) / "Data" / "SKSE" / "Plugins" \
                / "CompaSSE" / "mo2.ini"
        legacy_mo2_text = None
        if old_mo2 is not None:
            try:
                if old_mo2.is_file():
                    legacy_mo2_text = old_mo2.read_text(
                        encoding="utf-8", errors="replace")
            except OSError:
                legacy_mo2_text = None
        if "mo2" not in out and legacy_mo2_text is not None:
            found = _valid_file(legacy_mo2_text)
            if found is not None:
                legacy["mo2"] = str(found)
                out["mo2"] = found
        if legacy:
            vals.update(legacy)
            try:
                import configparser
                parser = configparser.RawConfigParser()
                parser.optionxform = lambda optionstr: optionstr
                parser.add_section("Paths")
                for k, v in vals.items():
                    parser.set("Paths", k, v)
                with open(path, "w", encoding="utf-8") as f:
                    parser.write(f)
            except OSError:
                pass
            else:
                for old in (old_game, old_mo2):
                    try:
                        if old is not None and old.is_file():
                            old.unlink()
                    except OSError:
                        pass
    return out

def store_setting(app_dir, key, value, game_dir=None):
    """Remember one setting (None/"" forgets it). Returns True on success."""
    path = _settings_file(app_dir)
    if path is None:
        return False
    vals = _read_settings(path)
    if value:
        vals[key] = str(value)
    else:
        vals.pop(key, None)
    try:
        import configparser
        parser = configparser.RawConfigParser()
        parser.optionxform = lambda optionstr: optionstr
        parser.add_section("Paths")
        for k, v in vals.items():
            parser.set("Paths", k, v)
        with open(path, "w", encoding="utf-8") as f:
            parser.write(f)
        return True
    except OSError:
        return False

def saved_game_exe(app_dir):
    """Remembered SkyrimSE.exe location, or None."""
    return load_settings(app_dir).get("game")

def save_game_exe(app_dir, exe_path):
    """Remember a SkyrimSE.exe location. Returns True on success."""
    return store_setting(app_dir, "game", exe_path)

def saved_mo2_ini(app_dir, game_dir=None):
    """Remembered ModOrganizer.ini location, or None."""
    return load_settings(app_dir, game_dir).get("mo2")

def save_mo2_ini(app_dir, ini_path):
    """Remember a ModOrganizer.ini location. Returns True on success."""
    return store_setting(app_dir, "mo2", ini_path)

def clear_mo2_ini(app_dir):
    """Forget the ModOrganizer.ini location. Returns True on success."""
    path = _settings_file(app_dir)
    if path is None:
        return False
    if store_setting(app_dir, "mo2", None):
        return True
    try:
        return not path.exists()
    except OSError:
        return False
