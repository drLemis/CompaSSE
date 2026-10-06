"""Surgeon: co-save plugin blocks, list and drop.

Engine lives in surgeon.engine, the GUI tab in surgeon.tab.
"""
from .engine import (
    describe_chunks,
    drop_plugin,
    ess_thumbnail,
    fcc,
    find_uid_owners,
    fmt_index,
    locate_uid,
    missing_mods,
    parse_cosave,
    parse_save_filename,
    parse_uid,
    plugin_list_chunk,
    read_ess_info,
)
