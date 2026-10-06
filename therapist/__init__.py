"""Therapist tools: audit, scan, fix. Built on core, used by the GUI."""
from .audit import (analyze_plugin, check_version_independence)
from .fix import (patch_bytes_guarded, patch_flag,
    patch_flag_force, patch_version_independence,
    patch_version_independence_force, resolve_bytes_site)
from .scan import (collect_xref_ids, count_xref_ids,
    disambiguate_hook_by_callee, find_hooks, find_pattern_offsets,
    find_version_gates, patch_hook_offset, pattern_matches_at)
from .tab import TherapistTab

__all__ = ["analyze_plugin", "check_version_independence",
    "patch_bytes_guarded", "patch_flag", "patch_flag_force",
    "patch_version_independence", "patch_version_independence_force",
    "resolve_bytes_site", "collect_xref_ids", "count_xref_ids",
    "disambiguate_hook_by_callee", "find_hooks", "find_pattern_offsets",
    "find_version_gates", "patch_hook_offset", "pattern_matches_at",
    "TherapistTab"]
