#!/usr/bin/env python3
"""Read-only adaptive resolver audit for two real Hero Siege S10 builds."""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace


STATFORGE_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = next(
    (parent for parent in STATFORGE_ROOT.parents if (parent / "HSOfflineLootForge").is_dir()),
    STATFORGE_ROOT.parent,
)
SYMBOL_TOOLS = WORKSPACE_ROOT / "HSOfflineLootForge" / "scripts"
sys.path.insert(0, str(STATFORGE_ROOT))
sys.path.insert(0, str(SYMBOL_TOOLS))

import hs_statforge as statforge  # noqa: E402
from hs_symbol_forge import PE, extract  # noqa: E402


GAME_BUILDS = (
    Path(r"C:\Users\falor\Downloads\Hero-Siege-AnkerGames\HeroSiege\bin\Hero_Siege.exe"),
    Path(r"C:\Program Files (x86)\Steam\steamapps\common\HeroSiege\bin\Hero_Siege.exe"),
)
LEGACY_CONFIG = (
    WORKSPACE_ROOT
    / "HSStatForge"
    / "_backups"
    / "pre_obsidian_20260824_090711"
    / "hs_statforge_stats.json"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def make_forge(path: Path, pe: PE, functions: dict[str, int]):
    forge = statforge.StatForge.__new__(statforge.StatForge)
    forge.pm = SimpleNamespace(process_id=4242)
    forge.runtime_cache_lock = threading.RLock()
    forge.pe_sections_cache = {}
    forge.function_addresses_cache = {}
    forge.verified_module_hashes = {}
    module = {
        "name": statforge.PROCESS_NAME,
        "path": str(path),
        "base": pe.image_base,
    }
    forge._hero_module = lambda _name: module
    forge._discover_function_addresses = lambda _module: functions
    forge.log_line = lambda _message: None

    def read_raw(address: int, size: int):
        file_offset = pe.va_to_fo(address)
        if file_offset is None:
            raise RuntimeError(f"unmapped test address: 0x{address:x}")
        return bytes(pe.mm[file_offset:file_offset + size])

    forge._read_raw = read_raw
    return forge


def main() -> None:
    legacy_payload = json.loads(LEGACY_CONFIG.read_text(encoding="utf-8"))
    migration = statforge.StatForge.__new__(statforge.StatForge)
    migration.stat_bindings = [statforge.StatBinding.from_dict(item) for item in legacy_payload["stats"]]
    migration._save_bindings = lambda: None
    migration._apply_builtin_bindings()
    assert all("module_sha256" not in (binding.resolver or {}) for binding in migration.stat_bindings)
    print("PASS: legacy v2 bindings migrate to adaptive v3 resolvers without a whole-file hash.")

    for path in GAME_BUILDS:
        assert path.is_file(), f"Hero Siege test build not found: {path}"
        pe = PE(str(path))
        try:
            functions = extract(pe)
            forge = make_forge(path, pe, functions)
            for binding in statforge.DEFAULT_STATS:
                assert "module_sha256" not in (binding.resolver or {})
                if forge._is_s10_stat_return_proxy_binding(binding):
                    _module, site, original = forge._resolve_s10_stat_return_site(binding)
                    assert site == functions[binding.resolver["function_name"]]
                    assert forge._is_supported_s10_stat_entry(original)
                    corrupted = bytes([original[0] ^ 0xFF]) + original[1:]
                    assert not forge._is_supported_s10_stat_entry(corrupted)
                elif forge._is_s10_exp_proxy_binding(binding):
                    _module, site, original = forge._resolve_s10_exp_factor_site(binding)
                    assert forge._is_s10_exp_factor_store(original)
                    assert site >= functions[binding.resolver["function_name"]]

            owned = forge._build_s10_stat_return_patch(123.0)
            assert forge._is_owned_s10_stat_return_patch(owned)
            assert not forge._is_owned_s10_stat_return_patch(owned[:-1] + b"\x90")
            print(f"PASS {path.name} sha256={sha256(path)[:12]} functions={len(functions)}")
        finally:
            pe.mm.close()
            pe.f.close()

    print("PASS: adaptive stat/EXP resolvers accept both S10 layouts and reject corrupted entries without writes.")


if __name__ == "__main__":
    main()
