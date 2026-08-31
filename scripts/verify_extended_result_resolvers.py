#!/usr/bin/env python3
"""Read-only verification of StatForge's extended Season 10 result resolvers."""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pymem


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import hs_statforge as app  # noqa: E402


EXPECTED = {
    "gml_Script_CalculateEndDamage": (0x3A5425, "48 8b 85 00 0e 00 00"),
    "gml_Script_StatSpellCritRate": (0x5A1B87C, "49 8b c6 0f 28 b4 24 a0 03 00 00"),
    "gml_Script_StatCritDamage": (0x5A3021C, "48 8b 85 c0 18 00 00"),
    "gml_Script_StatSpellCritDamage": (0x5A1FA5C, "49 8b c6 4c 8d 9c 24 a0 03 00 00"),
    "gml_Script_StatCritRate": (0x5A22A3C, "49 8b c6 0f 28 b4 24 a0 03 00 00"),
    "gml_Script_StatDefense": (0x5BA4613, "48 8b 85 a0 11 00 00"),
    "gml_Script_StatAttackSpeed": (0x5B3A05C, "48 8b c3 0f 28 b4 24 80 65 00 00"),
    "gml_Script_StatFasterCastRate": (0x5A51BE2, "48 8b 85 10 3a 00 00"),
    "gml_Script_StatSpellHaste": (0x5B96B16, "48 8b 85 00 03 00 00"),
}


def main() -> None:
    forge = app.StatForge.__new__(app.StatForge)
    forge.pm = pymem.Pymem(app.PROCESS_NAME)
    forge.verified_module_hashes = {}
    forge.pe_sections_cache = {}
    forge.function_addresses_cache = {}
    forge.runtime_cache_lock = threading.RLock()
    forge._main_module_cache = None

    module = forge._hero_module(app.PROCESS_NAME)
    if not module:
        raise RuntimeError(f"{app.PROCESS_NAME} is not loaded")

    checked = set()
    for binding in app.DEFAULT_STATS:
        if binding.key not in {
            "total_damage_bonus",
            "attack_speed_bonus",
            "faster_cast_rate_bonus",
            "skill_haste_bonus",
            "defense_bonus",
            "critical_strike_damage_bonus",
            "critical_strike_chance_bonus",
            "spell_critical_damage_bonus",
            "spell_critical_chance_bonus",
        }:
            continue
        resolver = binding.resolver or {}
        if binding.key == "attack_speed_bonus":
            if resolver.get("kind") != app.S10_SCALAR_RESULT_MULTIPLIER:
                raise RuntimeError("Attack Speed must use the scalar StatAttackSpeed result")
            if resolver.get("function_name") != "gml_Script_StatAttackSpeed":
                raise RuntimeError("Attack Speed must resolve the aggregate StatAttackSpeed function")
        names = resolver.get("function_names") or [resolver.get("function_name")]
        for function_name in names:
            function_name = str(function_name)
            _module, site, original = forge._resolve_s10_result_epilogue_site(binding, function_name)
            rva = site - int(module["base"])
            expected_rva, expected_hex = EXPECTED[function_name]
            expected_bytes = bytes.fromhex(expected_hex)
            if rva != expected_rva or original != expected_bytes:
                raise RuntimeError(
                    f"{function_name}: expected RVA 0x{expected_rva:x} / {expected_hex}, "
                    f"got RVA 0x{rva:x} / {original.hex(' ')}"
                )
            print(f"OK {function_name}: RVA 0x{rva:x} | {original.hex(' ')}")
            checked.add(function_name)

    missing = sorted(set(EXPECTED) - checked)
    if missing:
        raise RuntimeError(f"unverified functions: {', '.join(missing)}")
    print(f"PASS: {len(checked)} exact Season 10 result preludes verified; no writes made.")


if __name__ == "__main__":
    main()
