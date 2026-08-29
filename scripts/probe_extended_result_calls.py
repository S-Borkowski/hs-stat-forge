#!/usr/bin/env python3
"""Temporarily count extended-stat calls with behavior-neutral result hooks."""

from __future__ import annotations

import math
import struct
import sys
import threading
import time
from pathlib import Path

import pymem


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import hs_statforge as app  # noqa: E402


TARGET_KEYS = {
    "total_damage_bonus",
    "attack_speed_bonus",
    "faster_cast_rate_bonus",
    "defense_bonus",
    "critical_strike_damage_bonus",
    "critical_strike_chance_bonus",
    "spell_critical_damage_bonus",
    "spell_critical_chance_bonus",
}


def make_forge():
    forge = app.StatForge.__new__(app.StatForge)
    forge.pm = pymem.Pymem(app.PROCESS_NAME)
    forge.verified_module_hashes = {}
    forge.pe_sections_cache = {}
    forge.function_addresses_cache = {}
    forge.runtime_cache_lock = threading.RLock()
    forge._main_module_cache = None
    return forge


def main(duration: float = 45.0) -> None:
    forge = make_forge()
    hooks = []
    installed = []
    try:
        for binding in app.DEFAULT_STATS:
            if binding.key not in TARGET_KEYS:
                continue
            resolver = binding.resolver or {}
            kind = str(resolver.get("kind") or "").lower()
            additive = kind == app.S10_ARRAY_RESULT_ADDITIVE
            array_result = kind in (app.S10_ARRAY_RESULT_MULTIPLIER, app.S10_ARRAY_RESULT_ADDITIVE)
            names = resolver.get("function_names") or [resolver.get("function_name")]
            for name in names:
                function_name = str(name)
                _module, site, original = forge._resolve_s10_result_epilogue_site(binding, function_name)
                if forge._read_raw(site, len(original)) != original:
                    raise RuntimeError(f"{function_name}: hook site is occupied; no probe started")
                cave = forge._alloc_near_sites([site], app.S10_RESULT_HOOK_ALLOCATION_SIZE, instruction_size=5)
                modifier = 0.0 if additive else 1.0
                if array_result:
                    blob = app.build_s10_array_result_hook_blob(
                        cave,
                        original,
                        modifier,
                        additive=additive,
                    )
                else:
                    blob = app.build_s10_scalar_result_hook_blob(cave, original, modifier)
                patch = app.build_s10_result_epilogue_patch(cave, site, len(original))
                forge._write_memory(cave, blob)
                hooks.append({
                    "name": function_name,
                    "site": site,
                    "original": original,
                    "patch": patch,
                    "data": cave + app.S10_RESULT_HOOK_DATA_OFFSET,
                })

        for hook in hooks:
            forge._write_code_when_quiescent(hook["site"], hook["patch"])
            if forge._read_raw(hook["site"], len(hook["patch"])) != hook["patch"]:
                raise RuntimeError(f"{hook['name']}: probe hook verification failed")
            installed.append(hook)

        print(f"PROBE ACTIVE: {len(installed)} no-op hooks for {duration:g}s")
        print("Open the stat panel, attack, cast, hit an enemy, and let an enemy hit you.")
        deadline = time.time() + duration
        last_counts = {hook["name"]: 0 for hook in hooks}
        while time.time() < deadline:
            for hook in hooks:
                native, modified, count, modifier = struct.unpack(
                    "<ddQd", forge._read_raw(hook["data"], 32)
                )
                if count != last_counts[hook["name"]]:
                    if math.isfinite(native) and math.isfinite(modified):
                        print(
                            f"CALL {hook['name']}: native={native:g} result={modified:g} "
                            f"modifier={modifier:g} count={count}"
                        )
                    last_counts[hook["name"]] = count
            time.sleep(0.1)

        print("FINAL COUNTS")
        for hook in hooks:
            native, modified, count, modifier = struct.unpack(
                "<ddQd", forge._read_raw(hook["data"], 32)
            )
            print(f"{hook['name']}: {count} | {native:g} -> {modified:g}")
    finally:
        for hook in reversed(installed):
            current = forge._read_raw(hook["site"], len(hook["original"]))
            if current == hook["patch"]:
                forge._write_code_when_quiescent(hook["site"], hook["original"])
            restored = forge._read_raw(hook["site"], len(hook["original"])) == hook["original"]
            print(f"RESTORED {hook['name']}: {restored}")


if __name__ == "__main__":
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 45.0
    main(seconds)
