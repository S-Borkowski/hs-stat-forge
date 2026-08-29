#!/usr/bin/env python3
"""Count StatAttackSpeed calls with a behavior-neutral x1 native result hook."""

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


def main(duration: float = 20.0, factor: float = 1.0, scalar: bool = False) -> None:
    forge = app.StatForge.__new__(app.StatForge)
    forge.pm = pymem.Pymem(app.PROCESS_NAME)
    forge.verified_module_hashes = {}
    forge.pe_sections_cache = {}
    forge.function_addresses_cache = {}
    forge.runtime_cache_lock = threading.RLock()
    forge._main_module_cache = None
    binding = app.StatBinding(
        key="attack_speed_root_probe",
        name="Attack Speed Root Probe",
        resolver={
            "kind": app.S10_ARRAY_RESULT_MULTIPLIER,
            "module": app.PROCESS_NAME,
            "function_name": "gml_Script_StatAttackSpeed",
        },
    )

    _module, site, original = forge._resolve_s10_result_epilogue_site(binding)
    if forge._read_raw(site, len(original)) != original:
        raise RuntimeError("StatAttackSpeed root hook site is occupied")
    cave = forge._alloc_near_sites([site], app.S10_RESULT_HOOK_ALLOCATION_SIZE, instruction_size=5)
    if scalar:
        blob = app.build_s10_scalar_result_hook_blob(cave, original, factor)
    else:
        blob = app.build_s10_array_result_hook_blob(cave, original, factor)
    patch = app.build_s10_result_epilogue_patch(cave, site, len(original))
    data = cave + app.S10_RESULT_HOOK_DATA_OFFSET
    forge._write_memory(cave, blob)
    installed = False
    try:
        forge._write_code_when_quiescent(site, patch)
        installed = forge._read_raw(site, len(patch)) == patch
        if not installed:
            raise RuntimeError("StatAttackSpeed root probe installation failed")
        value_kind = "scalar" if scalar else "array"
        print(f"PROBE ACTIVE: StatAttackSpeed {value_kind} x{factor:g} for {duration:g}s @ {hex(site)}")
        last_count = 0
        deadline = time.time() + duration
        while time.time() < deadline:
            native, modified, count, factor = struct.unpack("<ddQd", forge._read_raw(data, 32))
            if count != last_count:
                if math.isfinite(native) and math.isfinite(modified):
                    print(f"CALL native={native:g} result={modified:g} factor={factor:g} count={count}")
                last_count = count
            time.sleep(0.1)
        native, modified, count, factor = struct.unpack("<ddQd", forge._read_raw(data, 32))
        print(f"FINAL count={count} native={native:g} result={modified:g} factor={factor:g}")
    finally:
        if installed and forge._read_raw(site, len(original)) == patch:
            forge._write_code_when_quiescent(site, original)
        print(f"RESTORED: {forge._read_raw(site, len(original)) == original}")


if __name__ == "__main__":
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    multiplier = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0
    scalar_mode = len(sys.argv) > 3 and sys.argv[3].lower() == "scalar"
    main(seconds, multiplier, scalar_mode)
