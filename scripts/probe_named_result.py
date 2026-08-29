#!/usr/bin/env python3
"""Reversibly probe one named Season 10 YYC result as scalar or array."""

from __future__ import annotations

import argparse
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("function_name")
    parser.add_argument("mode", choices=("scalar", "array", "additive"))
    parser.add_argument("--seconds", type=float, default=20.0)
    parser.add_argument("--modifier", type=float, default=1.0)
    args = parser.parse_args()

    forge = app.StatForge.__new__(app.StatForge)
    forge.pm = pymem.Pymem(app.PROCESS_NAME)
    forge.verified_module_hashes = {}
    forge.pe_sections_cache = {}
    forge.function_addresses_cache = {}
    forge.runtime_cache_lock = threading.RLock()
    forge._main_module_cache = None

    if args.mode == "scalar":
        kind = app.S10_SCALAR_RESULT_MULTIPLIER
    elif args.mode == "additive":
        kind = app.S10_ARRAY_RESULT_ADDITIVE
    else:
        kind = app.S10_ARRAY_RESULT_MULTIPLIER
    binding = app.StatBinding(
        key="named_result_probe",
        name=f"Named Result Probe: {args.function_name}",
        resolver={
            "kind": kind,
            "module": app.PROCESS_NAME,
            "function_name": args.function_name,
        },
    )
    module, site, original = forge._resolve_s10_result_epilogue_site(binding)
    if forge._read_raw(site, len(original)) != original:
        raise RuntimeError("hook site is occupied; no probe started")
    cave = forge._alloc_near_sites(
        [site], app.S10_RESULT_HOOK_ALLOCATION_SIZE, instruction_size=5
    )
    if args.mode == "scalar":
        blob = app.build_s10_scalar_result_hook_blob(
            cave, original, args.modifier
        )
    else:
        blob = app.build_s10_array_result_hook_blob(
            cave, original, args.modifier, additive=args.mode == "additive"
        )
    patch = app.build_s10_result_epilogue_patch(cave, site, len(original))
    data = cave + app.S10_RESULT_HOOK_DATA_OFFSET
    forge._write_memory(cave, blob)
    installed = False
    try:
        forge._write_code_when_quiescent(site, patch)
        installed = forge._read_raw(site, len(patch)) == patch
        if not installed:
            raise RuntimeError("probe installation failed")
        print(
            f"PROBE ACTIVE {args.function_name} {args.mode} "
            f"x{args.modifier:g} for {args.seconds:g}s | "
            f"RVA 0x{site - int(module['base']):X}"
        )
        last_count = 0
        last_print_count = 0
        deadline = time.time() + args.seconds
        while time.time() < deadline:
            native, modified, count, modifier = struct.unpack(
                "<ddQd", forge._read_raw(data, 32)
            )
            if count != last_count:
                if math.isfinite(native) and math.isfinite(modified):
                    if last_print_count == 0 or count - last_print_count >= 20:
                        print(
                            f"CALL native={native:g} result={modified:g} "
                            f"modifier={modifier:g} count={count}"
                        )
                        last_print_count = count
                last_count = count
            time.sleep(0.1)
        native, modified, count, modifier = struct.unpack(
            "<ddQd", forge._read_raw(data, 32)
        )
        print(
            f"FINAL count={count} native={native:g} "
            f"result={modified:g} modifier={modifier:g}"
        )
    finally:
        if installed and forge._read_raw(site, len(original)) == patch:
            forge._write_code_when_quiescent(site, original)
        print(f"RESTORED: {forge._read_raw(site, len(original)) == original}")


if __name__ == "__main__":
    main()
