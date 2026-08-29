"""Reversible live probe for the S10 StatForge Multiplier dual-layer route."""

from __future__ import annotations

import os
import sys
import threading
import time

import pymem


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import hs_statforge_multiplier as multiplier


def main() -> int:
    tool = object.__new__(multiplier.StatForgeMultiplier)
    tool.pm = pymem.Pymem(multiplier.core.PROCESS_NAME)
    tool.verified_module_hashes = {}
    tool.pe_sections_cache = {}
    tool.function_addresses_cache = {}
    tool._main_module_cache = None
    tool.runtime_cache_lock = threading.RLock()

    binding = multiplier.MULTIPLIER_STATS[0]
    snapshot = tool._protected_snapshot(binding)
    native = float(snapshot["value"])
    target = native * 2.0
    return_payload = None
    table_changed = False
    started = time.perf_counter()
    try:
        return_payload = tool._apply_gameplay_return(binding, target)
        return_ms = (time.perf_counter() - started) * 1000.0
        patched_code = tool._read_raw(
            int(return_payload["return_site"]), len(return_payload["return_patch"])
        )
        if patched_code != return_payload["return_patch"]:
            raise RuntimeError("gameplay return bytes did not verify")

        confirmed = tool._write_protected_value(binding, snapshot, target)
        table_changed = True
        time.sleep(0.25)
        reread = tool._protected_snapshot(binding, int(snapshot["entry"]))
        if not tool._values_close(float(reread["value"]), target):
            raise RuntimeError(f"table did not persist: {reread['value']} != {target}")
        print(
            f"PASS apply: native={native:g} target={target:g} "
            f"table={float(confirmed['value']):g} return_patch_ms={return_ms:.1f}"
        )
    finally:
        errors = []
        if table_changed:
            try:
                current = tool._protected_snapshot(binding, int(snapshot["entry"]))
                tool._write_protected_value(binding, current, native)
            except Exception as exc:  # pragma: no cover - diagnostic safety path
                errors.append(f"table restore: {exc}")
        if return_payload is not None:
            try:
                tool._restore_gameplay_return(binding, return_payload)
            except Exception as exc:  # pragma: no cover - diagnostic safety path
                errors.append(f"code restore: {exc}")
        restored = tool._protected_snapshot(binding, int(snapshot["entry"]))
        code_ok = True
        if return_payload is not None:
            code_ok = tool._read_raw(
                int(return_payload["return_site"]), len(return_payload["return_original"])
            ) == return_payload["return_original"]
        print(f"RESTORE table={float(restored['value']):g} code_original={code_ok}")
        if errors:
            raise RuntimeError("; ".join(errors))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
