#!/usr/bin/env python3
"""Execute the shared SetVariable multiplier dispatcher in-process."""

from __future__ import annotations

import ctypes
import math
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import hs_statforge_multiplier as multiplier  # noqa: E402


def main() -> int:
    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualAlloc.argtypes = (
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
    )
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualFree.argtypes = (
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.wintypes.DWORD,
    )
    kernel32.VirtualFree.restype = ctypes.wintypes.BOOL

    allocation = int(
        kernel32.VirtualAlloc(
            None,
            0x3000,
            multiplier.core.MEM_COMMIT | multiplier.core.MEM_RESERVE,
            multiplier.core.PAGE_EXECUTE_READWRITE,
        )
        or 0
    )
    if not allocation:
        raise ctypes.WinError()
    site = allocation
    cave = allocation + 0x1000
    try:
        continuation = (
            b"\x66\x0f\x28\xc1"  # movapd xmm0, xmm1
            b"\x48\x83\xc4\x40"  # add rsp, 40h
            b"\x5f"  # pop rdi
            b"\x48\x8b\x5c\x24\x10"  # restore rbx
            b"\x48\x8b\x74\x24\x18"  # restore rsi
            b"\xc3"
        )
        native = multiplier.SET_VARIABLE_ORIGINAL_ENTRY + continuation
        ctypes.memmove(site, native, len(native))
        blob = multiplier.build_set_variable_hook_blob(
            cave,
            site,
            multiplier.SET_VARIABLE_ORIGINAL_ENTRY,
        )
        ctypes.memmove(cave, blob, len(blob))
        patch = multiplier.build_set_variable_hook_patch(cave)
        ctypes.memmove(site, patch, len(patch))

        data = cave + multiplier.SET_VARIABLE_HOOK_DATA_OFFSET
        ctypes.memmove(data + 0x00, struct.pack("<d", 2.0), 8)
        ctypes.memmove(data + 0x08, struct.pack("<d", 3.0), 8)
        ctypes.memmove(data + 0x40, struct.pack("<Q", 1), 8)
        ctypes.memmove(data + 0x48, struct.pack("<Q", 1), 8)

        function = ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_double, ctypes.c_double)(site)
        assert math.isclose(function(126490.0, 10.0), 20.0)
        assert math.isclose(function(126310.0, 25.0), 75.0)
        assert math.isclose(function(123.0, 7.0), 7.0)

        mf_native, mf_scaled, mf_counter = struct.unpack(
            "<ddQ", ctypes.string_at(data + 0x10, 24)
        )
        ms_native, ms_scaled, ms_counter = struct.unpack(
            "<ddQ", ctypes.string_at(data + 0x28, 24)
        )
        assert math.isclose(mf_native, 10.0)
        assert math.isclose(mf_scaled, 20.0)
        assert mf_counter == 1
        assert math.isclose(ms_native, 25.0)
        assert math.isclose(ms_scaled, 75.0)
        assert ms_counter == 1
    finally:
        kernel32.VirtualFree(ctypes.c_void_p(allocation), 0, multiplier.core.MEM_RELEASE)

    print("PASS: SetVariable hook scales only Magic Find and Movement Speed native writes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
