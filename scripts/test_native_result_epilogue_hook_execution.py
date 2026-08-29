#!/usr/bin/env python3
"""Execute the native-result epilogue multiplier in this Python process."""

from __future__ import annotations

import ctypes
import math
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import hs_statforge_multiplier as multiplier  # noqa: E402


class RValue(ctypes.Structure):
    _fields_ = [("value", ctypes.c_double), ("flags", ctypes.c_uint32), ("kind", ctypes.c_uint32)]


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
    function = allocation
    cave = allocation + 0x1000
    try:
        prefix = (
            b"\x55"  # push rbp
            b"\x48\x89\xe5"  # mov rbp, rsp
            b"\x48\x83\xec\x20"  # sub rsp, 20h
            b"\x48\x89\x8d\xf8\xff\xff\xff"  # mov [rbp-8], rcx
        )
        result_load = b"\x48\x8b\x85\xf8\xff\xff\xff"  # mov rax, [rbp-8]
        suffix = b"\xc9\xc3"  # leave; ret
        site = function + len(prefix)
        function_raw = prefix + result_load + suffix
        ctypes.memmove(function, function_raw, len(function_raw))

        blob = multiplier.build_native_result_epilogue_blob(cave, result_load, 1.5)
        ctypes.memmove(cave, blob, len(blob))
        patch = multiplier.build_native_result_epilogue_patch(cave, site)
        ctypes.memmove(site, patch, len(patch))

        function_type = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)
        hooked = function_type(function)
        result = RValue(10.0, 0, 0)
        returned = hooked(ctypes.byref(result))
        assert returned == ctypes.addressof(result)
        assert result.kind == 0 and result.flags == 0
        assert math.isclose(result.value, 15.0)

        data = ctypes.string_at(cave + multiplier.NATIVE_HOOK_DATA_OFFSET, 24)
        native, scaled, counter = struct.unpack("<ddQ", data)
        assert math.isclose(native, 10.0)
        assert math.isclose(scaled, 15.0)
        assert counter == 1
    finally:
        kernel32.VirtualFree(ctypes.c_void_p(allocation), 0, multiplier.core.MEM_RELEASE)

    print("PASS: native epilogue hook multiplies the live result and returns safely.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
