#!/usr/bin/env python3
"""Execute the S10 native-result wrapper against a synthetic YYC function."""

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


PREFIXES = (
    bytes.fromhex("4c 89 44 24 18 48 89 54 24 10 48 89 4c 24 08"),
    bytes.fromhex("48 8b c4 4c 89 40 18 48 89 50 10 48 89 48 08"),
)


def run_one(prefix: bytes) -> None:
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
    kernel32.FlushInstructionCache.argtypes = (
        ctypes.wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
    )
    kernel32.FlushInstructionCache.restype = ctypes.wintypes.BOOL

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
        native_value = ctypes.c_double(10.0)
        native_body = (
            b"\x48\x8b\x54\x24\x28"  # mov rdx, [rsp+28h] (fifth argument)
            b"\x48\x8b\x02"  # mov rax, [rdx]
            b"\x49\x89\x00"  # mov [r8], rax
            b"\x41\xc7\x40\x08\x00\x00\x00\x00"
            b"\x41\xc7\x40\x0c\x00\x00\x00\x00"
            b"\xb8\x78\x56\x34\x12"  # deliberately do not return the RValue pointer
            b"\xc3"
        )
        ctypes.memmove(site, prefix + native_body, len(prefix) + len(native_body))
        blob = multiplier.build_native_result_hook_blob(cave, site, prefix, 1.5)
        ctypes.memmove(cave, blob, len(blob))
        patch = multiplier.build_native_result_hook_patch(cave)
        ctypes.memmove(site, patch, len(patch))
        kernel32.FlushInstructionCache(kernel32.GetCurrentProcess(), ctypes.c_void_p(allocation), 0x3000)

        function_type = ctypes.CFUNCTYPE(
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
        )
        function = function_type(site)
        result = RValue(0.0, 0, 0)
        returned = function(None, None, ctypes.byref(result), 0, ctypes.byref(native_value))
        assert returned == ctypes.addressof(result)
        assert result.kind == 0 and result.flags == 0
        assert math.isclose(result.value, 15.0)

        data = ctypes.string_at(cave + multiplier.NATIVE_HOOK_DATA_OFFSET, 24)
        observed_native, observed_scaled, counter = struct.unpack("<ddQ", data)
        assert math.isclose(observed_native, 10.0)
        assert math.isclose(observed_scaled, 15.0)
        assert counter == 1
    finally:
        kernel32.VirtualFree(ctypes.c_void_p(allocation), 0, multiplier.core.MEM_RELEASE)


def main() -> int:
    for prefix in PREFIXES:
        run_one(prefix)
    print("PASS: native YYC result hooks execute, scale and report both supported S10 entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
