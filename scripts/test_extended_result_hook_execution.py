#!/usr/bin/env python3
"""Execute R14/RSP Season 10 result hooks and verify CALL stack compensation."""

from __future__ import annotations

import ctypes
import math
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import hs_statforge as forge  # noqa: E402


class RValue(ctypes.Structure):
    _fields_ = [("value", ctypes.c_double), ("flags", ctypes.c_uint32), ("kind", ctypes.c_uint32)]


CASES = (
    (
        "R14 + MOV RBP,[RSP+58h]",
        bytes.fromhex(
            "48 81 ec 60 00 00 00 "  # sub rsp,60h
            "48 89 6c 24 58 "        # save rbp
            "4c 89 74 24 50 "        # save r14
            "49 89 ce"               # r14 = result pointer
        ),
        bytes.fromhex("49 8b c6 48 8b 6c 24 58"),
        bytes.fromhex(
            "4c 8b 74 24 50 "        # restore r14
            "48 81 c4 60 00 00 00 "  # add rsp,60h
            "c3"
        ),
    ),
    (
        "R14 + LEA R11,[RSP+3A0h]",
        bytes.fromhex(
            "41 56 "                  # push r14
            "48 81 ec a0 03 00 00 "  # sub rsp,3a0h
            "49 89 ce"               # r14 = result pointer
        ),
        bytes.fromhex("49 8b c6 4c 8d 9c 24 a0 03 00 00"),
        bytes.fromhex(
            "4d 8b 33 "               # restore r14 from [r11]
            "49 83 c3 08 "            # r11 = caller rsp
            "49 8b e3 "               # rsp = r11
            "c3"
        ),
    ),
    (
        "R15 + MOV RBX,[RSP+1E0h]",
        bytes.fromhex(
            "48 81 ec e8 01 00 00 "  # sub rsp,1e8h
            "48 89 9c 24 e0 01 00 00 "  # save rbx
            "4c 89 bc 24 d8 01 00 00 "  # save r15
            "49 89 cf"               # r15 = result pointer
        ),
        bytes.fromhex("49 8b c7 48 8b 9c 24 e0 01 00 00"),
        bytes.fromhex(
            "4c 8b bc 24 d8 01 00 00 "  # restore r15
            "48 81 c4 e8 01 00 00 "  # add rsp,1e8h
            "c3"
        ),
    ),
    (
        "RBX + MOVAPS XMM6,[RSP+6580h]",
        bytes.fromhex(
            "53 "                       # push rbx
            "48 81 ec 90 65 00 00 "    # sub rsp,6590h
            "0f 29 b4 24 80 65 00 00 " # save xmm6
            "48 89 cb"                  # rbx = result pointer
        ),
        bytes.fromhex("48 8b c3 0f 28 b4 24 80 65 00 00"),
        bytes.fromhex(
            "48 81 c4 90 65 00 00 "    # add rsp,6590h
            "5b "                       # pop rbx
            "c3"
        ),
    ),
)


def run_case(label: str, prefix: bytes, original: bytes, suffix: bytes) -> None:
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
            forge.MEM_COMMIT | forge.MEM_RESERVE,
            forge.PAGE_EXECUTE_READWRITE,
        )
        or 0
    )
    if not allocation:
        raise ctypes.WinError()
    function = allocation
    cave = allocation + 0x1000
    try:
        site = function + len(prefix)
        native_function = prefix + original + suffix
        ctypes.memmove(function, native_function, len(native_function))
        blob = forge.build_s10_scalar_result_hook_blob(cave, original, 1.5)
        ctypes.memmove(cave, blob, len(blob))
        patch = forge.build_s10_result_epilogue_patch(cave, site, len(original))
        ctypes.memmove(site, patch, len(patch))
        kernel32.FlushInstructionCache(kernel32.GetCurrentProcess(), ctypes.c_void_p(allocation), 0x3000)

        function_type = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)
        hooked = function_type(function)
        result = RValue(10.0, 0, 0)
        returned = hooked(ctypes.byref(result))
        assert returned == ctypes.addressof(result), label
        assert result.kind == 0 and result.flags == 0, label
        assert math.isclose(result.value, 15.0), label
        native, modified, calls, factor = struct.unpack(
            "<ddQd", ctypes.string_at(cave + forge.S10_RESULT_HOOK_DATA_OFFSET, 32)
        )
        assert math.isclose(native, 10.0) and math.isclose(modified, 15.0), label
        assert calls == 1 and math.isclose(factor, 1.5), label
        print(f"PASS {label}: 10 x 1.5 = {result.value:g}")
    finally:
        kernel32.VirtualFree(ctypes.c_void_p(allocation), 0, forge.MEM_RELEASE)


def main() -> int:
    for case in CASES:
        run_case(*case)
    print("PASS: all observed R14/RSP result preludes preserve the native stack.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
