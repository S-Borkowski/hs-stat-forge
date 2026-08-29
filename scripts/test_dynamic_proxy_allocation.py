#!/usr/bin/env python3
"""Exercise StatForge private proxy allocation in this Python process only."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pymem  # noqa: E402
import pymem.memory  # noqa: E402

import hs_statforge as statforge  # noqa: E402


def main() -> None:
    pm = pymem.Pymem(os.getpid())
    forge = statforge.StatForge.__new__(statforge.StatForge)
    forge.pm = pm
    try:
        module = pymem.process.base_module(pm.process_handle)
        site = int(module.lpBaseOfDll) + 0x1000
        address = forge._alloc_near_sites([site], 0x1000, instruction_size=5)
        try:
            assert forge._all_rel32_reachable([site], address, 5)
            assert pymem.memory.read_bytes(pm.process_handle, address, 32) == bytes(32)
            payload = forge._build_s10_exp_cave(7.5)
            forge._write_memory(address, payload)
            assert pymem.memory.read_bytes(pm.process_handle, address, len(payload)) == payload
        finally:
            assert statforge.kernel32.VirtualFreeEx(
                pm.process_handle,
                ctypes.c_void_p(address),
                0,
                statforge.MEM_RELEASE,
            )
        print("PASS: private proxy memory allocates near code, writes, verifies and releases cleanly.")
    finally:
        pm.close_process()


if __name__ == "__main__":
    main()
