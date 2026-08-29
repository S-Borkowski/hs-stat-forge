#!/usr/bin/env python3
"""Force Toolhelp/Pymem module discovery off and verify the native PEB fallback."""

from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pymem  # noqa: E402
import pymem.memory  # noqa: E402

import hs_valuescanner as scanner  # noqa: E402


def main() -> None:
    pm = pymem.Pymem(os.getpid())
    original_list_modules = scanner.list_modules
    original_module_from_name = pymem.process.module_from_name
    original_base_module = pymem.process.base_module
    try:
        normal = scanner.resolve_main_module(pm, "python.exe")
        assert normal and normal["base"] and normal["size"]

        scanner.list_modules = lambda _pid: []
        pymem.process.module_from_name = lambda *_args, **_kwargs: None
        pymem.process.base_module = lambda *_args, **_kwargs: None
        fallback = scanner.resolve_main_module(pm, "python.exe")

        assert fallback is not None
        assert fallback["source"] == "PEB"
        assert fallback["base"] == normal["base"]
        assert fallback["size"] == normal["size"]
        assert Path(fallback["path"]).is_file()
        assert pymem.memory.read_bytes(pm.process_handle, fallback["base"], 2) == b"MZ"
        print(
            f"PASS: forced PEB fallback resolved base=0x{fallback['base']:x}, "
            f"size=0x{fallback['size']:x}, path={fallback['path']}"
        )
    finally:
        scanner.list_modules = original_list_modules
        pymem.process.module_from_name = original_module_from_name
        pymem.process.base_module = original_base_module
        pm.close_process()


if __name__ == "__main__":
    main()
