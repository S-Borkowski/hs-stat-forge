#!/usr/bin/env python3
"""Regression test for the CalculateEndDamage/helper epilogue ambiguity."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import hs_statforge as app  # noqa: E402


BASE = 0x140000000
FUNCTION = BASE + 0x1000
REAL_EPILOGUE_OFFSET = 0x40
HELPER_EPILOGUE_OFFSET = 0x100
REAL_RESULT_LOAD = bytes.fromhex("48 8b 85 00 0e 00 00")


class ResolverHarness:
    def __init__(self) -> None:
        self.code = bytearray(b"\x90" * 0x180)
        self.code[REAL_EPILOGUE_OFFSET:REAL_EPILOGUE_OFFSET + 7] = REAL_RESULT_LOAD
        self.code[REAL_EPILOGUE_OFFSET + 7:REAL_EPILOGUE_OFFSET + 15] = bytes.fromhex(
            "4c 8d 9c 24 a8 0e 00 00"
        )
        self.code[REAL_EPILOGUE_OFFSET + 15:REAL_EPILOGUE_OFFSET + 19] = bytes.fromhex(
            "49 8b e3 c3"
        )

        # This is the anonymous helper shape the old resolver selected.
        self.code[HELPER_EPILOGUE_OFFSET:HELPER_EPILOGUE_OFFSET + 8] = bytes.fromhex(
            "49 8b c6 48 8b 6c 24 58"
        )
        self.code[HELPER_EPILOGUE_OFFSET + 8:HELPER_EPILOGUE_OFFSET + 15] = bytes.fromhex(
            "48 83 c4 40 41 5e c3"
        )
        self.live_code = bytearray(self.code)

    @staticmethod
    def _hero_module(_module_name: str):
        return {"base": BASE, "name": app.PROCESS_NAME}

    def _discover_function_addresses(self, _module: dict):
        return {
            "gml_Script_CalculateEndDamage": FUNCTION,
            "gml_Script_NextNamedFunction": FUNCTION + len(self.code),
        }

    def _function_extent(self, _function: int, _addresses: list[int]):
        return len(self.code)

    def _read_module_file_bytes(self, _module: dict, rva: int, size: int):
        start = rva - (FUNCTION - BASE)
        return bytes(self.code[start:start + size])

    def _read_raw(self, address: int, size: int):
        start = address - FUNCTION
        return bytes(self.live_code[start:start + size])


def main() -> int:
    binding = next(row for row in app.DEFAULT_STATS if row.key == "total_damage_bonus")
    harness = ResolverHarness()
    _module, site, original = app.StatForge._resolve_s10_result_epilogue_site(
        harness, binding
    )

    expected = FUNCTION + REAL_EPILOGUE_OFFSET
    assert site == expected, f"expected real epilogue {hex(expected)}, got {hex(site)}"
    assert original == REAL_RESULT_LOAD
    assert site != FUNCTION + HELPER_EPILOGUE_OFFSET

    corrupted = ResolverHarness()
    corrupted.live_code[REAL_EPILOGUE_OFFSET + 7] ^= 0x01
    try:
        app.StatForge._resolve_s10_result_epilogue_site(corrupted, binding)
    except RuntimeError as exc:
        assert "epilogue context differs" in str(exc)
    else:
        raise AssertionError("modified live epilogue context was not rejected")
    print(
        "PASS: CalculateEndDamage resolved to its own RBP result epilogue; "
        "anonymous helper ignored; modified live context rejected."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
