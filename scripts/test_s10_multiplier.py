#!/usr/bin/env python3
"""Write-free tests for the separate Season 10 multiplier variant."""

from __future__ import annotations

import sys
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import hs_statforge_multiplier as multiplier  # noqa: E402


class RefreshHarness:
    _values_close = staticmethod(multiplier.StatForgeMultiplier._values_close)

    def __init__(self, current: float):
        self.current = current
        self.binding = multiplier.MULTIPLIER_STATS[0]
        self.writes: list[float] = []
        self.ui_updates: list[tuple[float, float, float]] = []

    def _find_binding(self, key: str):
        return self.binding if key == self.binding.key else None

    def _protected_snapshot(self, _binding, _entry=None):
        return {"entry": 0x1000, "value_address": 0x2000, "value": self.current}

    def _write_protected_value(self, _binding, snapshot, value: float):
        self.writes.append(value)
        self.current = value
        return {**snapshot, "value": value}

    def _read_set_variable_slot(self, _key):
        return {
            "factor": 10.0,
            "native": 0.0,
            "scaled": 0.0,
            "counter": 0,
            "enabled": True,
        }

    def _apply_gameplay_return(self, _binding, value: float, _payload=None):
        return {"return_site": 0x3000, "return_original": b"original", "return_patch": value}

    def _set_multiplier_current_text(self, _binding, native: float, scaled: float, factor: float):
        self.ui_updates.append((native, scaled, factor))


class ProtectedWriteHarness:
    _values_close = staticmethod(multiplier.StatForgeMultiplier._values_close)

    def __init__(self, snapshot: dict):
        self.snapshot = dict(snapshot)
        self.memory = {
            snapshot["value_address"]: bytes(snapshot["encrypted_raw"]),
            snapshot["entry"] + snapshot["integrity_offset"]: bytes(snapshot["integrity_raw"]),
            snapshot["entry"] + snapshot["undefined_offset"]: bytes(snapshot["undefined_raw"]),
        }
        self.write_order: list[tuple[int, bytes]] = []

    @staticmethod
    def _s10_integrity_value(value_bits: int, xor_key: int):
        return multiplier.core.StatForge._s10_integrity_value(value_bits, xor_key)

    def _write_memory(self, address: int, raw: bytes):
        self.write_order.append((address, bytes(raw)))
        self.memory[address] = bytes(raw)

    def _protected_snapshot(self, _binding, _entry=None):
        encrypted = struct.unpack("<Q", self.memory[self.snapshot["value_address"]])[0]
        bits = encrypted ^ self.snapshot["xor_key"]
        value = struct.unpack("<d", struct.pack("<Q", bits))[0]
        return {**self.snapshot, "value": value}


class ReturnPatchHarness:
    def __init__(self, value: float):
        self.site = 0x3000
        self.original = b"O" * len(multiplier.StatForgeMultiplier._build_s10_stat_return_patch(0.0))
        self.patch = multiplier.StatForgeMultiplier._build_s10_stat_return_patch(value)
        self.writes = 0
        self.logs: list[str] = []

    def _resolve_s10_stat_return_site(self, _binding):
        return {}, self.site, self.original

    @staticmethod
    def _build_s10_stat_return_patch(value: float):
        return multiplier.StatForgeMultiplier._build_s10_stat_return_patch(value)

    @staticmethod
    def _is_owned_s10_stat_return_patch(raw: bytes):
        return multiplier.StatForgeMultiplier._is_owned_s10_stat_return_patch(raw)

    def _read_raw(self, _site: int, _size: int):
        return self.patch

    def _write_patch_group(self, _sites, _patches):
        self.writes += 1

    def log_line(self, text: str):
        self.logs.append(text)


def main() -> int:
    numeric_patch = multiplier.StatForgeMultiplier._build_s10_stat_return_patch(550.0)
    kind_marker = bytes.fromhex("41 c7 40 0c")
    kind_at = numeric_patch.index(kind_marker) + len(kind_marker)
    assert numeric_patch[kind_at:kind_at + 4] == b"\x00\x00\x00\x00"
    assert multiplier.StatForgeMultiplier._is_owned_s10_stat_return_patch(numeric_patch)

    kinds = [item.resolver["kind"] for item in multiplier.MULTIPLIER_STATS[:3]]
    assert kinds == [
        multiplier.MULTIPLIER_KIND,
        multiplier.MULTIPLIER_KIND,
        multiplier.VALUE_KIND,
    ]
    all_skills = multiplier.MULTIPLIER_STATS[2]
    assert all_skills.slider_max == 200
    assert all_skills.resolver["max"] == 200
    assert multiplier.core.CONFIG_FILE.endswith(multiplier.CONFIG_NAME)
    assert multiplier.CONFIG_NAME != "hs_statforge_stats.json"

    assert len(multiplier.MULTIPLIER_STATS) == 4
    assert {
        item.key
        for item in multiplier.MULTIPLIER_STATS
        if item.resolver.get("kind") == multiplier.NATIVE_RESULT_KIND
    } == multiplier.VERIFIED_NATIVE_RESULT_KEYS
    native_bindings = multiplier.EXPERIMENTAL_NATIVE_STATS
    assert len(native_bindings) == 12
    assert native_bindings[0].key == "total_damage_bonus"
    entered, factor = multiplier.StatForgeMultiplier._native_result_factor(native_bindings[0], "50")
    assert entered == 50.0 and factor == 1.5
    entered, factor = multiplier.StatForgeMultiplier._native_result_factor(native_bindings[0], "100")
    assert entered == 100.0 and factor == 2.0

    set_cave = 0x180200000
    set_site = 0x180001370
    set_patch = multiplier.build_set_variable_hook_patch(set_cave)
    assert len(set_patch) == multiplier.SET_VARIABLE_HOOK_ENTRY_SIZE
    set_blob = multiplier.build_set_variable_hook_blob(
        set_cave,
        set_site,
        multiplier.SET_VARIABLE_ORIGINAL_ENTRY,
    )
    assert len(set_blob) == multiplier.SET_VARIABLE_HOOK_ALLOCATION_SIZE
    set_trampoline = multiplier.SET_VARIABLE_HOOK_TRAMPOLINE_OFFSET
    assert (
        set_blob[set_trampoline:set_trampoline + multiplier.SET_VARIABLE_HOOK_ENTRY_SIZE]
        == multiplier.SET_VARIABLE_ORIGINAL_ENTRY
    )
    set_data = multiplier.SET_VARIABLE_HOOK_DATA_OFFSET
    assert struct.unpack_from("<dd", set_blob, set_data) == (1.0, 1.0)
    set_instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(set_blob[:0x100], set_cave))
    assert sum(row.mnemonic == "mulsd" for row in set_instructions) == 2

    cave = 0x180000000
    site = 0x145CF2A80
    original_entry = bytes.fromhex("4c 89 44 24 18 48 89 54 24 10 48 89 4c 24 08")
    hook_patch = multiplier.build_native_result_hook_patch(cave)
    assert len(hook_patch) == multiplier.NATIVE_HOOK_ENTRY_SIZE
    assert hook_patch[:2] == b"\x48\xb8" and struct.unpack("<Q", hook_patch[2:10])[0] == cave
    blob = multiplier.build_native_result_hook_blob(cave, site, original_entry, 1.5)
    assert len(blob) == multiplier.NATIVE_HOOK_ALLOCATION_SIZE
    trampoline_at = multiplier.NATIVE_HOOK_TRAMPOLINE_OFFSET
    assert blob[trampoline_at:trampoline_at + 15] == original_entry
    assert struct.unpack_from("<d", blob, multiplier.NATIVE_HOOK_DATA_OFFSET + 24)[0] == 1.5
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(blob[:0x70], cave))
    mnemonics = []
    for row in instructions:
        mnemonics.append(row.mnemonic)
        if row.mnemonic == "ret":
            break
    assert mnemonics[0] == "sub"
    assert "call" in mnemonics and "mulsd" in mnemonics and mnemonics[-1] == "ret"

    epilogue_site = 0x145A6074E
    epilogue_cave = 0x145B00000
    result_load = bytes.fromhex("48 8b 85 20 22 00 00")
    epilogue_patch = multiplier.build_native_result_epilogue_patch(
        epilogue_cave,
        epilogue_site,
    )
    assert len(epilogue_patch) == multiplier.NATIVE_EPILOGUE_PATCH_SIZE
    relative = struct.unpack_from("<i", epilogue_patch, 1)[0]
    assert epilogue_site + 5 + relative == epilogue_cave
    epilogue_blob = multiplier.build_native_result_epilogue_blob(
        epilogue_cave,
        result_load,
        2.5,
    )
    assert epilogue_blob[:len(result_load)] == result_load
    assert struct.unpack_from(
        "<d",
        epilogue_blob,
        multiplier.NATIVE_HOOK_DATA_OFFSET + 24,
    )[0] == 2.5
    epilogue_instructions = list(
        Cs(CS_ARCH_X86, CS_MODE_64).disasm(epilogue_blob[:0x80], epilogue_cave)
    )
    epilogue_mnemonics = []
    for row in epilogue_instructions:
        epilogue_mnemonics.append(row.mnemonic)
        if row.mnemonic == "ret":
            break
    assert epilogue_mnemonics[0] == "mov"
    assert "call" not in epilogue_mnemonics
    assert "mulsd" in epilogue_mnemonics and epilogue_mnemonics[-1] == "ret"

    harness = RefreshHarness(current=100.0)
    payload = {
        "kind": multiplier.MULTIPLIER_KIND,
        "entry": 0x1000,
        "value_address": 0x2000,
        "factor": 10.0,
        "last_native": 10.0,
        "last_written": 100.0,
        "last_counter": 0,
    }
    multiplier.StatForgeMultiplier._refresh_multiplier(harness, "magic_find", payload)
    assert harness.writes == [], "the tool must not multiply its own last write again"

    harness.current = 15.0  # coherent native equipment/zone recalculation
    multiplier.StatForgeMultiplier._refresh_multiplier(harness, "magic_find", payload)
    assert harness.writes == [150.0]
    assert payload["last_native"] == 15.0
    assert payload["last_written"] == 150.0
    assert harness.ui_updates == [(15.0, 150.0, 10.0)]

    multiplier.StatForgeMultiplier._refresh_multiplier(harness, "magic_find", payload)
    assert harness.writes == [150.0], "the scaled value must remain stable after refresh"

    return_harness = ReturnPatchHarness(150.0)
    return_payload = {
        "return_site": return_harness.site,
        "return_original": return_harness.original,
        "return_patch": return_harness.patch,
    }
    multiplier.StatForgeMultiplier._apply_gameplay_return(
        return_harness, multiplier.MULTIPLIER_STATS[0], 150.0, return_payload
    )
    assert return_harness.writes == 0, "an unchanged gameplay patch must never suspend game threads"

    multiplier.StatForgeMultiplier._apply_gameplay_return(
        return_harness, multiplier.MULTIPLIER_STATS[0], 150.0, None
    )
    assert return_harness.writes == 0, "a matching stale patch should be adopted without rewriting"
    assert return_harness.logs, "stale patch recovery should be recorded"

    xor_key = 0x123456789ABCDEF0
    native_bits = struct.unpack("<Q", struct.pack("<d", 10.0))[0]
    original_snapshot = {
        "entry": 0x1000,
        "value_address": 0x2000,
        "value": 10.0,
        "xor_key": xor_key,
        "encrypted_raw": struct.pack("<Q", native_bits ^ xor_key),
        "integrity_raw": struct.pack(
            "<Q", multiplier.core.StatForge._s10_integrity_value(native_bits, xor_key)
        ),
        "undefined_raw": b"\x00",
        "integrity_offset": 0x08,
        "undefined_offset": 0x20,
    }
    protected = ProtectedWriteHarness(original_snapshot)
    multiplier.StatForgeMultiplier._write_protected_value(
        protected, multiplier.MULTIPLIER_STATS[0], original_snapshot, 20.0
    )
    assert [raw for _address, raw in protected.write_order[::3]] != []
    assert protected.write_order[0] == (0x1020, b"\x01")
    assert protected.write_order[-1] == (0x1020, b"\x00")
    assert protected._protected_snapshot(None)["value"] == 20.0
    print("PASS: native epilogue, protected-table and EXP multiplier helpers are structurally valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
