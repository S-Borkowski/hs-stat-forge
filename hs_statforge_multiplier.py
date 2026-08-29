# -*- coding: utf-8 -*-
"""HS Offline Stat Forge — native-stat multiplier variant.

This is intentionally a separate application from hs_statforge.py.  The
original edition replaces selected GameMaker stat-return values.  This edition
multiplies the live Season 10 protected stat-table values so the game UI and
gameplay consumers observe the same scaled value.
"""

from __future__ import annotations

import math
import os
import queue
import struct
import time
import ctypes

import hs_statforge as core
import hs_valuescanner as scan


APP_TITLE = "HS Offline Stat Forge Multiplier v1.2.0-s10-adaptive"
CONFIG_NAME = "hs_statforge_multiplier.json"
MULTIPLIER_KIND = "s10_ac_dll_multiplier"
VALUE_KIND = "s10_ac_dll_value"
NATIVE_RESULT_KIND = "s10_native_result_multiplier"
SET_VARIABLE_RVA = 0x1370
SET_VARIABLE_HOOK_ENTRY_SIZE = 15
SET_VARIABLE_HOOK_TRAMPOLINE_OFFSET = 0x100
SET_VARIABLE_HOOK_DATA_OFFSET = 0x200
SET_VARIABLE_HOOK_ALLOCATION_SIZE = 0x1000
SET_VARIABLE_ORIGINAL_ENTRY = bytes.fromhex(
    "48 89 5c 24 10 48 89 74 24 18 57 48 83 ec 40"
)
# The protected table is refreshed only for UI visibility.  Polling it at the
# base tool's 80 ms code-freeze cadence is unnecessary and can contend with
# Tk callbacks while the game rebuilds stats during combat/zone changes.
POLL_SECONDS = 0.25
S10_REAL_RETURN_PATCH_TAIL = bytes.fromhex(
    "49 89 00 "
    "41 c7 40 08 00 00 00 00 "
    "41 c7 40 0c 00 00 00 00 "
    "4c 89 c0 c3"
)

# Exact fallbacks are used only when a patched GameMaker build no longer
# exposes a readable runtime registration table.  Every RVA is bound to a
# whole-file SHA-256 and the function prologue is still validated before use.
VERIFIED_STAT_RVAS = {
    "8046293cc8df1c735c680860d3f26d33c6993afb2a2469bac7f1d1d2ee882f6b": {
        "gml_Script_StatMagicFind": 98_350_992,
        "gml_Script_StatMovementSpeed": 98_884_656,
        "gml_Script_StatAllSkills": 99_353_680,
        "gml_Script_StatTotalDamage": 0x5CF2A80,
        "gml_Script_StatAttackSpeed": 0x5E8AC00,
        "gml_Script_StatFasterCastRate": 0x5DA8DD0,
        "gml_Script_StatLifeReplenish": 0x5DF9F80,
        "gml_Script_StatManaReplenish": 0x5E16C30,
        "gml_Script_StatMaxLife": 0x5DE4F90,
        "gml_Script_StatMaxMana": 0x5DF4C60,
        "gml_Script_StatCritRate": 0x5D97C90,
        "gml_Script_StatCritDamage": 0x5D9B1D0,
        "gml_Script_StatArmor": 0x5D82450,
        "gml_Script_StatDefense": 0x5F1E9D0,
        "gml_Script_StatLifePerHit": 0x5E32A40,
    },
    "728c85aec0fe44040f2285308043a712195ea1e4ff88cf066dc85bec84d015c5": {
        "gml_Script_StatMagicFind": 98_350_992,
        "gml_Script_StatMovementSpeed": 98_884_656,
        "gml_Script_StatAllSkills": 99_353_680,
        "gml_Script_StatTotalDamage": 0x5CF2A80,
        "gml_Script_StatAttackSpeed": 0x5E8AC00,
        "gml_Script_StatFasterCastRate": 0x5DA8DD0,
        "gml_Script_StatLifeReplenish": 0x5DF9F80,
        "gml_Script_StatManaReplenish": 0x5E16C30,
        "gml_Script_StatMaxLife": 0x5DE4F90,
        "gml_Script_StatMaxMana": 0x5DF4C60,
        "gml_Script_StatCritRate": 0x5D97C90,
        "gml_Script_StatCritDamage": 0x5D9B1D0,
        "gml_Script_StatArmor": 0x5D82450,
        "gml_Script_StatDefense": 0x5F1E9D0,
        "gml_Script_StatLifePerHit": 0x5E32A40,
    },
    "5f8085456a27109681403d8c57533e6999fbd0664752ff5f2856985b5fbbde71": {
        "gml_Script_StatMagicFind": 98_331_696,
        "gml_Script_StatMovementSpeed": 98_865_360,
        "gml_Script_StatAllSkills": 99_334_384,
        "gml_Script_StatTotalDamage": 0x5CEDF00,
        "gml_Script_StatAttackSpeed": 0x5E860A0,
        "gml_Script_StatFasterCastRate": 0x5DA4270,
        "gml_Script_StatLifeReplenish": 0x5DF5420,
        "gml_Script_StatManaReplenish": 0x5E120D0,
        "gml_Script_StatMaxLife": 0x5DE0430,
        "gml_Script_StatMaxMana": 0x5DF0100,
        "gml_Script_StatCritRate": 0x5D93130,
        "gml_Script_StatCritDamage": 0x5D96670,
        "gml_Script_StatArmor": 0x5D7D8F0,
        "gml_Script_StatDefense": 0x5F19E70,
        "gml_Script_StatLifePerHit": 0x5E2DEE0,
    },
}


def _native_result_binding(
    key: str,
    name: str,
    function_name: str,
    default_write: str,
    color: str,
    slider_max: float,
    max_value: float,
    *,
    input_mode: str = "factor",
) -> core.StatBinding:
    return core.StatBinding(
        key=key,
        name=name,
        type_name="Double",
        default_write=default_write,
        button_color=color,
        slider_max=slider_max,
        resolver={
            "kind": NATIVE_RESULT_KIND,
            "module": core.PROCESS_NAME,
            "function_module": core.PROCESS_NAME,
            "function_name": function_name,
            "input_mode": input_mode,
            "max": max_value,
        },
    )


MULTIPLIER_STATS = [
    core.StatBinding(
        key="magic_find",
        name="Magic Find Multiplier",
        type_name="Double",
        default_write="10",
        button_color="#0f766e",
        slider_max=1000,
        resolver={
            "kind": MULTIPLIER_KIND,
            "module": "ac_dll_gm.dll",
            "module_sha256": core.AC_DLL_S10_SHA256,
            "table_rva": core.AC_DLL_TABLE_RVA,
            "key": 126490,
            "function_module": core.PROCESS_NAME,
            "function_name": "gml_Script_StatMagicFind",
            "max": 1_000_000_000,
        },
    ),
    core.StatBinding(
        key="movement_speed",
        name="Movement Speed Multiplier",
        type_name="Double",
        default_write="2",
        button_color="#7c3aed",
        slider_max=100,
        resolver={
            "kind": MULTIPLIER_KIND,
            "module": "ac_dll_gm.dll",
            "module_sha256": core.AC_DLL_S10_SHA256,
            "table_rva": core.AC_DLL_TABLE_RVA,
            "key": 126310,
            "function_module": core.PROCESS_NAME,
            "function_name": "gml_Script_StatMovementSpeed",
            "max": 1000,
        },
    ),
    core.StatBinding(
        key="all_skills",
        name="All Skills",
        type_name="Double",
        default_write="200",
        button_color="#b45309",
        slider_max=200,
        resolver={
            "kind": VALUE_KIND,
            "module": "ac_dll_gm.dll",
            "module_sha256": core.AC_DLL_S10_SHA256,
            "table_rva": core.AC_DLL_TABLE_RVA,
            "key": 126670,
            "function_module": core.PROCESS_NAME,
            "function_name": "gml_Script_StatAllSkills",
            "max": 200,
        },
    ),
    # The site this patches is the `1` in  experience = base * (1 + bonus).
    # Verified in 7.0.30: xmm11 is loaded once from an .rdata constant (1.0),
    # stored to [rsp+0x40] here, then 0x186E10 ADDS the bonus into that slot and
    # 0x187880 MULTIPLIES the base by it.  So overwriting the 1 really does
    # scale the final experience - this is the right site, not a stray literal.
    core.StatBinding(
        key="exp_multiplier",
        name="EXP Multiplier",
        type_name="Double",
        default_write="10",
        button_color="#be123c",
        slider_max=100,
        resolver={
            "kind": "s10_exp_factor_proxy",
            "module": core.PROCESS_NAME,
            "function_name": "gml_Script_EnemyCalculateExperience",
            "context_hex": core.S10_EXP_FACTOR_CONTEXT.hex(" "),
            "store_hex": core.S10_EXP_FACTOR_STORE.hex(" "),
            "max": 100,
        },
    ),
    _native_result_binding(
        "total_damage_bonus",
        "Total Damage Bonus (%)",
        "gml_Script_StatTotalDamage",
        "50",
        "#dc6b2f",
        500,
        10_000,
        input_mode="bonus_percent",
    ),
    _native_result_binding(
        "attack_speed_multiplier",
        "Attack Speed Multiplier",
        "gml_Script_StatAttackSpeed",
        "2",
        "#d97706",
        20,
        100,
    ),
    _native_result_binding(
        "cast_speed_multiplier",
        "Cast Speed Multiplier",
        "gml_Script_StatFasterCastRate",
        "2",
        "#a855f7",
        20,
        100,
    ),
    _native_result_binding(
        "life_regen_multiplier",
        "Life Replenish Multiplier",
        "gml_Script_StatLifeReplenish",
        "10",
        "#16a34a",
        100,
        1_000,
    ),
    _native_result_binding(
        "mana_regen_multiplier",
        "Mana Replenish Multiplier",
        "gml_Script_StatManaReplenish",
        "10",
        "#2563eb",
        100,
        1_000,
    ),
    _native_result_binding(
        "max_life_multiplier",
        "Maximum Life Multiplier",
        "gml_Script_StatMaxLife",
        "10",
        "#be123c",
        100,
        1_000,
    ),
    _native_result_binding(
        "max_mana_multiplier",
        "Maximum Mana Multiplier",
        "gml_Script_StatMaxMana",
        "10",
        "#1d4ed8",
        100,
        1_000,
    ),
    _native_result_binding(
        "crit_chance_multiplier",
        "Critical Chance Multiplier",
        "gml_Script_StatCritRate",
        "2",
        "#eab308",
        20,
        100,
    ),
    _native_result_binding(
        "crit_damage_multiplier",
        "Critical Damage Multiplier",
        "gml_Script_StatCritDamage",
        "2",
        "#ef4444",
        20,
        100,
    ),
    _native_result_binding(
        "armor_multiplier",
        "Armor Multiplier",
        "gml_Script_StatArmor",
        "10",
        "#64748b",
        100,
        1_000,
    ),
    _native_result_binding(
        "defense_multiplier",
        "Defense Multiplier",
        "gml_Script_StatDefense",
        "10",
        "#0f766e",
        100,
        1_000,
    ),
    _native_result_binding(
        "life_per_hit_multiplier",
        "Life Per Hit Multiplier",
        "gml_Script_StatLifePerHit",
        "10",
        "#059669",
        100,
        1_000,
    ),
]

# Native result wrappers correctly reproduce the small ABI harness, but two
# real-game tests (Total Damage and Maximum Life) produced access violations
# inside GameMaker RValue helpers.  Keep the catalog for static research while
# preventing an existing JSON from exposing any unverified route.
VERIFIED_NATIVE_RESULT_KEYS: set[str] = set()
EXPERIMENTAL_NATIVE_STATS = [
    item
    for item in MULTIPLIER_STATS
    if (
        (item.resolver or {}).get("kind") == NATIVE_RESULT_KIND
        and item.key not in VERIFIED_NATIVE_RESULT_KEYS
    )
]
EXPERIMENTAL_NATIVE_KEYS = {item.key for item in EXPERIMENTAL_NATIVE_STATS}
MULTIPLIER_STATS = [
    item
    for item in MULTIPLIER_STATS
    if (
        (item.resolver or {}).get("kind") != NATIVE_RESULT_KIND
        or item.key in VERIFIED_NATIVE_RESULT_KEYS
    )
]


# The base application was designed to allow built-in resolver replacement.
# Give this executable its own title, config and defaults before constructing
# the UI; the original source/config remain untouched.
core.APP_TITLE = APP_TITLE
core.CONFIG_FILE = os.path.join(core.runtime_app_dir(), CONFIG_NAME)
core.CONFIG_VERSION = 3
core.RETIRED_S10_BINDINGS.update(EXPERIMENTAL_NATIVE_KEYS)
core.DEFAULT_STATS = MULTIPLIER_STATS


NATIVE_HOOK_ENTRY_SIZE = 15
NATIVE_HOOK_TRAMPOLINE_OFFSET = 0x80
NATIVE_HOOK_DATA_OFFSET = 0x100
NATIVE_HOOK_ALLOCATION_SIZE = 0x1000
NATIVE_EPILOGUE_PATCH_SIZE = 7


def build_set_variable_hook_patch(cave: int) -> bytes:
    """Jump from ac_dll_gm!SetVariable to the shared multiplier dispatcher."""
    return b"\x48\xb8" + struct.pack("<Q", int(cave)) + b"\xff\xe0" + b"\x90" * 3


def build_set_variable_hook_blob(cave: int, site: int, original_entry: bytes) -> bytes:
    """Multiply selected native SetVariable values before encryption.

    The game supplies the protected-table key in XMM0 and the freshly
    calculated native value in XMM1.  Matching values are multiplied in XMM1,
    then the untouched SetVariable prologue continues through a trampoline.
    This makes equipment, buff and zone recalculations adaptive and prevents
    multiplying an already-scaled table value.
    """
    if bytes(original_entry) != SET_VARIABLE_ORIGINAL_ENTRY:
        raise ValueError("SetVariable hook requires the verified 15-byte prologue")

    trampoline = int(cave) + SET_VARIABLE_HOOK_TRAMPOLINE_OFFSET
    data = int(cave) + SET_VARIABLE_HOOK_DATA_OFFSET
    mf_key_bits = struct.unpack("<Q", struct.pack("<d", 126490.0))[0]
    ms_key_bits = struct.unpack("<Q", struct.pack("<d", 126310.0))[0]
    code = bytearray()
    code += b"\x66\x48\x0f\x7e\xc0"  # movq rax, xmm0
    code += b"\x48\xba" + struct.pack("<Q", mf_key_bits)  # mov rdx, MF key bits
    code += b"\x48\x39\xd0"  # cmp rax, rdx
    mf_jump = len(code) + 1
    code += b"\x74\x00"  # je magic_find
    code += b"\x48\xba" + struct.pack("<Q", ms_key_bits)  # mov rdx, MS key bits
    code += b"\x48\x39\xd0"  # cmp rax, rdx
    ms_jump = len(code) + 1
    code += b"\x74\x00"  # je movement_speed
    tail_jumps: list[int] = []
    tail_jumps.append(len(code) + 1)
    code += b"\xeb\x00"  # jmp trampoline_tail

    magic_find = len(code)
    code += b"\x48\xb8" + struct.pack("<Q", data)  # mov rax, data
    code += b"\x48\x83\x78\x40\x00"  # cmp qword [rax+40h], 0 (enabled)
    tail_jumps.append(len(code) + 1)
    code += b"\x74\x00"  # je trampoline_tail
    code += b"\xf2\x0f\x11\x48\x10"  # movsd [rax+10h], xmm1 (native)
    code += b"\xf2\x0f\x59\x08"  # mulsd xmm1, [rax] (factor)
    code += b"\xf2\x0f\x11\x48\x18"  # movsd [rax+18h], xmm1 (scaled)
    code += b"\x48\xff\x40\x20"  # inc qword [rax+20h]
    tail_jumps.append(len(code) + 1)
    code += b"\xeb\x00"  # jmp trampoline_tail

    movement_speed = len(code)
    code += b"\x48\xb8" + struct.pack("<Q", data)  # mov rax, data
    code += b"\x48\x83\x78\x48\x00"  # cmp qword [rax+48h], 0 (enabled)
    tail_jumps.append(len(code) + 1)
    code += b"\x74\x00"  # je trampoline_tail
    code += b"\xf2\x0f\x11\x48\x28"  # movsd [rax+28h], xmm1 (native)
    code += b"\xf2\x0f\x59\x48\x08"  # mulsd xmm1, [rax+8] (factor)
    code += b"\xf2\x0f\x11\x48\x30"  # movsd [rax+30h], xmm1 (scaled)
    code += b"\x48\xff\x40\x38"  # inc qword [rax+38h]

    trampoline_tail = len(code)
    code += b"\x48\xb8" + struct.pack("<Q", trampoline)
    code += b"\xff\xe0"  # jmp rax

    for jump_index, target in ((mf_jump, magic_find), (ms_jump, movement_speed)):
        delta = target - (jump_index + 1)
        if not -128 <= delta <= 127:
            raise ValueError("SetVariable key branch is out of range")
        code[jump_index] = delta & 0xFF
    for jump_index in tail_jumps:
        delta = trampoline_tail - (jump_index + 1)
        if not -128 <= delta <= 127:
            raise ValueError("SetVariable tail branch is out of range")
        code[jump_index] = delta & 0xFF

    if len(code) >= SET_VARIABLE_HOOK_TRAMPOLINE_OFFSET:
        raise ValueError("SetVariable dispatcher overlaps its trampoline")
    trampoline_raw = (
        bytes(original_entry)
        + b"\x48\xb8"
        + struct.pack("<Q", int(site) + SET_VARIABLE_HOOK_ENTRY_SIZE)
        + b"\xff\xe0"
    )
    if SET_VARIABLE_HOOK_TRAMPOLINE_OFFSET + len(trampoline_raw) >= SET_VARIABLE_HOOK_DATA_OFFSET:
        raise ValueError("SetVariable trampoline overlaps its data")
    blob = bytearray(SET_VARIABLE_HOOK_ALLOCATION_SIZE)
    blob[:len(code)] = code
    start = SET_VARIABLE_HOOK_TRAMPOLINE_OFFSET
    blob[start:start + len(trampoline_raw)] = trampoline_raw
    # factors; then native/scaled/counter for MF and MS; then enabled flags.
    struct.pack_into("<dd", blob, SET_VARIABLE_HOOK_DATA_OFFSET, 1.0, 1.0)
    struct.pack_into("<ddQ", blob, SET_VARIABLE_HOOK_DATA_OFFSET + 0x10, 0.0, 0.0, 0)
    struct.pack_into("<ddQ", blob, SET_VARIABLE_HOOK_DATA_OFFSET + 0x28, 0.0, 0.0, 0)
    struct.pack_into("<QQ", blob, SET_VARIABLE_HOOK_DATA_OFFSET + 0x40, 0, 0)
    return bytes(blob)


SET_VARIABLE_SLOTS = {
    "magic_find": {
        "factor": 0x00,
        "native": 0x10,
        "scaled": 0x18,
        "counter": 0x20,
        "enabled": 0x40,
    },
    "movement_speed": {
        "factor": 0x08,
        "native": 0x28,
        "scaled": 0x30,
        "counter": 0x38,
        "enabled": 0x48,
    },
}


def build_native_result_hook_patch(cave: int) -> bytes:
    """Absolute entry jump padded to the two verified 15-byte YYC prefixes."""
    return b"\x48\xb8" + struct.pack("<Q", int(cave)) + b"\xff\xe0" + b"\x90" * 3


def build_native_result_hook_blob(
    cave: int,
    site: int,
    original_entry: bytes,
    factor: float,
) -> bytes:
    """Build a wrapper that calls native YYC code, then scales its real RValue.

    Data at +0x100 is: native double, scaled double, call counter and factor.
    This lets the UI report the exact value observed by gameplay without
    replacing the game's own stat calculation.
    """
    if len(original_entry) != NATIVE_HOOK_ENTRY_SIZE:
        raise ValueError("native result hook requires exactly 15 original bytes")
    if not math.isfinite(factor) or factor <= 0:
        raise ValueError("native result hook factor must be positive and finite")

    trampoline = int(cave) + NATIVE_HOOK_TRAMPOLINE_OFFSET
    data = int(cave) + NATIVE_HOOK_DATA_OFFSET
    code = bytearray()
    # The YYC signature has a fifth stack argument (the argument-array
    # pointer).  A wrapper must explicitly forward it; merely preserving the
    # four register arguments leaves the native routine reading our return
    # address as its argument array.
    code += b"\x48\x83\xec\x38"  # shadow + stack arg + locals, ABI aligned
    code += b"\x48\x8b\x44\x24\x60"  # mov rax, [rsp+60h] (incoming arg 5)
    code += b"\x48\x89\x44\x24\x20"  # mov [rsp+20h], rax (outgoing arg 5)
    code += b"\x4c\x89\x44\x24\x28"  # mov [rsp+28h], r8 (stable result pointer)
    code += b"\x48\xb8" + struct.pack("<Q", trampoline)
    code += b"\xff\xd0"  # call rax
    code += b"\x48\x8b\x54\x24\x28"  # mov rdx, [rsp+28h]
    code += b"\x48\x85\xd2"  # test rdx, rdx
    null_jump = len(code) + 1
    code += b"\x74\x00"  # je done
    code += b"\x83\x7a\x0c\x00"  # cmp dword ptr [rdx+0Ch], VALUE_REAL
    type_jump = len(code) + 1
    code += b"\x75\x00"  # jne done
    code += b"\x48\xb9" + struct.pack("<Q", data)  # mov rcx, data
    code += b"\xf2\x0f\x10\x02"  # movsd xmm0, [rdx]
    code += b"\xf2\x0f\x11\x01"  # movsd [rcx], xmm0 (native)
    code += b"\xf2\x0f\x59\x41\x18"  # mulsd xmm0, [rcx+18h] (factor)
    code += b"\xf2\x0f\x11\x02"  # movsd [rdx], xmm0 (scaled result)
    code += b"\xf2\x0f\x11\x41\x08"  # movsd [rcx+8], xmm0 (scaled mirror)
    code += b"\x48\xff\x41\x10"  # inc qword ptr [rcx+10h]
    done = len(code)
    code += b"\x48\x8b\x44\x24\x28"  # return the stable result pointer
    code += b"\x48\x83\xc4\x38\xc3"  # add rsp, 38h; ret
    for jump_index in (null_jump, type_jump):
        delta = done - (jump_index + 1)
        if not -128 <= delta <= 127:
            raise ValueError("native result hook branch is out of range")
        code[jump_index] = delta & 0xFF

    if len(code) >= NATIVE_HOOK_TRAMPOLINE_OFFSET:
        raise ValueError("native result hook overlaps its trampoline")
    blob = bytearray(NATIVE_HOOK_ALLOCATION_SIZE)
    blob[: len(code)] = code
    trampoline_raw = (
        bytes(original_entry)
        + b"\x48\xb8"
        + struct.pack("<Q", int(site) + NATIVE_HOOK_ENTRY_SIZE)
        + b"\xff\xe0"
    )
    start = NATIVE_HOOK_TRAMPOLINE_OFFSET
    blob[start : start + len(trampoline_raw)] = trampoline_raw
    struct.pack_into("<ddQd", blob, NATIVE_HOOK_DATA_OFFSET, 0.0, 0.0, 0, float(factor))
    return bytes(blob)


def build_native_result_epilogue_patch(cave: int, site: int) -> bytes:
    """Call a nearby result-scaling cave from the verified 7-byte epilogue load."""
    relative = int(cave) - (int(site) + 5)
    if not -(2**31) <= relative < 2**31:
        raise ValueError("native result epilogue cave is outside rel32 range")
    return b"\xe8" + struct.pack("<i", relative) + b"\x90\x90"


def build_native_result_epilogue_blob(
    cave: int,
    original_result_load: bytes,
    factor: float,
) -> bytes:
    """Scale the final native real RValue without wrapping the YYC function.

    The patched epilogue first reloads the native result pointer into RAX. The
    cave reproduces that instruction, multiplies a real result in place, then
    returns to the untouched register-restore sequence. This avoids replacing
    the calculation with a constant and avoids calling through GameMaker's ABI.
    """
    if len(original_result_load) != NATIVE_EPILOGUE_PATCH_SIZE:
        raise ValueError("native result epilogue requires one 7-byte result load")
    if original_result_load[:3] != b"\x48\x8b\x85":
        raise ValueError("native result epilogue load is not MOV RAX,[RBP+disp32]")
    if not math.isfinite(factor) or factor <= 0:
        raise ValueError("native result epilogue factor must be positive and finite")

    data = int(cave) + NATIVE_HOOK_DATA_OFFSET
    code = bytearray(original_result_load)
    code += b"\x48\x85\xc0"  # test rax, rax
    null_jump = len(code) + 1
    code += b"\x74\x00"  # je done
    code += b"\x83\x78\x0c\x00"  # cmp dword ptr [rax+0Ch], VALUE_REAL
    type_jump = len(code) + 1
    code += b"\x75\x00"  # jne done
    code += b"\x48\xb9" + struct.pack("<Q", data)  # mov rcx, data
    code += b"\xf2\x0f\x10\x00"  # movsd xmm0, [rax]
    code += b"\xf2\x0f\x11\x01"  # movsd [rcx], xmm0 (native)
    code += b"\xf2\x0f\x59\x41\x18"  # mulsd xmm0, [rcx+18h] (factor)
    code += b"\xf2\x0f\x11\x00"  # movsd [rax], xmm0 (scaled result)
    code += b"\xf2\x0f\x11\x41\x08"  # movsd [rcx+8], xmm0 (scaled mirror)
    code += b"\x48\xff\x41\x10"  # inc qword ptr [rcx+10h]
    done = len(code)
    code += b"\xc3"
    for jump_index in (null_jump, type_jump):
        delta = done - (jump_index + 1)
        if not -128 <= delta <= 127:
            raise ValueError("native result epilogue branch is out of range")
        code[jump_index] = delta & 0xFF

    if len(code) >= NATIVE_HOOK_DATA_OFFSET:
        raise ValueError("native result epilogue code overlaps its data")
    blob = bytearray(NATIVE_HOOK_ALLOCATION_SIZE)
    blob[:len(code)] = code
    struct.pack_into("<ddQd", blob, NATIVE_HOOK_DATA_OFFSET, 0.0, 0.0, 0, float(factor))
    return bytes(blob)


class StatForgeMultiplier(core.StatForge):
    @staticmethod
    def _build_s10_stat_return_patch(value: float):
        """Return a numeric GameMaker RValue (VALUE_REAL=0), not a bool."""
        value_bits = struct.unpack("<Q", struct.pack("<d", float(value)))[0]
        return b"\x48\xb8" + struct.pack("<Q", value_bits) + S10_REAL_RETURN_PATCH_TAIL

    @staticmethod
    def _is_owned_s10_stat_return_patch(raw: bytes):
        if len(raw) != 10 + len(S10_REAL_RETURN_PATCH_TAIL):
            return False
        if raw[:2] != b"\x48\xb8" or raw[10:] != S10_REAL_RETURN_PATCH_TAIL:
            return False
        return math.isfinite(struct.unpack("<d", raw[2:10])[0])

    def __init__(self):
        # Tk widgets may only be touched by the main thread.  The base class
        # starts the monitor thread during __init__, so create the queue first.
        self._ui_updates: queue.SimpleQueue[tuple[str, str]] = queue.SimpleQueue()
        self._native_hook_reserve: dict[str, dict] = {}
        self._native_hook_pid: int | None = None
        self._set_variable_hook: dict | None = None
        self._set_variable_hook_pid: int | None = None
        super().__init__()
        self.details.set(
            "Verified Season 10 routes only: Magic Find, Movement Speed, All Skills and EXP."
        )
        self.root.after(100, self._drain_ui_updates)

    def _drain_ui_updates(self):
        """Apply monitor-thread text updates exclusively on Tk's main thread."""
        try:
            while True:
                key, text = self._ui_updates.get_nowait()
                current_var = self.stat_current_vars.get(key)
                if current_var:
                    current_var.set(text)
        except queue.Empty:
            pass
        try:
            self.root.after(100, self._drain_ui_updates)
        except Exception:
            pass

    def refresh_status(self):
        """Refresh visual state without resolving every inactive code route."""
        for binding in self.stat_bindings:
            if binding.key not in self.stat_buttons:
                continue
            is_on = binding.key in self.active_stat_keys
            self._configure_stat_toggle(binding, is_on)
            if not is_on:
                current_var = self.stat_current_vars.get(binding.key)
                if current_var:
                    current_var.set("Current: native")
        self._set_active_text()
        self._sync_status_indicator()

    def log_line(self, text: str):
        super().log_line(text)
        try:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log_path = os.path.join(core.runtime_app_dir(), "hs_statforge_multiplier.log")
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(f"[{stamp}] {text}\n")
        except Exception:
            pass

    def _replace_ui_copy(self, parent, replacements: dict[str, str]):
        for child in parent.winfo_children():
            try:
                current = str(child.cget("text"))
            except Exception:
                current = ""
            if current in replacements:
                child.configure(text=replacements[current])
            self._replace_ui_copy(child, replacements)

    def _build_ui(self):
        super()._build_ui()
        self._replace_ui_copy(
            self.root,
            {
                "OFFLINE STAT FORGE": "STAT FORGE MULTIPLIER",
                "RUNTIME STAT LAB": "NATIVE MULTIPLIER LAB",
                "v2.1  •  MEMORY ONLY": "v1.2.0 ADAPTIVE  •  MEMORY ONLY",
                "Attach to Hero Siege and manage reversible runtime overrides.":
                    "Attach to Hero Siege and multiply its live native stat values.",
                "STAT VAULT": "MULTIPLIER VAULT",
                "Season 10 native stat routes • choose a value, then forge the override.":
                    "Only live-verified Season 10 protected routes are available.",
                (
                    "OFFLINE ONLY  •  Season 10 verified toggles override native runtime results until Restore All, "
                    "the app closes, or the game closes. Game files on disk are never modified. Unsafe legacy Season 9 "
                    "routes remain intentionally unavailable."
                ): (
                    "OFFLINE ONLY  •  Magic Find and Movement Speed multiply every fresh native value; All Skills "
                    "sets a target up to 200 and EXP uses its verified final-factor route. Equipment, buffs and zone "
                    "changes are tracked automatically. Restore All returns every route to native state."
                ),
            },
        )

    def _render_stat_buttons(self):
        super()._render_stat_buttons()
        for key, card in self.stat_cards.items():
            if key == "all_skills":
                label = "TARGET VALUE"
            elif key == "total_damage_bonus":
                label = "BONUS PERCENT"
            else:
                label = "MULTIPLIER"
            self._replace_ui_copy(card, {"FORGE VALUE": label})

    @staticmethod
    def _is_multiplier_binding(binding: core.StatBinding) -> bool:
        return bool(
            binding.resolver
            and str(binding.resolver.get("kind") or "").lower() == MULTIPLIER_KIND
        )

    @staticmethod
    def _is_direct_value_binding(binding: core.StatBinding) -> bool:
        return bool(
            binding.resolver
            and str(binding.resolver.get("kind") or "").lower() == VALUE_KIND
        )

    @staticmethod
    def _is_native_result_binding(binding: core.StatBinding) -> bool:
        return bool(
            binding.resolver
            and str(binding.resolver.get("kind") or "").lower() == NATIVE_RESULT_KIND
        )

    def _is_ac_dll_table_binding(self, binding: core.StatBinding):
        return (
            self._is_multiplier_binding(binding)
            or self._is_direct_value_binding(binding)
            or super()._is_ac_dll_table_binding(binding)
        )

    @staticmethod
    def _values_close(left: float, right: float) -> bool:
        return math.isclose(float(left), float(right), rel_tol=1e-10, abs_tol=1e-10)

    def _module_sha256(self, module: dict) -> str:
        path = str(module.get("path") or "")
        if not path or not os.path.exists(path):
            raise RuntimeError("Hero_Siege.exe module path is unavailable")
        stat = os.stat(path)
        cache_key = f"{os.path.normcase(os.path.abspath(path))}|{stat.st_size}|{stat.st_mtime_ns}"
        actual = self.verified_module_hashes.get(cache_key)
        if actual is None:
            digest = core.hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            actual = digest.hexdigest().lower()
            self.verified_module_hashes[cache_key] = actual
        return actual

    def _resolve_s10_stat_return_site(self, binding: core.StatBinding):
        resolver = dict(binding.resolver or {})
        function_module = str(resolver.get("function_module") or core.PROCESS_NAME)
        function_resolver = dict(resolver)
        function_resolver["module"] = function_module
        function_binding = core.StatBinding.from_dict(binding.to_dict())
        function_binding.resolver = function_resolver
        try:
            return super()._resolve_s10_stat_return_site(function_binding)
        except RuntimeError as adaptive_error:
            module = self._hero_module(function_module)
            if not module:
                raise adaptive_error
            function_name = str(resolver.get("function_name") or "").strip()
            actual_hash = self._module_sha256(module)
            rva = VERIFIED_STAT_RVAS.get(actual_hash, {}).get(function_name)
            if rva is None:
                raise adaptive_error
            site = int(module["base"]) + int(rva)
            patch_size = len(self._build_s10_stat_return_patch(0.0))
            original = self._original_module_bytes(module, site, patch_size)
            if len(original) != patch_size or not self._is_supported_s10_stat_entry(original):
                raise RuntimeError(
                    f"{binding.name}: verified-build fallback entry failed structure validation"
                ) from adaptive_error
            live = self._read_raw(site, patch_size)
            if live != original and not self._is_owned_s10_stat_return_patch(live):
                raise RuntimeError(
                    f"{binding.name}: verified-build fallback entry contains an unknown patch"
                ) from adaptive_error
            if hasattr(self, "log"):
                self.log_line(
                    f"{binding.name}: exact build fallback {actual_hash[:12]} "
                    f"{function_name} RVA=0x{int(rva):x}"
                )
            return module, site, original

    def _resolve_native_result_epilogue_site(self, binding: core.StatBinding):
        """Locate the common final `MOV RAX,[RBP+result]` before the YYC return."""
        resolver = dict(binding.resolver or {})
        module_name = str(resolver.get("function_module") or core.PROCESS_NAME)
        module = self._hero_module(module_name)
        if not module:
            raise RuntimeError(f"{module_name} is not loaded")
        functions = self._discover_function_addresses(module)
        function_name = str(resolver.get("function_name") or "").strip()
        function_address = functions.get(function_name)
        if not function_address:
            raise RuntimeError(f"{function_name} was not found in the S10 runtime table")
        extent = self._function_extent(function_address, list(functions.values()))
        code = self._read_module_file_bytes(
            module,
            function_address - int(module["base"]),
            extent,
        )
        candidates = []
        for offset in range(max(0, len(code) - 0x200), max(0, len(code) - 14)):
            original = code[offset:offset + NATIVE_EPILOGUE_PATCH_SIZE]
            if original[:3] != b"\x48\x8b\x85":
                continue
            if code[offset + 7:offset + 11] != b"\x0f\x28\xb4\x24":
                continue
            # Both verified S10 layouts restore XMM6, unwind the frame and
            # return immediately after this result-pointer load.
            tail = code[offset + 7:offset + 0x60]
            if b"\x48\x81\xc4" not in tail or b"\x5b\x5d\xc3" not in tail:
                continue
            candidates.append((function_address + offset, original))
        if len(candidates) != 1:
            raise RuntimeError(
                f"{binding.name}: expected one native result epilogue, found {len(candidates)}"
            )
        site, original = candidates[0]
        live = self._read_raw(site, len(original))
        if live != original and not (
            len(live) == NATIVE_EPILOGUE_PATCH_SIZE
            and live[:1] == b"\xe8"
            and live[5:] == b"\x90\x90"
        ):
            raise RuntimeError(f"{binding.name}: native result epilogue contains an unknown patch")
        return module, site, original

    def attach_to_process(self, process):
        previous_pid = self._native_hook_pid
        previous_set_variable_pid = self._set_variable_hook_pid
        attached = super().attach_to_process(process)
        if attached:
            current_pid = int(self.pm.process_id)
            if previous_pid != current_pid:
                # Remote allocations belong to one process lifetime.  A dead
                # process releases them itself; never reuse their addresses.
                self._native_hook_reserve.clear()
            self._native_hook_pid = current_pid
            if previous_set_variable_pid != current_pid:
                self._set_variable_hook = None
            self._set_variable_hook_pid = current_pid
        return attached

    @staticmethod
    def _native_result_factor(binding: core.StatBinding, value_text: str) -> tuple[float, float]:
        resolver = binding.resolver or {}
        entered = float(core.parse_value(value_text, binding.type_name))
        if not math.isfinite(entered):
            raise RuntimeError("Value must be finite")
        max_value = float(resolver.get("max", binding.slider_max))
        mode = str(resolver.get("input_mode") or "factor").lower()
        if mode == "bonus_percent":
            if entered < 0:
                raise RuntimeError("Damage bonus percentage must be zero or greater")
            entered = min(entered, max_value)
            factor = 1.0 + entered / 100.0
        else:
            if entered <= 0:
                raise RuntimeError("Multiplier must be greater than zero")
            entered = min(entered, max_value)
            factor = entered
        if not math.isfinite(factor) or factor <= 0:
            raise RuntimeError("Calculated multiplier is invalid")
        return entered, factor

    def _write_entry_when_quiescent(self, site: int, raw: bytes, attempts: int = 250):
        """Write an entry patch only while no game thread executes that entry."""
        rights = (
            scan.THREAD_GET_CONTEXT
            | scan.THREAD_SUSPEND_RESUME
            | scan.THREAD_QUERY_INFORMATION
        )
        region_start = int(site)
        region_end = region_start + max(NATIVE_HOOK_ENTRY_SIZE, len(raw))
        for _attempt in range(attempts):
            handles = []
            busy = False
            try:
                for thread_id in core.list_threads(self.pm.process_id):
                    handle = core.kernel32.OpenThread(rights, False, int(thread_id))
                    if not handle:
                        continue
                    if core.kernel32.SuspendThread(handle) == 0xFFFFFFFF:
                        core.kernel32.CloseHandle(handle)
                        continue
                    handles.append(handle)
                    context = scan.CONTEXT()
                    context.ContextFlags = scan.CONTEXT_CONTROL
                    if not core.kernel32.GetThreadContext(handle, ctypes.byref(context)):
                        continue
                    if region_start <= int(context.Rip) < region_end:
                        busy = True
                if not busy:
                    self._write_memory(region_start, bytes(raw))
                    return
            finally:
                self._resume_game_threads(handles)
            time.sleep(0.002)
        raise RuntimeError(
            "Native function remained busy; no patch was applied. Pause in town and try again."
        )

    def _enable_native_result_multiplier(self, binding: core.StatBinding, value_text: str):
        entered, factor = self._native_result_factor(binding, value_text)
        with self.runtime_cache_lock:
            _module, site, original = self._resolve_native_result_epilogue_site(binding)
            current = self._read_raw(site, NATIVE_EPILOGUE_PATCH_SIZE)
            if current != original:
                raise RuntimeError(f"{binding.name}: native result epilogue is not clean; no write was made")

            # The seven-byte epilogue site supports a rel32 CALL. Allocate a
            # fresh nearby page on every activation; disabled pages remain
            # unreachable until the game exits instead of being reused while
            # a just-finished call may still be leaving the cave.
            cave = self._alloc_near_sites(
                [site],
                NATIVE_HOOK_ALLOCATION_SIZE,
                instruction_size=5,
            )
            self._native_hook_reserve[binding.key] = {
                "pid": int(self.pm.process_id),
                "cave": cave,
            }
            blob = build_native_result_epilogue_blob(cave, original, factor)
            patch = build_native_result_epilogue_patch(cave, site)
            try:
                self._write_memory(cave, blob)
                self._write_entry_when_quiescent(site, patch)
                if self._read_raw(site, len(patch)) != patch:
                    raise RuntimeError(f"{binding.name}: native result hook verification failed")
            except Exception:
                # Restore the epilogue but deliberately retain the now
                # unreachable page.  Freeing executable memory while another
                # thread may have just entered it is less safe than one 4 KiB
                # allocation that the process will reclaim on exit.
                try:
                    self._write_entry_when_quiescent(site, original)
                except Exception:
                    pass
                raise

            payload = {
                "kind": NATIVE_RESULT_KIND,
                "sites": [int(site)],
                "originals": [original],
                "patches": [patch],
                "cave": cave,
                "data_address": cave + NATIVE_HOOK_DATA_OFFSET,
                "entered": float(entered),
                "factor": float(factor),
                "last_counter": 0,
                "input_mode": str((binding.resolver or {}).get("input_mode") or "factor"),
            }
            self.stat_multi_patches[binding.key] = payload
            self.active_stat_keys.add(binding.key)
            binding.default_write = str(int(entered) if entered.is_integer() else entered)
            self._save_bindings()

        self._ui_updates.put((binding.key, "Current: waiting for native calculation"))
        if payload["input_mode"] == "bonus_percent":
            summary = f"+{entered:g}% (native × {factor:g})"
        else:
            summary = f"native × {factor:g}"
        self.details.set(f"{binding.name}: {summary}. The next native stat calculation will be shown.")
        self.log_line(f"{binding.name}: ON | {summary} @ {hex(site)}")

    def _disable_native_result_multiplier(self, binding: core.StatBinding):
        with self.runtime_cache_lock:
            payload = self.stat_multi_patches.get(binding.key)
            if payload and payload.get("kind") == NATIVE_RESULT_KIND:
                site = int(payload["sites"][0])
                original = bytes(payload["originals"][0])
                patch = bytes(payload["patches"][0])
                current = self._read_raw(site, len(original))
                if current == patch:
                    self._write_entry_when_quiescent(site, original)
                elif current != original:
                    raise RuntimeError(f"{binding.name}: native result hook is no longer owned by Multiplier")
                if self._read_raw(site, len(original)) != original:
                    raise RuntimeError(f"{binding.name}: native result epilogue restore verification failed")
            self.stat_multi_patches.pop(binding.key, None)
            self.active_stat_keys.discard(binding.key)
        self._ui_updates.put((binding.key, "Current: native"))
        self.details.set(f"{binding.name}: native calculation restored.")
        self.log_line(f"{binding.name}: OFF | native result hook restored.")

    def _refresh_native_result_multiplier(self, key: str, payload: dict):
        binding = self._find_binding(key)
        if not binding:
            return
        site = int(payload["sites"][0])
        original = bytes(payload["originals"][0])
        patch = bytes(payload["patches"][0])
        current = self._read_raw(site, len(patch))
        if current != patch:
            if current == original:
                raise RuntimeError(f"{binding.name}: native result hook was externally restored")
            raise RuntimeError(f"{binding.name}: native result epilogue contains an unknown patch")

        raw = self._read_raw(int(payload["data_address"]), 24)
        native, scaled, counter = struct.unpack("<ddQ", raw)
        if not counter or counter == int(payload.get("last_counter", 0)):
            return
        payload["last_counter"] = int(counter)
        if not (math.isfinite(native) and math.isfinite(scaled)):
            return
        if payload.get("input_mode") == "bonus_percent":
            text = f"Current: {native:g} + {payload['entered']:g}% = {scaled:g}"
        else:
            text = f"Current: {native:g} × {payload['factor']:g} = {scaled:g}"
        self._ui_updates.put((key, text))

    def _enable_stat(self, binding: core.StatBinding):
        if not self._is_native_result_binding(binding):
            return super()._enable_stat(binding)
        if not self._require():
            return
        value_var = self.stat_value_vars.get(binding.key)
        value_text = value_var.get().strip() if value_var else ""
        if not value_text:
            self.log_line(f"{binding.name}: enter a value first.")
            return
        try:
            self._enable_native_result_multiplier(binding, value_text)
        except Exception as exc:
            self.details.set(f"{binding.name}: failed - {exc}")
            self.log_line(f"{binding.name}: enable failed: {exc}")

    def _disable_stat(self, binding: core.StatBinding):
        if not self._is_native_result_binding(binding):
            return super()._disable_stat(binding)
        if not self._require():
            return
        try:
            self._disable_native_result_multiplier(binding)
        except Exception as exc:
            self.details.set(f"{binding.name}: restore failed - {exc}")
            self.log_line(f"{binding.name}: disable failed: {exc}")

    def _write_when_regions_quiescent(
        self,
        site: int,
        raw: bytes,
        regions: list[tuple[int, int]],
        attempts: int = 500,
    ):
        """Patch one entry only while no game thread is in owned hook code."""
        rights = (
            scan.THREAD_GET_CONTEXT
            | scan.THREAD_SUSPEND_RESUME
            | scan.THREAD_QUERY_INFORMATION
        )
        for _attempt in range(attempts):
            handles = []
            busy = False
            try:
                for thread_id in core.list_threads(self.pm.process_id):
                    handle = core.kernel32.OpenThread(rights, False, int(thread_id))
                    if not handle:
                        busy = True
                        continue
                    if core.kernel32.SuspendThread(handle) == 0xFFFFFFFF:
                        core.kernel32.CloseHandle(handle)
                        busy = True
                        continue
                    handles.append(handle)
                    context = scan.CONTEXT()
                    context.ContextFlags = scan.CONTEXT_CONTROL
                    if not core.kernel32.GetThreadContext(handle, ctypes.byref(context)):
                        busy = True
                        continue
                    rip = int(context.Rip)
                    if any(start <= rip < end for start, end in regions):
                        busy = True
                if not busy:
                    self._write_memory(int(site), bytes(raw))
                    return
            finally:
                self._resume_game_threads(handles)
            time.sleep(0.002)
        raise RuntimeError("SetVariable remained busy; no entry bytes were changed")

    def _resolve_set_variable_hook_site(self, binding: core.StatBinding):
        resolver = binding.resolver or {}
        module_name = str(resolver.get("module") or "ac_dll_gm.dll")
        module = self._hero_module(module_name)
        if not module:
            raise RuntimeError(f"{module_name} is not loaded")
        self._verify_module_fingerprint(
            module,
            resolver.get("module_sha256"),
            binding.name,
        )
        site = int(module["base"]) + SET_VARIABLE_RVA
        original = self._original_module_bytes(
            module,
            site,
            SET_VARIABLE_HOOK_ENTRY_SIZE,
        )
        if original != SET_VARIABLE_ORIGINAL_ENTRY:
            raise RuntimeError(
                f"{binding.name}: SetVariable prologue does not match the verified layout"
            )
        return module, site, original

    def _ensure_set_variable_hook(self, binding: core.StatBinding):
        current_pid = int(self.pm.process_id)
        payload = self._set_variable_hook
        if payload and self._set_variable_hook_pid == current_pid:
            current = self._read_raw(int(payload["site"]), len(payload["patch"]))
            if current != payload["patch"]:
                raise RuntimeError(
                    f"{binding.name}: shared SetVariable hook was changed by another tool"
                )
            return payload

        _module, site, original = self._resolve_set_variable_hook_site(binding)
        current = self._read_raw(site, len(original))
        if current != original:
            raise RuntimeError(
                f"{binding.name}: SetVariable entry is not clean; Restore All in other tools first"
            )
        cave = self._alloc_near_sites(
            [site],
            SET_VARIABLE_HOOK_ALLOCATION_SIZE,
            instruction_size=5,
        )
        blob = build_set_variable_hook_blob(cave, site, original)
        patch = build_set_variable_hook_patch(cave)
        try:
            self._write_memory(cave, blob)
            self._write_when_regions_quiescent(
                site,
                patch,
                [(site, site + SET_VARIABLE_HOOK_ENTRY_SIZE)],
            )
            if self._read_raw(site, len(patch)) != patch:
                raise RuntimeError("shared SetVariable hook verification failed")
        except Exception:
            try:
                self._write_when_regions_quiescent(
                    site,
                    original,
                    [(site, site + SET_VARIABLE_HOOK_ENTRY_SIZE)],
                )
            except Exception:
                pass
            raise
        payload = {
            "site": int(site),
            "original": bytes(original),
            "patch": bytes(patch),
            "cave": int(cave),
            "data": int(cave) + SET_VARIABLE_HOOK_DATA_OFFSET,
        }
        self._set_variable_hook = payload
        self._set_variable_hook_pid = current_pid
        return payload

    def _set_variable_slot(self, key: str) -> tuple[dict, dict]:
        slot = SET_VARIABLE_SLOTS.get(key)
        payload = self._set_variable_hook
        if not slot or not payload:
            raise RuntimeError(f"{key}: shared SetVariable slot is unavailable")
        return payload, slot

    def _configure_set_variable_slot(self, key: str, factor: float, enabled: bool):
        payload, slot = self._set_variable_slot(key)
        data = int(payload["data"])
        enabled_address = data + int(slot["enabled"])
        factor_address = data + int(slot["factor"])
        # Disable first; enable only after the complete factor is visible.
        if not enabled:
            self._write_memory(enabled_address, struct.pack("<Q", 0))
        self._write_memory(factor_address, struct.pack("<d", float(factor)))
        if enabled:
            self._write_memory(enabled_address, struct.pack("<Q", 1))
        observed_factor = struct.unpack("<d", self._read_raw(factor_address, 8))[0]
        observed_enabled = struct.unpack("<Q", self._read_raw(enabled_address, 8))[0]
        if not self._values_close(observed_factor, factor) or bool(observed_enabled) != bool(enabled):
            raise RuntimeError(f"{key}: SetVariable slot verification failed")

    def _read_set_variable_slot(self, key: str):
        payload, slot = self._set_variable_slot(key)
        data = int(payload["data"])
        factor = struct.unpack("<d", self._read_raw(data + int(slot["factor"]), 8))[0]
        native = struct.unpack("<d", self._read_raw(data + int(slot["native"]), 8))[0]
        scaled = struct.unpack("<d", self._read_raw(data + int(slot["scaled"]), 8))[0]
        counter = struct.unpack("<Q", self._read_raw(data + int(slot["counter"]), 8))[0]
        enabled = struct.unpack("<Q", self._read_raw(data + int(slot["enabled"]), 8))[0]
        return {
            "factor": float(factor),
            "native": float(native),
            "scaled": float(scaled),
            "counter": int(counter),
            "enabled": bool(enabled),
        }

    def _restore_set_variable_hook_if_unused(self):
        if any(
            payload.get("kind") == MULTIPLIER_KIND
            for payload in self.stat_multi_patches.values()
        ):
            return
        payload = self._set_variable_hook
        if not payload:
            return
        for key in SET_VARIABLE_SLOTS:
            self._configure_set_variable_slot(key, 1.0, False)
        site = int(payload["site"])
        original = bytes(payload["original"])
        patch = bytes(payload["patch"])
        current = self._read_raw(site, len(patch))
        if current == patch:
            cave = int(payload["cave"])
            self._write_when_regions_quiescent(
                site,
                original,
                [
                    (site, site + SET_VARIABLE_HOOK_ENTRY_SIZE),
                    (cave, cave + SET_VARIABLE_HOOK_DATA_OFFSET),
                ],
            )
        elif current != original:
            raise RuntimeError("shared SetVariable hook is no longer owned by Multiplier")
        if self._read_raw(site, len(original)) != original:
            raise RuntimeError("shared SetVariable hook restore verification failed")
        # Keep the allocation reserved and unreachable until the game exits.
        self._set_variable_hook = None

    def _protected_snapshot(self, binding: core.StatBinding, entry: int | None = None):
        resolver = binding.resolver or {}
        xor_offset = self._parse_int_setting(
            resolver.get("value_xor_offset", core.AC_DLL_VALUE_XOR_OFFSET),
            "value_xor_offset",
        )
        integrity_offset = self._parse_int_setting(
            resolver.get("integrity_offset", core.AC_DLL_INTEGRITY_OFFSET),
            "integrity_offset",
        )
        undefined_offset = self._parse_int_setting(
            resolver.get("undefined_offset", core.AC_DLL_UNDEFINED_OFFSET),
            "undefined_offset",
        )
        if entry is None:
            entry, _value_address = self._resolve_ac_dll_table_entry(binding, resolver)
        value_address = core.read_ptr(self.pm.process_handle, entry)
        if not value_address:
            raise RuntimeError(f"{binding.name}: protected value is not available in this zone")
        undefined = self._read_raw(entry + undefined_offset, 1)[0]
        if undefined:
            raise RuntimeError(f"{binding.name}: protected value is undefined")
        encrypted_raw = self._read_raw(value_address, 8)
        xor_raw = self._read_raw(entry + xor_offset, 8)
        integrity_raw = self._read_raw(entry + integrity_offset, 8)
        encrypted = struct.unpack("<Q", encrypted_raw)[0]
        xor_key = struct.unpack("<Q", xor_raw)[0]
        stored_integrity = struct.unpack("<Q", integrity_raw)[0]
        value_bits = encrypted ^ xor_key
        expected_integrity = self._s10_integrity_value(value_bits, xor_key)
        if stored_integrity != expected_integrity:
            raise RuntimeError(f"{binding.name}: protected value changed during snapshot")
        value = struct.unpack("<d", struct.pack("<Q", value_bits))[0]
        if not math.isfinite(value):
            raise RuntimeError(f"{binding.name}: native value is not finite")
        return {
            "entry": int(entry),
            "value_address": int(value_address),
            "value": float(value),
            "xor_key": int(xor_key),
            "encrypted_raw": encrypted_raw,
            "integrity_raw": integrity_raw,
            "undefined_raw": bytes([undefined]),
            "integrity_offset": int(integrity_offset),
            "undefined_offset": int(undefined_offset),
        }

    def _write_protected_value(self, binding: core.StatBinding, snapshot: dict, value: float):
        if not math.isfinite(value):
            raise RuntimeError(f"{binding.name}: scaled value is not finite")
        value_bits = struct.unpack("<Q", struct.pack("<d", float(value)))[0]
        xor_key = int(snapshot["xor_key"])
        encrypted_raw = struct.pack("<Q", value_bits ^ xor_key)
        integrity_raw = struct.pack("<Q", self._s10_integrity_value(value_bits, xor_key))
        value_address = int(snapshot["value_address"])
        integrity_address = int(snapshot["entry"]) + int(snapshot["integrity_offset"])
        undefined_address = int(snapshot["entry"]) + int(snapshot["undefined_offset"])
        # This table provides an explicit undefined byte for coherent updates.
        # Mark the value unavailable while its two protected words are changed;
        # this avoids suspending every game thread from the Tk UI callback.
        try:
            self._write_memory(undefined_address, b"\x01")
            self._write_memory(value_address, encrypted_raw)
            self._write_memory(integrity_address, integrity_raw)
            self._write_memory(undefined_address, b"\x00")
        except Exception:
            # Best-effort rollback keeps the entry readable even if one write
            # fails.  These originals came from one integrity-verified snapshot.
            try:
                self._write_memory(value_address, bytes(snapshot["encrypted_raw"]))
                self._write_memory(integrity_address, bytes(snapshot["integrity_raw"]))
                self._write_memory(undefined_address, bytes(snapshot["undefined_raw"]))
            except Exception:
                pass
            raise
        confirmed = self._protected_snapshot(binding, int(snapshot["entry"]))
        if not self._values_close(confirmed["value"], value):
            raise RuntimeError(
                f"{binding.name}: multiplier verification failed "
                f"({confirmed['value']!r} != {value!r})"
            )
        return confirmed

    def _apply_gameplay_return(self, binding: core.StatBinding, value: float, payload: dict | None = None):
        _module, site, original = self._resolve_s10_stat_return_site(binding)
        patch = self._build_s10_stat_return_patch(value)
        current = self._read_raw(site, len(original))
        if payload is None:
            if current != original and not self._is_owned_s10_stat_return_patch(current):
                raise RuntimeError(
                    f"{binding.name}: another StatForge return override is active; Restore All there first"
                )
            if current != original:
                self.log_line(f"{binding.name}: recovered a stale Multiplier return patch.")
                if current == patch:
                    return {
                        "return_site": int(site),
                        "return_original": bytes(original),
                        "return_patch": bytes(patch),
                    }
        else:
            previous_patch = payload.get("return_patch")
            if current not in (original, previous_patch):
                raise RuntimeError(f"{binding.name}: gameplay return site was changed by another tool")
            # Native stat-table recalculation does not remove this function
            # patch.  Avoid suspending every game thread just to rewrite bytes
            # that are already correct; doing so repeatedly caused the GUI to
            # block on runtime_cache_lock while combat was active.
            if current == patch:
                return {
                    "return_site": int(site),
                    "return_original": bytes(original),
                    "return_patch": bytes(patch),
                }
        self._write_patch_group([site], [patch])
        if self._read_raw(site, len(patch)) != patch:
            self._write_patch_group([site], [original])
            raise RuntimeError(f"{binding.name}: gameplay return verification failed")
        return {
            "return_site": int(site),
            "return_original": bytes(original),
            "return_patch": bytes(patch),
        }

    def _restore_gameplay_return(self, binding: core.StatBinding, payload: dict):
        site = payload.get("return_site")
        original = payload.get("return_original")
        patch = payload.get("return_patch")
        if not site or not original:
            return
        current = self._read_raw(int(site), len(original))
        if patch is not None and current == patch:
            self._write_patch_group([int(site)], [bytes(original)])
        elif current != original:
            raise RuntimeError(f"{binding.name}: gameplay return site is no longer owned by Multiplier")

    def _ensure_gameplay_return(self, binding: core.StatBinding, payload: dict):
        site = payload.get("return_site")
        patch = payload.get("return_patch")
        original = payload.get("return_original")
        if not site or not patch:
            return
        current = self._read_raw(int(site), len(patch))
        if current == patch:
            return
        if current == original:
            self._write_patch_group([int(site)], [bytes(patch)])
            return
        raise RuntimeError(f"{binding.name}: gameplay return site contains an unknown patch")

    def _settled_snapshot(self, binding: core.StatBinding, entry: int | None = None):
        """Snapshot the native value only once it has stopped moving.

        The protected cell is populated in stages while a character loads: it is
        first empty, then holds a partial value, and only later the real stat.
        Measured on 7.0.30 with Movement Speed: the cell read 25 mid-load while
        gml_Script_StatMovementSpeed was returning 200 once loaded.  Snapshotting
        during that window captured 25 as the "native", multiplied THAT, and wrote
        the product back over the cell - which destroys the real value and freezes
        the wrong base, because the refresh loop then only ever sees its own write.

        So we require two identical reads before trusting the value, and refuse a
        zero, which is what the cell reads at the main menu.
        """
        last = None
        for attempt in range(8):
            snapshot = self._protected_snapshot(binding, entry)
            value = float(snapshot["value"])
            if value != 0.0 and last is not None and abs(value - last) < 1e-9:
                return snapshot
            last = value
            time.sleep(0.15)
        if last == 0.0:
            raise RuntimeError(
                f"{binding.name}: the game reports 0 for this stat right now. "
                "Enter the game with a character first, then enable it."
            )
        raise RuntimeError(
            f"{binding.name}: the value is still changing ({last:g}). "
            "Wait until the character has finished loading, then try again."
        )

    def _set_multiplier_current_text(self, binding: core.StatBinding, native: float, scaled: float, factor: float):
        self._ui_updates.put((binding.key, f"Current: {native:g} × {factor:g} = {scaled:g}"))

    def _enable_s10_ac_stat(self, binding: core.StatBinding, value_text: str):
        if self._is_direct_value_binding(binding):
            return self._enable_s10_direct_value(binding, value_text)
        if not self._is_multiplier_binding(binding):
            return super()._enable_s10_ac_stat(binding, value_text)
        factor = float(core.parse_value(value_text, binding.type_name))
        if not math.isfinite(factor) or factor <= 0:
            raise RuntimeError("Multiplier must be greater than zero")
        resolver = binding.resolver or {}
        if "max" in resolver:
            factor = min(factor, float(resolver["max"]))
        with self.runtime_cache_lock:
            snapshot = self._settled_snapshot(binding)
            native = float(snapshot["value"])
            scaled = native * factor
            self._ensure_set_variable_hook(binding)
            self._configure_set_variable_slot(binding.key, factor, True)
            try:
                confirmed = self._write_protected_value(binding, snapshot, scaled)
            except Exception:
                self._configure_set_variable_slot(binding.key, 1.0, False)
                self._restore_set_variable_hook_if_unused()
                raise
            telemetry = self._read_set_variable_slot(binding.key)
            payload = {
                "kind": MULTIPLIER_KIND,
                "entry": int(snapshot["entry"]),
                "value_address": int(confirmed["value_address"]),
                "factor": float(factor),
                "last_native": native,
                "last_written": scaled,
                "last_counter": int(telemetry["counter"]),
            }
            self.stat_multi_patches[binding.key] = payload
            binding.default_write = str(int(factor) if factor.is_integer() else factor)
            self.active_stat_keys.add(binding.key)
            self._save_bindings()
        self._set_multiplier_current_text(binding, native, scaled, factor)
        self.details.set(
            f"{binding.name}: native {native:g} × {factor:g} = {scaled:g}. "
            "Equipment and zone recalculations will be tracked."
        )
        self.log_line(
            f"{binding.name}: ON | native {native:g} × {factor:g} = {scaled:g} "
            f"@ {hex(int(confirmed['value_address']))}"
        )

    def _enable_s10_direct_value(self, binding: core.StatBinding, value_text: str):
        target = float(core.parse_value(value_text, binding.type_name))
        if not math.isfinite(target) or target < 0:
            raise RuntimeError("Target value must be zero or greater")
        resolver = binding.resolver or {}
        if "max" in resolver:
            target = min(target, float(resolver["max"]))
        with self.runtime_cache_lock:
            snapshot = self._protected_snapshot(binding)
            native = float(snapshot["value"])
            return_payload = self._apply_gameplay_return(binding, target)
            try:
                confirmed = self._write_protected_value(binding, snapshot, target)
            except Exception:
                self._restore_gameplay_return(binding, return_payload)
                raise
            payload = {
                "kind": VALUE_KIND,
                "entry": int(snapshot["entry"]),
                "value_address": int(confirmed["value_address"]),
                "target": target,
                "last_native": native,
                "last_written": target,
            }
            payload.update(return_payload)
            self.stat_multi_patches[binding.key] = payload
            binding.default_write = str(int(target) if target.is_integer() else target)
            self.active_stat_keys.add(binding.key)
            self._save_bindings()
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set(f"Current: {native:g} → {target:g}")
        self.details.set(f"{binding.name}: native {native:g} → target {target:g}.")
        self.log_line(
            f"{binding.name}: ON | native {native:g} -> target {target:g} "
            f"@ {hex(int(confirmed['value_address']))}"
        )

    def _disable_s10_ac_stat(self, binding: core.StatBinding):
        if not (self._is_multiplier_binding(binding) or self._is_direct_value_binding(binding)):
            return super()._disable_s10_ac_stat(binding)
        return self._disable_tracked_table_value(binding)

    def _disable_tracked_table_value(self, binding: core.StatBinding):
        restored = None
        with self.runtime_cache_lock:
            payload = self.stat_multi_patches.get(binding.key)
            if payload and payload.get("kind") in {MULTIPLIER_KIND, VALUE_KIND}:
                telemetry = None
                if payload.get("kind") == MULTIPLIER_KIND and self._set_variable_hook:
                    try:
                        telemetry = self._read_set_variable_slot(binding.key)
                    except Exception:
                        telemetry = None
                    self._configure_set_variable_slot(binding.key, 1.0, False)
                try:
                    snapshot = self._protected_snapshot(binding, int(payload["entry"]))
                    same_slot = int(snapshot["value_address"]) == int(payload.get("value_address", 0))
                    last_scaled = (
                        float(telemetry["scaled"])
                        if telemetry and int(telemetry["counter"]) > 0
                        else float(payload["last_written"])
                    )
                    last_native = (
                        float(telemetry["native"])
                        if telemetry and int(telemetry["counter"]) > 0
                        else float(payload["last_native"])
                    )
                    still_ours = self._values_close(snapshot["value"], last_scaled)
                    if still_ours and (same_slot or telemetry is not None):
                        restored = last_native
                        self._write_protected_value(binding, snapshot, restored)
                except Exception:
                    # If the game has already rebuilt/removed the protected
                    # value, do not write a stale value into a new zone.
                    restored = None
            self.stat_multi_patches.pop(binding.key, None)
            self.active_stat_keys.discard(binding.key)
            if payload and payload.get("kind") == MULTIPLIER_KIND:
                self._restore_set_variable_hook_if_unused()
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set(f"Current: {restored:g}" if restored is not None else "Current: native")
        self.details.set(f"{binding.name}: native calculation restored.")
        self.log_line(f"{binding.name}: OFF | native protected value restored.")

    def _refresh_multiplier(self, key: str, payload: dict):
        binding = self._find_binding(key)
        if not binding:
            return
        snapshot = self._protected_snapshot(binding, int(payload["entry"]))
        pointer_changed = int(snapshot["value_address"]) != int(payload.get("value_address", 0))
        current = float(snapshot["value"])
        telemetry = self._read_set_variable_slot(key)
        if not telemetry["enabled"] or not self._values_close(telemetry["factor"], payload["factor"]):
            raise RuntimeError(f"{binding.name}: adaptive SetVariable slot is not active")
        counter_changed = int(telemetry["counter"]) != int(payload.get("last_counter", 0))
        if counter_changed and math.isfinite(telemetry["native"]) and math.isfinite(telemetry["scaled"]):
            payload["last_counter"] = int(telemetry["counter"])
            payload["last_native"] = float(telemetry["native"])
            payload["last_written"] = float(telemetry["scaled"])
            payload["value_address"] = int(snapshot["value_address"])
            self._set_multiplier_current_text(
                binding,
                float(telemetry["native"]),
                float(telemetry["scaled"]),
                float(payload["factor"]),
            )
            # SetVariable already committed exactly this scaled value.  Do not
            # mistake it for a new native value and multiply it a second time.
            if self._values_close(current, telemetry["scaled"]):
                return
        if not pointer_changed and self._values_close(current, payload["last_written"]):
            return
        # Some zone initialization paths populate the protected slot directly
        # rather than calling SetVariable.  Scale that fresh coherent value
        # once as a fallback; ordinary recalculations use the hook above.
        native = current
        factor = float(payload["factor"])
        scaled = native * factor
        confirmed = self._write_protected_value(binding, snapshot, scaled)
        payload["value_address"] = int(confirmed["value_address"])
        payload["last_native"] = native
        payload["last_written"] = scaled
        self._set_multiplier_current_text(binding, native, scaled, factor)

    def _refresh_direct_value(self, key: str, payload: dict):
        binding = self._find_binding(key)
        if not binding:
            return
        snapshot = self._protected_snapshot(binding, int(payload["entry"]))
        pointer_changed = int(snapshot["value_address"]) != int(payload.get("value_address", 0))
        current = float(snapshot["value"])
        if not pointer_changed and self._values_close(current, payload["last_written"]):
            return
        native = current
        target = float(payload["target"])
        return_payload = self._apply_gameplay_return(binding, target, payload)
        confirmed = self._write_protected_value(binding, snapshot, target)
        payload.update(return_payload)
        payload["value_address"] = int(confirmed["value_address"])
        payload["last_native"] = native
        payload["last_written"] = target

        self._ui_updates.put((key, f"Current: {native:g} → {target:g}"))

    def _freeze_loop(self):
        while True:
            if self.attached and self.pm and self.stat_frozen_bytes:
                for key, raw in list(self.stat_frozen_bytes.items()):
                    address = self.stat_frozen_addresses.get(key)
                    if not address:
                        continue
                    try:
                        self._write_memory(address, raw)
                    except Exception:
                        pass
            if self.attached and self.pm and self.stat_multi_patches:
                for key, payload in list(self.stat_multi_patches.items()):
                    try:
                        with self.runtime_cache_lock:
                            # A disable may have removed this payload after the
                            # outer snapshot was made but before this lock was
                            # acquired.  Never resurrect a just-restored patch.
                            if self.stat_multi_patches.get(key) is not payload:
                                continue
                            if payload.get("kind") == NATIVE_RESULT_KIND:
                                self._refresh_native_result_multiplier(key, payload)
                                continue
                            if payload.get("kind") == MULTIPLIER_KIND:
                                binding = self._find_binding(key)
                                if binding:
                                    self._ensure_gameplay_return(binding, payload)
                                self._refresh_multiplier(key, payload)
                                continue
                            if payload.get("kind") == VALUE_KIND:
                                binding = self._find_binding(key)
                                if binding:
                                    self._ensure_gameplay_return(binding, payload)
                                self._refresh_direct_value(key, payload)
                                continue
                            constant_address = payload.get("constant_address")
                            constant_raw = payload.get("constant_raw")
                            if constant_address and constant_raw:
                                self._write_memory(int(constant_address), constant_raw)
                            sites = list(payload.get("sites", [])) + list(payload.get("gate_sites", []))
                            patches = list(payload.get("patches", [])) + list(payload.get("gate_patches", []))
                            self._write_patch_group(sites, patches, skip_if_current=True)
                    except Exception:
                        pass
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    StatForgeMultiplier().run()
