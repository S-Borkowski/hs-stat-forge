# -*- coding: utf-8 -*-
import ctypes
import hashlib
import json
import math
import mmap
import os
import struct
import sys
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox

import hs_valuescanner as scan

try:
    import pymem
    import pymem.memory
    import pymem.process
except ImportError:
    messagebox.showerror(
        "Missing dependency",
        "The 'pymem' package is required.\n\nInstall it with:\npython -m pip install pymem",
    )
    sys.exit(1)

from hs_valuescanner import (
    BG,
    PANEL,
    ACCENT,
    ACCENT2,
    TEXT,
    SUBTEXT,
    PROCESS_NAME,
    force_write_memory,
    format_value,
    list_modules,
    list_processes,
    list_threads,
    pack_value,
    parse_value,
    read_value,
    read_ptr,
    resolve_main_module,
    resolve_pointer_path,
    explain_pointer_resolution,
)

APP_TITLE = "HS Offline Stat Forge v2.5.0"


def runtime_app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def runtime_resource_path(filename: str):
    bundle = getattr(sys, "_MEIPASS", None)
    if bundle:
        candidate = os.path.join(bundle, filename)
        if os.path.exists(candidate):
            return candidate
    direct = os.path.join(runtime_app_dir(), filename)
    if os.path.exists(direct):
        return direct
    return os.path.join(runtime_app_dir(), "native_density", "bin", filename)


CONFIG_FILE = os.path.join(runtime_app_dir(), "hs_statforge_stats.json")
LOG_FILE = os.path.join(runtime_app_dir(), "hs_statforge.log")
CONFIG_VERSION = 9
CONFIG_SEASON = 10
# These Season 9 routes target code that no longer exists in Season 10.  They
# are pruned during config migration so an older local JSON cannot re-enable
# an unsafe fallback address.
RETIRED_S10_BINDINGS = {"angelic_drop_rate", "angelic_ss_drops"}
# Bindings that patch the same native function in incompatible ways.  The
# entry proxy returns before the epilogue runs, which would silently starve
# the additive result hook, so only one of each group may be active.
STAT_EXCLUSIVE_KEYS = {
    "all_skills": ("all_skills_set",),
    "all_skills_set": ("all_skills",),
}
AC_DLL_TABLE_RVA = 0x5688
AC_DLL_TABLE_ENTRY_SIZE = 0x28
AC_DLL_TABLE_PAGE_SIZE = 0x5008
AC_DLL_VALUE_XOR_OFFSET = 0x18
AC_DLL_INTEGRITY_OFFSET = 0x08
AC_DLL_UNDEFINED_OFFSET = 0x20
AC_DLL_S10_SHA256 = "ea33261a54ba922b4074ae211990087c3a74fa840ead44ab30f0c74e504c505a"
AC_DLL_INTEGRITY_SEED = 0x9E3779B97F4A7C15
AC_DLL_INTEGRITY_MULTIPLIER = 0xBF58476D1CE4E5B9
UINT64_MASK = (1 << 64) - 1
ANGELIC_RATE_MAX = 100
ANGELIC_BASE_CHANCE = 1e-05
ANGELIC_MOVSD_PREFIX = bytes.fromhex("f2 0f 10 15")
ANGELIC_MOVSD_SIZE = 8
ANGELIC_GATE_SIZE = 6
NOP6 = bytes.fromhex("90 90 90 90 90 90")
S10_EXP_FACTOR_STORE = bytes.fromhex("f2 44 0f 11 5c 24 40")
S10_EXP_FACTOR_CONTEXT = bytes.fromhex("f2 44 0f 11 5c 24 40 83 ce 10")
S10_RARITY_SOURCE_ARGC = 4
S10_BOOL_TEST_SUFFIXES = (
    bytes.fromhex("84 c0"),
    bytes.fromhex("84 db"),
    bytes.fromhex("84 c9"),
    bytes.fromhex("84 d2"),
    bytes.fromhex("40 84 ff"),
    bytes.fromhex("40 84 f6"),
)
# YYC may move functions between builds, but these argument-save sequences are
# part of the native script ABI used by the three Season 10 stat functions.
# Validate the target function itself instead of allow-listing one whole EXE.
S10_STAT_ENTRY_PREFIXES = (
    bytes.fromhex("4c 89 44 24 18 48 89 54 24 10 48 89 4c 24 08"),
    bytes.fromhex("48 8b c4 4c 89 40 18 48 89 50 10 48 89 48 08"),
    # gml_Script_EnemyCalculateExperience saves RBX with a MOV instead of a
    # PUSH, so its prologue carries an extra "48 89 58 20" here and one fewer
    # push below.  Without this variant the return proxy refused the function,
    # which is why the EXP knob fell back to patching a constant inside it.
    bytes.fromhex("48 8b c4 48 89 58 20 4c 89 40 18 48 89 50 10 48 89 48 08"),
)
# Which registers are pushed depends on whether RBX was already saved above.
S10_STAT_ENTRY_PUSH_VARIANTS = (
    bytes.fromhex("55 53 56 57 41 54 41 55 41 56 41 57"),   # RBX pushed
    bytes.fromhex("55 56 57 41 54 41 55 41 56 41 57"),      # RBX saved by MOV
)
S10_STAT_ENTRY_PUSHES = S10_STAT_ENTRY_PUSH_VARIANTS[0]
S10_STAT_RETURN_PATCH_TAIL = bytes.fromhex(
    "49 89 00 "
    "41 c7 40 08 00 00 00 00 "
    "41 c7 40 0c 00 00 00 00 "
    "4c 89 c0 c3"
)
S10_STAT_LEGACY_BOOL_RETURN_PATCH_TAIL = bytes.fromhex(
    "49 89 00 "
    "41 c7 40 08 00 00 00 00 "
    "41 c7 40 0c 0d 00 00 00 "
    "4c 89 c0 c3"
)
S10_ARRAY_RESULT_MULTIPLIER = "s10_array_result_multiplier"
S10_ARRAY_RESULT_ADDITIVE = "s10_array_result_additive"
S10_SCALAR_RESULT_MULTIPLIER = "s10_scalar_result_multiplier"
S10_RESULT_EPILOGUE_PATCH_SIZE = 7
S10_RESULT_HOOK_DATA_OFFSET = 0x100
S10_RESULT_HOOK_ALLOCATION_SIZE = 0x1000
DENSITY_RESOLVER = "s10_standalone_density"
DENSITY_DLL_NAME = "HSStatForgeDensity.dll"
DENSITY_MAGIC = 0x44465348
DENSITY_VERSION = 3
DENSITY_STATUS_READY = 2
DENSITY_STATUS_ERROR = 3
# Exact-build hints skip the expensive GameMaker heap catalog scan. Unknown
# builds still use the adaptive resolver, so a game update does not turn this
# optimization into an unsafe fixed-address patch.
DENSITY_FAST_PATHS = {
    "438bf4848688c5be52ac15f26f02b46da620d90587c28e766a9cea190f3a7de4": {
        "depth_rva": 0x0B51C210,
        "layer_rva": 0x0B51C330,
        "creator_indices": (1409, 1410, 1411, 1412, 1413, 1414, 1415),
    },
}
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40
THREAD_SUSPEND_RESUME = 0x0002
kernel32 = ctypes.windll.kernel32
kernel32.VirtualAllocEx.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
)
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.VirtualFreeEx.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.wintypes.DWORD,
)
kernel32.VirtualFreeEx.restype = ctypes.wintypes.BOOL
kernel32.OpenThread.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)
kernel32.OpenThread.restype = ctypes.wintypes.HANDLE
kernel32.SuspendThread.argtypes = (ctypes.wintypes.HANDLE,)
kernel32.SuspendThread.restype = ctypes.wintypes.DWORD
kernel32.ResumeThread.argtypes = (ctypes.wintypes.HANDLE,)
kernel32.ResumeThread.restype = ctypes.wintypes.DWORD
kernel32.CloseHandle.argtypes = (ctypes.wintypes.HANDLE,)
kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
kernel32.GetTickCount64.restype = ctypes.c_ulonglong


class DensitySharedState(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("version", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("status", ctypes.c_long),
        ("enabled", ctypes.c_long),
        ("shutdown", ctypes.c_long),
        ("last_error", ctypes.c_long),
        ("protected_pool_used", ctypes.c_long),
        ("multiplier", ctypes.c_double),
        ("depth_address", ctypes.c_uint64),
        ("layer_address", ctypes.c_uint64),
        ("creator_count", ctypes.c_uint32),
        ("creator_indices", ctypes.c_int32 * 16),
        ("capacity_skips", ctypes.c_long),
        ("host_heartbeat", ctypes.c_longlong),
        ("depth_calls", ctypes.c_longlong),
        ("layer_calls", ctypes.c_longlong),
        ("creator_matches", ctypes.c_longlong),
        ("extra_creators", ctypes.c_longlong),
        ("hook_generation", ctypes.c_longlong),
        ("message", ctypes.c_char * 256),
    ]


if ctypes.sizeof(DensitySharedState) != 432:
    raise RuntimeError("Standalone density IPC layout is invalid")


def build_s10_result_epilogue_patch(cave: int, site: int, patch_size: int = S10_RESULT_EPILOGUE_PATCH_SIZE) -> bytes:
    if patch_size < 5:
        raise ValueError("result hook patch must cover at least five bytes")
    relative = int(cave) - (int(site) + 5)
    if not -(2**31) <= relative < 2**31:
        raise ValueError("result hook cave is outside rel32 range")
    return b"\xe8" + struct.pack("<i", relative) + b"\x90" * (patch_size - 5)


def _finish_result_hook_blob(code: bytearray, fixups: list[tuple[int, str]], labels: dict[str, int]) -> bytes:
    for displacement_at, label in fixups:
        if label not in labels:
            raise ValueError(f"missing result hook label: {label}")
        struct.pack_into("<i", code, displacement_at, labels[label] - (displacement_at + 4))
    if len(code) >= S10_RESULT_HOOK_DATA_OFFSET:
        raise ValueError("result hook code overlaps its telemetry data")
    blob = bytearray(S10_RESULT_HOOK_ALLOCATION_SIZE)
    blob[:len(code)] = code
    return blob


def _is_verified_s10_result_prelude(original: bytes) -> bool:
    """Accept only complete, observed YYC result/epilogue instruction pairs."""
    if len(original) == 7 and original[:3] == b"\x48\x8b\x85":
        return True
    if len(original) == 8 and original[:7] == b"\x49\x8b\xc6\x48\x8b\x6c\x24":
        return True
    if (
        len(original) == 11
        and original[:7] == b"\x48\x8b\xc3\x0f\x28\xb4\x24"
    ):
        return True  # MOV RAX,RBX + MOVAPS XMM6,[RSP+disp32]
    if len(original) != 11 or original[:2] != b"\x49\x8b":
        return False
    result_register = original[2]
    if result_register not in (0xC6, 0xC7):  # MOV RAX,R14 / MOV RAX,R15
        return False
    replay = original[3:7]
    return replay in (
        b"\x0f\x28\xb4\x24",  # MOVAPS XMM6,[RSP+disp32]
        b"\x4c\x8d\x9c\x24",  # LEA R11,[RSP+disp32]
        b"\x48\x8b\x9c\x24",  # MOV RBX,[RSP+disp32]
    )


def _call_adjusted_s10_result_prelude(original: bytes) -> bytes:
    """Replay an observed epilogue correctly after our CALL pushed 8 bytes."""
    if not _is_verified_s10_result_prelude(original):
        raise ValueError("result prelude is not verified")
    adjusted = bytearray(original)
    if len(original) == 8:
        displacement = struct.unpack_from("<b", original, 7)[0] + 8
        if not -128 <= displacement <= 127:
            raise ValueError("adjusted epilogue disp8 is out of range")
        struct.pack_into("<b", adjusted, 7, displacement)
    elif len(original) == 11:
        displacement = struct.unpack_from("<i", original, 7)[0] + 8
        struct.pack_into("<i", adjusted, 7, displacement)
    return bytes(adjusted)


def build_s10_array_result_hook_blob(
    cave: int,
    original_result_load: bytes,
    modifier: float,
    *,
    additive: bool = False,
) -> bytes:
    """Scale element zero of a native Stat* result array.

    Season 10 returns stat details as a GameMaker array.  The RValue points to
    a dynamic-array object whose element pointer is at +8; element zero is the
    final value shown by the game.  The last scaled value is recognized so a
    reused array cannot be multiplied repeatedly.
    """
    if not _is_verified_s10_result_prelude(original_result_load):
        raise ValueError("array result hook site is not a verified complete YYC result prelude")
    if not math.isfinite(modifier) or (not additive and modifier <= 0):
        raise ValueError("array result modifier must be finite and multipliers must be positive")

    data = int(cave) + S10_RESULT_HOOK_DATA_OFFSET
    code = bytearray(_call_adjusted_s10_result_prelude(original_result_load))
    fixups: list[tuple[int, str]] = []
    labels: dict[str, int] = {}

    def branch(opcode: bytes, label: str):
        code.extend(opcode)
        displacement_at = len(code)
        code.extend(b"\x00\x00\x00\x00")
        fixups.append((displacement_at, label))

    code += b"\x48\x85\xc0"                         # test rax,rax
    branch(b"\x0f\x84", "done")
    code += b"\x83\x78\x0c\x02"                 # result kind == VALUE_ARRAY
    branch(b"\x0f\x85", "done")
    code += b"\x48\x8b\x10\x48\x85\xd2"     # rdx = dynamic array object
    branch(b"\x0f\x84", "done")
    code += b"\x48\x8b\x52\x08\x48\x85\xd2" # rdx = RValue element array
    branch(b"\x0f\x84", "done")
    code += b"\x83\x7a\x0c\x00"                 # element zero kind == VALUE_REAL
    branch(b"\x0f\x85", "done")
    code += b"\x48\xb9" + struct.pack("<Q", data)  # rcx = telemetry
    code += b"\x48\xff\x41\x10"                 # calls++
    code += b"\xf2\x0f\x10\x02"                 # xmm0 = current element zero
    code += b"\x48\x83\x79\x30\x00"           # enabled?
    branch(b"\x0f\x84", "disabled")

    code += b"\x48\x3b\x51\x20"                 # same element pointer?
    branch(b"\x0f\x85", "scale")
    code += b"\x48\x83\x79\x28\x00"           # initialized?
    branch(b"\x0f\x84", "scale")
    code += b"\x66\x0f\x2e\x41\x08"           # current == last scaled?
    branch(b"\x0f\x8a", "scale")                 # unordered means new native
    branch(b"\x0f\x84", "done")                  # already scaled; do not compound

    labels["scale"] = len(code)
    code += b"\xf2\x0f\x11\x01"                 # save native
    code += (b"\xf2\x0f\x58\x41\x18" if additive else b"\xf2\x0f\x59\x41\x18")
    code += b"\xf2\x0f\x11\x02"                 # write scaled element zero
    code += b"\xf2\x0f\x11\x41\x08"           # save scaled mirror
    code += b"\x48\x89\x51\x20"                 # save element pointer
    code += b"\x48\xc7\x41\x28\x01\x00\x00\x00"  # initialized = 1
    branch(b"\xe9", "done")

    labels["disabled"] = len(code)
    code += b"\x48\x3b\x51\x20"
    branch(b"\x0f\x85", "disabled_done")
    code += b"\x48\x83\x79\x28\x00"
    branch(b"\x0f\x84", "disabled_done")
    code += b"\x66\x0f\x2e\x41\x08"
    branch(b"\x0f\x8a", "disabled_done")
    branch(b"\x0f\x85", "disabled_done")
    code += b"\xf2\x0f\x10\x09"                 # xmm1 = last native
    code += b"\xf2\x0f\x11\x0a"                 # restore element zero

    labels["disabled_done"] = len(code)
    code += b"\x48\xc7\x41\x28\x00\x00\x00\x00"  # initialized = 0
    code += b"\x48\xff\x41\x38"                 # restore calls++
    labels["done"] = len(code)
    code += b"\xc3"

    blob = _finish_result_hook_blob(code, fixups, labels)
    struct.pack_into(
        "<ddQdQQQQ",
        blob,
        S10_RESULT_HOOK_DATA_OFFSET,
        0.0,
        0.0,
        0,
        float(modifier),
        0,
        0,
        1,
        0,
    )
    return bytes(blob)


def build_s10_scalar_result_hook_blob(cave: int, original_result_load: bytes, factor: float) -> bytes:
    """Scale a real RValue after the game's complete native calculation."""
    if not _is_verified_s10_result_prelude(original_result_load):
        raise ValueError("scalar result hook site is not a verified complete YYC result prelude")
    if not math.isfinite(factor) or factor <= 0:
        raise ValueError("scalar result multiplier must be positive and finite")

    data = int(cave) + S10_RESULT_HOOK_DATA_OFFSET
    code = bytearray(_call_adjusted_s10_result_prelude(original_result_load))
    fixups: list[tuple[int, str]] = []
    labels: dict[str, int] = {}

    def branch(opcode: bytes, label: str):
        code.extend(opcode)
        displacement_at = len(code)
        code.extend(b"\x00\x00\x00\x00")
        fixups.append((displacement_at, label))

    code += b"\x48\x85\xc0"
    branch(b"\x0f\x84", "done")
    code += b"\x83\x78\x0c\x00"                 # VALUE_REAL
    branch(b"\x0f\x85", "done")
    code += b"\x48\xb9" + struct.pack("<Q", data)
    code += b"\xf2\x0f\x10\x00"
    code += b"\xf2\x0f\x11\x01"                 # native
    code += b"\xf2\x0f\x59\x41\x18"
    code += b"\xf2\x0f\x11\x00"                 # scaled result
    code += b"\xf2\x0f\x11\x41\x08"           # scaled mirror
    code += b"\x48\xff\x41\x10"
    labels["done"] = len(code)
    code += b"\xc3"
    blob = _finish_result_hook_blob(code, fixups, labels)
    struct.pack_into("<ddQd", blob, S10_RESULT_HOOK_DATA_OFFSET, 0.0, 0.0, 0, float(factor))
    return bytes(blob)


@dataclass
class StatBinding:
    key: str
    name: str
    type_name: str = "Double"
    addr: str = ""
    pointer: dict | None = None
    resolver: dict | None = None
    default_write: str = ""
    button_color: str = "#334155"
    slider_max: float = 1000

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            key=str(data.get("key") or "").strip(),
            name=str(data.get("name") or "").strip(),
            type_name=str(data.get("type") or "Double"),
            addr=str(data.get("addr") or "").strip(),
            pointer=data.get("pointer") if isinstance(data.get("pointer"), dict) else None,
            resolver=data.get("resolver") if isinstance(data.get("resolver"), dict) else None,
            default_write=str(data.get("default_write") or "").strip(),
            button_color=str(data.get("button_color") or "#334155"),
            slider_max=float(data.get("slider_max") or 1000),
        )

    def to_dict(self):
        payload = {
            "key": self.key,
            "name": self.name,
            "type": self.type_name,
            "addr": self.addr,
            "default_write": self.default_write,
            "button_color": self.button_color,
            "slider_max": self.slider_max,
        }
        if self.pointer:
            payload["pointer"] = self.pointer
        if self.resolver:
            payload["resolver"] = self.resolver
        return payload


DEFAULT_STATS = [
    StatBinding(
        key="magic_find",
        name="Magic Find Multiplier",
        type_name="Double",
        default_write="10",
        button_color="#0f766e",
        resolver={
            "kind": S10_ARRAY_RESULT_MULTIPLIER,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_StatMagicFind",
            "max": 1000,
        },
    ),
    StatBinding(
        key="movement_speed",
        name="Movement Speed Multiplier",
        type_name="Double",
        default_write="2",
        button_color="#7c3aed",
        slider_max=100,
        resolver={
            "kind": S10_ARRAY_RESULT_MULTIPLIER,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_StatMovementSpeed",
            "max": 100,
        },
    ),
    StatBinding(
        key="all_skills",
        name="All Skills Bonus (+N)",
        type_name="Double",
        default_write="19",
        button_color="#b45309",
        slider_max=100,
        resolver={
            # StatAllSkills returns a stat array like Skill Haste; element zero
            # is the total the talent path reads through ReturnSpecificStat.
            # Adding to the finished native result keeps gear "+X All Skills",
            # elemental flats and buffs stacking on top instead of replacing
            # the whole function with a constant.
            "kind": S10_ARRAY_RESULT_ADDITIVE,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_StatAllSkills",
            "input_mode": "additive",
            "max": 100,
        },
    ),
    StatBinding(
        key="all_skills_set",
        name="All Skills (Set Exact)",
        type_name="Double",
        default_write="28",
        button_color="#9a3412",
        slider_max=100,
        resolver={
            # Legacy absolute mode: replaces the StatAllSkills entry so the
            # function returns this constant and nothing else stacks.
            "kind": "s10_stat_return_proxy",
            "module": PROCESS_NAME,
            "function_name": "gml_Script_StatAllSkills",
        },
    ),
    StatBinding(
        key="exp_multiplier",
        name="EXP Multiplier",
        type_name="Double",
        default_write="10",
        button_color="#be123c",
        slider_max=100,
        resolver={
            "kind": S10_SCALAR_RESULT_MULTIPLIER,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_EnemyCalculateExperience",
            "max": 100,
        },
    ),
    StatBinding(
        key="total_damage_bonus",
        name="Total Damage Bonus (%)",
        type_name="Double",
        default_write="100",
        button_color="#dc2626",
        slider_max=1000,
        resolver={
            "kind": S10_SCALAR_RESULT_MULTIPLIER,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_CalculateEndDamage",
            "input_mode": "bonus_percent",
            "max": 1000,
        },
    ),
    StatBinding(
        key="attack_speed_bonus",
        name="Attack Speed Bonus (%)",
        type_name="Double",
        default_write="100",
        button_color="#ea580c",
        slider_max=500,
        resolver={
            "kind": S10_SCALAR_RESULT_MULTIPLIER,
            "module": PROCESS_NAME,
            # Live 7.0.5.0 telemetry proved this aggregate function returns a
            # scalar VALUE_REAL (23.1 on the measured character), not a stat
            # detail array.  The hand-specific array helpers are UI queries.
            "function_name": "gml_Script_StatAttackSpeed",
            "input_mode": "bonus_percent",
            "max": 500,
        },
    ),
    StatBinding(
        key="faster_cast_rate_bonus",
        name="Faster Cast Rate Bonus",
        type_name="Double",
        default_write="50",
        button_color="#d97706",
        slider_max=500,
        resolver={
            "kind": S10_ARRAY_RESULT_ADDITIVE,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_StatFasterCastRate",
            "input_mode": "additive",
            "max": 500,
        },
    ),
    StatBinding(
        key="skill_haste_bonus",
        name="Skill Haste Bonus",
        type_name="Double",
        default_write="100",
        button_color="#0891b2",
        slider_max=500,
        resolver={
            "kind": S10_ARRAY_RESULT_ADDITIVE,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_StatSpellHaste",
            "input_mode": "additive",
            "max": 500,
        },
    ),
    StatBinding(
        key="defense_bonus",
        name="Defense Bonus (%)",
        type_name="Double",
        default_write="100",
        button_color="#2563eb",
        slider_max=1000,
        resolver={
            "kind": S10_ARRAY_RESULT_MULTIPLIER,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_StatDefense",
            "input_mode": "bonus_percent",
            "max": 1000,
        },
    ),
    StatBinding(
        key="critical_strike_damage_bonus",
        name="Critical Strike Damage Bonus (%)",
        type_name="Double",
        default_write="100",
        button_color="#be123c",
        slider_max=1000,
        resolver={
            "kind": S10_ARRAY_RESULT_MULTIPLIER,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_StatCritDamage",
            "input_mode": "bonus_percent",
            "max": 1000,
        },
    ),
    StatBinding(
        key="critical_strike_chance_bonus",
        name="Critical Strike Chance Bonus (%)",
        type_name="Double",
        default_write="100",
        button_color="#db2777",
        slider_max=500,
        resolver={
            "kind": S10_ARRAY_RESULT_MULTIPLIER,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_StatCritRate",
            "input_mode": "bonus_percent",
            "max": 500,
        },
    ),
    StatBinding(
        key="spell_critical_damage_bonus",
        name="Spell Critical Damage Bonus (%)",
        type_name="Double",
        default_write="100",
        button_color="#9333ea",
        slider_max=1000,
        resolver={
            "kind": S10_ARRAY_RESULT_MULTIPLIER,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_StatSpellCritDamage",
            "input_mode": "bonus_percent",
            "max": 1000,
        },
    ),
    StatBinding(
        key="spell_critical_chance_bonus",
        name="Spell Critical Chance Bonus (%)",
        type_name="Double",
        default_write="100",
        button_color="#7c3aed",
        slider_max=500,
        resolver={
            "kind": S10_ARRAY_RESULT_MULTIPLIER,
            "module": PROCESS_NAME,
            "function_name": "gml_Script_StatSpellCritRate",
            "input_mode": "bonus_percent",
            "max": 500,
        },
    ),
    StatBinding(
        key="monster_density",
        name="Monster Density Multiplier",
        type_name="Double",
        default_write="2",
        button_color="#16a34a",
        slider_max=5,
        resolver={
            "kind": DENSITY_RESOLVER,
            "min": 1,
            "max": 5,
            "step": 0.5,
        },
    ),
]


class StatForge:
    def __init__(self):
        self.pm = None
        self.attached = False
        self.selected_pid = None
        self.selected_process_name = PROCESS_NAME

        self.stat_bindings: list[StatBinding] = []
        self.stat_buttons: dict[str, tk.Button] = {}
        self.stat_value_vars: dict[str, tk.StringVar] = {}
        self.stat_slider_vars: dict[str, tk.DoubleVar] = {}
        self.stat_current_vars: dict[str, tk.StringVar] = {}
        self.stat_cards: dict[str, tk.Frame] = {}
        self.stat_original_bytes: dict[str, bytes] = {}
        self.stat_frozen_bytes: dict[str, bytes] = {}
        self.stat_frozen_addresses: dict[str, int] = {}
        self.stat_multi_patches: dict[str, dict] = {}
        self.active_stat_keys: set[str] = set()
        self.verified_module_hashes: dict[str, str] = {}
        self.pe_sections_cache: dict[tuple, dict] = {}
        self.function_addresses_cache: dict[tuple, dict[str, int]] = {}
        self._main_module_cache: dict | None = None
        self.runtime_cache_lock = threading.RLock()
        self._last_process_liveness_check = 0.0
        self.density_mapping = None
        self.density_state: DensitySharedState | None = None

        self.root = tk.Tk()
        self.root.title(APP_TITLE)
        self.root.geometry("1080x820")
        self.root.minsize(820, 620)
        self.root.configure(bg="#07070b")
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.status = tk.StringVar(value="Hero_Siege.exe waiting.")
        self.active_profile = tk.StringVar(value="Active Boosts: None")
        self.details = tk.StringVar(value="Select a stat boost to toggle it on. Click again to restore the original value.")

        self._build_ui()
        self._load_bindings()
        threading.Thread(target=self._freeze_loop, daemon=True).start()
        self.root.after(250, self._poll_result_telemetry)

    def _build_ui(self):
        header = tk.Frame(self.root, bg="#0a0910", height=94)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Frame(header, bg="#c6923c", height=2).pack(fill="x", side="top")

        brand = tk.Frame(header, bg="#0a0910")
        brand.pack(side="left", fill="y", padx=(28, 0), pady=(15, 12))
        tk.Label(
            brand,
            text="HERO SIEGE  •  SEASON 10",
            fg="#cda85f",
            bg="#0a0910",
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        ).pack(fill="x")
        tk.Label(
            brand,
            text="OFFLINE STAT FORGE",
            fg="#f5f2e9",
            bg="#0a0910",
            font=("Segoe UI", 23, "bold"),
            anchor="w",
        ).pack(fill="x", pady=(1, 0))

        build_box = tk.Frame(header, bg="#0a0910")
        build_box.pack(side="right", padx=(0, 28), pady=(20, 14))
        tk.Label(
            build_box,
            text="RUNTIME STAT LAB",
            fg="#aa98d4",
            bg="#15121d",
            padx=12,
            pady=6,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="e")
        tk.Label(
            build_box,
            text="v2.5.0  •  ADDITIVE ALL SKILLS",
            fg="#716b7d",
            bg="#0a0910",
            font=("Consolas", 8),
        ).pack(anchor="e", pady=(5, 0))

        body_outer = tk.Frame(self.root, bg="#07070b")
        body_outer.pack(fill="both", expand=True)
        body_canvas = tk.Canvas(body_outer, bg="#07070b", highlightthickness=0, bd=0)
        body_scrollbar = tk.Scrollbar(
            body_outer,
            orient="vertical",
            command=body_canvas.yview,
            bg="#17151d",
            troughcolor="#09090d",
            activebackground="#6f579b",
            relief="flat",
            bd=0,
        )
        body_canvas.configure(yscrollcommand=body_scrollbar.set)
        body_scrollbar.pack(side="right", fill="y")
        body_canvas.pack(side="left", fill="both", expand=True)

        body = tk.Frame(body_canvas, bg="#07070b")
        body_window = body_canvas.create_window((24, 20), window=body, anchor="nw")

        def update_scroll_region(_event=None):
            body_canvas.configure(scrollregion=body_canvas.bbox("all"))

        def resize_body(event):
            body_canvas.itemconfigure(body_window, width=max(1, event.width - 48))

        def on_mousewheel(event):
            body_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        body.bind("<Configure>", update_scroll_region)
        body_canvas.bind("<Configure>", resize_body)
        body_canvas.bind_all("<MouseWheel>", on_mousewheel)

        control_panel, control_body = self._create_forge_panel(
            body,
            "FORGE CONTROL",
            "Attach to Hero Siege and manage reversible runtime overrides.",
            "#7f5bb5",
        )
        control_panel.pack(fill="x", pady=(0, 14))

        status_row = tk.Frame(control_body, bg="#0d0c13")
        status_row.pack(fill="x", padx=14, pady=(12, 10))
        self.status_dot = tk.Canvas(status_row, width=24, height=24, bg="#0d0c13", bd=0, highlightthickness=0)
        self.status_dot.pack(side="left", padx=(0, 8))
        self.status_glow = self.status_dot.create_oval(2, 2, 22, 22, fill="#49351f", outline="")
        self.status_core = self.status_dot.create_oval(8, 8, 16, 16, fill="#b47b3b", outline="")
        tk.Label(
            status_row,
            textvariable=self.status,
            fg="#e9e4ef",
            bg="#0d0c13",
            anchor="w",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left", fill="x", expand=True)
        tk.Label(
            status_row,
            text="EXE UNTOUCHED",
            fg="#c9a75e",
            bg="#17141d",
            padx=10,
            pady=5,
            font=("Segoe UI", 8, "bold"),
        ).pack(side="right")

        actions = tk.Frame(control_body, bg="#0d0c13")
        actions.pack(fill="x", padx=14, pady=(0, 14))
        action_buttons = (
            ("ATTACH / SELECT", self.attach, "#7f5bb5"),
            ("RELOAD BINDINGS", self._reload_bindings, "#227f76"),
            ("REFRESH STATUS", self.refresh_status, "#536176"),
            ("RESTORE ALL", self.restore_all, "#a23a46"),
        )
        for index, (text, command, color) in enumerate(action_buttons):
            button = self._create_forge_button(actions, text, command, color)
            button.grid(
                row=0,
                column=index,
                padx=(0 if index == 0 else 8, 0),
                sticky="ew",
                ipady=4,
            )
            actions.grid_columnconfigure(index, weight=1)

        stat_panel, stat_frame = self._create_forge_panel(
            body,
            "STAT VAULT",
            "Season 10 native stat routes • choose a value, then forge the override.",
            "#c6923c",
        )
        stat_panel.pack(fill="x", pady=(0, 14))
        self.stat_frame = stat_frame

        active_strip = tk.Frame(body, bg="#121019", highlightthickness=1, highlightbackground="#292430")
        active_strip.pack(fill="x", pady=(0, 14))
        tk.Frame(active_strip, bg="#7f5bb5", width=4).pack(side="left", fill="y")
        tk.Label(
            active_strip,
            text="ACTIVE FORGE",
            fg="#a38cce",
            bg="#121019",
            padx=12,
            pady=10,
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left")
        tk.Label(
            active_strip,
            textvariable=self.active_profile,
            fg="#f0edf4",
            bg="#121019",
            anchor="w",
            pady=10,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", fill="x", expand=True)

        note = (
            "OFFLINE ONLY  •  Season 10 verified toggles override native runtime results until Restore All, "
            "the app closes, or the game closes. Game files on disk are never modified. Unsafe legacy Season 9 "
            "routes remain intentionally unavailable."
        )
        intel_panel, intel_body = self._create_forge_panel(
            body,
            "FORGE INTEL",
            "Live operation details and the reversible patch activity log.",
            "#3a8b83",
        )
        intel_panel.pack(fill="both", expand=True, pady=(0, 22))
        tk.Label(
            intel_body,
            text=note,
            fg="#948d9e",
            bg="#0d0c13",
            anchor="w",
            justify="left",
            wraplength=930,
            padx=14,
            pady=10,
            font=("Segoe UI", 8),
        ).pack(fill="x")
        tk.Label(
            intel_body,
            textvariable=self.details,
            fg="#d4cedc",
            bg="#0d0c13",
            anchor="w",
            justify="left",
            wraplength=930,
            padx=14,
            pady=11,
            font=("Segoe UI", 9),
        ).pack(fill="x")
        self.log = tk.Text(
            intel_body,
            height=9,
            bg="#09090e",
            fg="#b9c6d9",
            insertbackground="#d9e2ff",
            selectbackground="#493766",
            relief="flat",
            bd=0,
            padx=12,
            pady=10,
            font=("Consolas", 9),
        )
        self.log.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.log_line("Ready.")

    def _create_forge_panel(self, parent, title: str, subtitle: str, accent: str):
        outer = tk.Frame(parent, bg="#28242f", bd=0)
        panel = tk.Frame(outer, bg="#0d0c13", bd=0)
        panel.pack(fill="both", expand=True, padx=1, pady=1)
        heading = tk.Frame(panel, bg="#121019", height=58)
        heading.pack(fill="x")
        heading.pack_propagate(False)
        tk.Frame(heading, bg=accent, width=4).pack(side="left", fill="y")
        text_box = tk.Frame(heading, bg="#121019")
        text_box.pack(side="left", fill="both", expand=True, padx=14, pady=(8, 6))
        tk.Label(
            text_box,
            text=title,
            fg="#f2eef5",
            bg="#121019",
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        ).pack(fill="x")
        tk.Label(
            text_box,
            text=subtitle,
            fg="#817a8c",
            bg="#121019",
            font=("Segoe UI", 8),
            anchor="w",
            justify="left",
        ).pack(fill="x", pady=(2, 0))
        tk.Frame(panel, bg="#25212d", height=1).pack(fill="x")
        content = tk.Frame(panel, bg="#0d0c13")
        content.pack(fill="both", expand=True)
        return outer, content

    def _create_forge_button(self, parent, text: str, command, accent: str):
        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg="#171820",
            fg="#e4dfea",
            activebackground=accent,
            activeforeground="#ffffff",
            highlightthickness=1,
            highlightbackground=accent,
            highlightcolor=accent,
            relief="flat",
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=8,
        )
        button.bind("<Enter>", lambda _event, b=button, c=accent: b.config(bg=c, fg="#ffffff"))
        button.bind("<Leave>", lambda _event, b=button: b.config(bg="#171820", fg="#e4dfea"))
        return button

    def _stat_accent(self, binding: StatBinding):
        return {
            "magic_find": "#c6923c",
            "movement_speed": "#7658a9",
            "all_skills": "#238b7e",
            "all_skills_set": "#8a5a2b",
            "exp_multiplier": "#b74755",
            "monster_density": "#16a34a",
        }.get(binding.key, binding.button_color or "#7658a9")

    def _stat_code(self, binding: StatBinding):
        return {
            "magic_find": "MF",
            "movement_speed": "MS",
            "all_skills": "A+",
            "all_skills_set": "A=",
            "exp_multiplier": "XP",
            "monster_density": "MD",
        }.get(binding.key, binding.name[:2].upper())

    def _configure_stat_toggle(self, binding: StatBinding, is_on: bool):
        button = self.stat_buttons.get(binding.key)
        if not button:
            return
        accent = self._stat_accent(binding)
        if is_on:
            bg, fg, border = "#0b5c48", "#f0fff9", "#54d7ae"
            text = "◆  ACTIVE  •  CLICK TO RESTORE"
            hover = "#11765c"
        else:
            bg, fg, border = "#171820", "#d8d5df", accent
            text = "◇  ENABLE BOOST"
            hover = "#24232d"
        button.config(
            text=text,
            bg=bg,
            fg=fg,
            activebackground=hover,
            activeforeground=fg,
            highlightbackground=border,
            highlightcolor=border,
        )
        button.bind("<Enter>", lambda _event, b=button, c=hover: b.config(bg=c))
        button.bind("<Leave>", lambda _event, b=button, c=bg: b.config(bg=c))

    def _sync_status_indicator(self):
        if not hasattr(self, "status_dot"):
            return
        if self.attached and self.pm:
            glow, core = "#1e634f", "#46d6a5"
        elif "failed" in self.status.get().lower():
            glow, core = "#5a252d", "#d25463"
        else:
            glow, core = "#49351f", "#b47b3b"
        self.status_dot.itemconfigure(self.status_glow, fill=glow)
        self.status_dot.itemconfigure(self.status_core, fill=core)

    def log_line(self, text: str):
        self.log.insert("end", f"> {text}\n")
        self.log.see("end")
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as handle:
                handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {text}\n")
        except Exception:
            pass

    def _default_payload(self):
        return {
            "version": CONFIG_VERSION,
            "season": CONFIG_SEASON,
            "stats": [item.to_dict() for item in DEFAULT_STATS],
        }

    def _load_bindings(self):
        if not os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self._default_payload(), f, indent=4)
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
        raw_stats = [item for item in payload.get("stats", []) if isinstance(item, dict)]
        removed_retired = any(
            str(item.get("key") or "").strip() in RETIRED_S10_BINDINGS for item in raw_stats
        )
        self.stat_bindings = [
            StatBinding.from_dict(item)
            for item in raw_stats
            if str(item.get("key") or "").strip() not in RETIRED_S10_BINDINGS
        ]
        if not self.stat_bindings:
            self.stat_bindings = [StatBinding.from_dict(item.to_dict()) for item in DEFAULT_STATS]
        self._apply_builtin_bindings()
        if removed_retired or payload.get("version") != CONFIG_VERSION or payload.get("season") != CONFIG_SEASON:
            self._save_bindings()
        self._render_stat_buttons()

    def _apply_builtin_bindings(self):
        defaults = {item.key: item for item in DEFAULT_STATS}
        original_keys = {item.key for item in self.stat_bindings}
        self.stat_bindings = [item for item in self.stat_bindings if item.key not in RETIRED_S10_BINDINGS]
        changed = original_keys != {item.key for item in self.stat_bindings}
        for binding in self.stat_bindings:
            default = defaults.get(binding.key)
            if not default:
                continue
            if default.resolver and binding.resolver != default.resolver:
                old_kind = str((binding.resolver or {}).get("kind") or "").lower()
                new_kind = str(default.resolver.get("kind") or "").lower()
                binding.resolver = dict(default.resolver)
                binding.addr = ""
                binding.pointer = None
                if old_kind != new_kind:
                    binding.default_write = default.default_write
                changed = True
            if binding.name != default.name:
                binding.name = default.name
                changed = True
            if not binding.default_write and default.default_write:
                binding.default_write = default.default_write
                changed = True
            if binding.slider_max != default.slider_max:
                binding.slider_max = default.slider_max
                changed = True
        existing = {item.key for item in self.stat_bindings}
        for default in DEFAULT_STATS:
            if default.key not in existing:
                self.stat_bindings.append(StatBinding.from_dict(default.to_dict()))
                changed = True
        if changed:
            self._save_bindings()

    def _reload_bindings(self):
        self._load_bindings()
        self.log_line("Bindings reloaded.")

    def _save_bindings(self):
        payload = {
            "version": CONFIG_VERSION,
            "season": CONFIG_SEASON,
            "stats": [item.to_dict() for item in self.stat_bindings],
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4)

    def _render_stat_buttons(self):
        for child in self.stat_frame.winfo_children():
            child.destroy()
        self.stat_buttons.clear()
        self.stat_cards.clear()
        self.stat_value_vars.clear()
        self.stat_slider_vars.clear()
        self.stat_current_vars.clear()

        for index, binding in enumerate(self.stat_bindings):
            row = index // 2
            col = index % 2
            accent = self._stat_accent(binding)
            card = tk.Frame(
                self.stat_frame,
                bg="#111019",
                highlightthickness=1,
                highlightbackground="#302b38",
                bd=0,
            )
            card.grid(
                row=row,
                column=col,
                padx=(14 if col == 0 else 7, 14 if col == 1 else 7),
                pady=(14 if row == 0 else 7, 14),
                sticky="nsew",
            )
            card.grid_columnconfigure(1, weight=1)
            self.stat_cards[binding.key] = card

            tk.Frame(card, bg=accent, height=3).grid(row=0, column=0, columnspan=2, sticky="ew")

            tk.Label(
                card,
                text=self._stat_code(binding),
                bg="#191720",
                fg=accent,
                width=4,
                pady=7,
                font=("Consolas", 10, "bold"),
            ).grid(row=1, column=0, sticky="w", padx=(12, 8), pady=(12, 4))

            tk.Label(
                card,
                text=binding.name,
                bg="#111019",
                fg="#f4f0f6",
                font=("Segoe UI", 12, "bold"),
            ).grid(row=1, column=1, sticky="w", padx=(0, 12), pady=(12, 4))

            current_var = tk.StringVar(value="Current: ?")
            self.stat_current_vars[binding.key] = current_var
            tk.Label(
                card,
                textvariable=current_var,
                bg="#111019",
                fg="#8d8498",
                font=("Consolas", 9),
            ).grid(row=2, column=0, columnspan=2, sticky="w", padx=12, pady=(2, 9))

            slider_var = tk.DoubleVar(value=float(binding.default_write or 0))
            value_var = tk.StringVar(value=binding.default_write or "")
            self.stat_slider_vars[binding.key] = slider_var
            self.stat_value_vars[binding.key] = value_var
            resolver_kind = str((binding.resolver or {}).get("kind") or "").lower()
            if resolver_kind == "s10_rarity_proxy":
                tk.Label(
                    card,
                    text="S10 native monster-drop route\nBinary toggle — no rate value required",
                    bg="#111019",
                    fg="#cba660",
                    justify="left",
                    anchor="w",
                    font=("Segoe UI", 9),
                ).grid(row=3, column=0, columnspan=2, rowspan=3, sticky="ew", padx=12, pady=(4, 12))
            else:
                minimum = float((binding.resolver or {}).get("min", 0))
                step = float((binding.resolver or {}).get("step", 1))
                range_row = tk.Frame(card, bg="#111019")
                range_row.grid(row=3, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 2))
                tk.Label(
                    range_row,
                    text="FORGE VALUE",
                    bg="#111019",
                    fg="#746d7e",
                    font=("Segoe UI", 7, "bold"),
                ).pack(side="left")
                tk.Label(
                    range_row,
                    text=f"{minimum:g} — {binding.slider_max:g}",
                    bg="#111019",
                    fg="#5f5968",
                    font=("Consolas", 8),
                ).pack(side="right")
                scale = tk.Scale(
                    card,
                    from_=minimum,
                    to=binding.slider_max,
                    orient="horizontal",
                    resolution=step,
                    variable=slider_var,
                    bg="#111019",
                    fg="#cbd5e1",
                    troughcolor="#2b2731",
                    highlightthickness=0,
                    activebackground=accent,
                    sliderrelief="flat",
                    bd=0,
                    showvalue=False,
                    length=250,
                    command=lambda val, k=binding.key: self._sync_slider_to_entry(k, val),
                )
                scale.grid(row=4, column=0, columnspan=2, sticky="ew", padx=8, pady=(0, 2))

                entry = tk.Entry(
                    card,
                    textvariable=value_var,
                    bg="#09090e",
                    fg="#f0ebf3",
                    insertbackground="#f0ebf3",
                    justify="center",
                    relief="flat",
                    bd=0,
                    highlightthickness=1,
                    highlightbackground="#37313f",
                    highlightcolor=accent,
                    font=("Segoe UI", 10, "bold"),
                )
                entry.grid(row=5, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 10), ipady=5)
                entry.bind("<Return>", lambda _event, k=binding.key: self._sync_entry_to_slider(k))
                entry.bind("<FocusOut>", lambda _event, k=binding.key: self._sync_entry_to_slider(k))

            btn = tk.Button(
                card,
                text="◇  ENABLE BOOST",
                command=lambda k=binding.key: self.toggle_stat(k),
                bg="#171820",
                fg="#d8d5df",
                activebackground="#24232d",
                activeforeground="#ffffff",
                highlightthickness=1,
                highlightbackground=accent,
                highlightcolor=accent,
                relief="flat",
                bd=0,
                cursor="hand2",
                justify="center",
                font=("Segoe UI", 8, "bold"),
                pady=9,
            )
            btn.grid(row=6, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 12))
            self.stat_buttons[binding.key] = btn

        for col in range(2):
            self.stat_frame.grid_columnconfigure(col, weight=1, uniform="stat")
        for row in range((len(self.stat_bindings) + 1) // 2):
            self.stat_frame.grid_rowconfigure(row, weight=1)

        self.refresh_status()

    def _conflicting_active_key(self, binding: StatBinding):
        for other_key in STAT_EXCLUSIVE_KEYS.get(binding.key, ()):
            if other_key in self.active_stat_keys:
                return other_key
        return None

    def _find_binding(self, key: str):
        return next((item for item in self.stat_bindings if item.key == key), None)

    def _parse_int_setting(self, value, field_name: str):
        try:
            if isinstance(value, str):
                return int(value.strip(), 0)
            return int(value)
        except Exception as exc:
            raise RuntimeError(f"invalid resolver {field_name}: {value!r}") from exc

    def _write_memory(self, address: int, raw_data: bytes):
        old_protect = ctypes.wintypes.DWORD()
        if not kernel32.VirtualProtectEx(
            self.pm.process_handle,
            ctypes.c_void_p(address),
            ctypes.c_size_t(len(raw_data)),
            0x40,
            ctypes.byref(old_protect),
        ):
            raise RuntimeError(f"VirtualProtectEx failed at {hex(address)}")
        try:
            pymem.memory.write_bytes(self.pm.process_handle, address, raw_data, len(raw_data))
            kernel32.FlushInstructionCache(
                self.pm.process_handle,
                ctypes.c_void_p(address),
                ctypes.c_size_t(len(raw_data)),
            )
        finally:
            dummy = ctypes.wintypes.DWORD()
            kernel32.VirtualProtectEx(
                self.pm.process_handle,
                ctypes.c_void_p(address),
                ctypes.c_size_t(len(raw_data)),
                old_protect.value,
                ctypes.byref(dummy),
            )

    def _suspend_game_threads(self):
        handles = []
        if not self.pm:
            return handles
        for thread_id in list_threads(self.pm.process_id):
            handle = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, int(thread_id))
            if not handle:
                continue
            result = kernel32.SuspendThread(handle)
            if result == 0xFFFFFFFF:
                kernel32.CloseHandle(handle)
                continue
            handles.append(handle)
        return handles

    @staticmethod
    def _resume_game_threads(handles):
        for handle in reversed(handles):
            try:
                kernel32.ResumeThread(handle)
            finally:
                kernel32.CloseHandle(handle)

    def _write_patch_group(self, sites: list[int], raw_values: list[bytes], skip_if_current: bool = False):
        pairs = [(int(site), bytes(raw)) for site, raw in zip(sites, raw_values)]
        if not pairs:
            return
        if skip_if_current:
            try:
                if all(self._read_raw(site, len(raw)) == raw for site, raw in pairs):
                    return
            except Exception:
                pass
        handles = self._suspend_game_threads()
        try:
            for site, raw in pairs:
                self._write_memory(site, raw)
        finally:
            self._resume_game_threads(handles)

    def _write_code_when_quiescent(self, site: int, raw: bytes, attempts: int = 250):
        """Patch code only while no game thread is executing the target bytes."""
        rights = scan.THREAD_GET_CONTEXT | scan.THREAD_SUSPEND_RESUME | scan.THREAD_QUERY_INFORMATION
        region_start = int(site)
        region_end = region_start + max(S10_RESULT_EPILOGUE_PATCH_SIZE, len(raw))
        for _attempt in range(attempts):
            handles = []
            busy = False
            try:
                for thread_id in list_threads(self.pm.process_id):
                    handle = kernel32.OpenThread(rights, False, int(thread_id))
                    if not handle:
                        continue
                    if kernel32.SuspendThread(handle) == 0xFFFFFFFF:
                        kernel32.CloseHandle(handle)
                        continue
                    handles.append(handle)
                    context = scan.CONTEXT()
                    context.ContextFlags = scan.CONTEXT_CONTROL
                    if kernel32.GetThreadContext(handle, ctypes.byref(context)):
                        if region_start <= int(context.Rip) < region_end:
                            busy = True
                if not busy:
                    self._write_memory(region_start, bytes(raw))
                    return
            finally:
                self._resume_game_threads(handles)
            time.sleep(0.002)
        raise RuntimeError("native stat function remained busy; pause in town and try again")

    def _is_exe_patch_binding(self, binding: StatBinding):
        return bool(binding.resolver and str(binding.resolver.get("kind") or "").lower() == "hero_exe_patch_double")

    def _is_ac_dll_table_binding(self, binding: StatBinding):
        return bool(binding.resolver and str(binding.resolver.get("kind") or "").lower() == "ac_dll_table")

    def _is_angelic_rate_binding(self, binding: StatBinding):
        return bool(binding.resolver and str(binding.resolver.get("kind") or "").lower() == "angelic_rate_multiplier")

    def _is_s10_exp_proxy_binding(self, binding: StatBinding):
        return bool(binding.resolver and str(binding.resolver.get("kind") or "").lower() == "s10_exp_factor_proxy")

    def _is_s10_stat_return_proxy_binding(self, binding: StatBinding):
        return bool(binding.resolver and str(binding.resolver.get("kind") or "").lower() == "s10_stat_return_proxy")

    def _is_s10_rarity_proxy_binding(self, binding: StatBinding):
        return bool(binding.resolver and str(binding.resolver.get("kind") or "").lower() == "s10_rarity_proxy")

    def _is_s10_array_result_binding(self, binding: StatBinding):
        return bool(
            binding.resolver
            and str(binding.resolver.get("kind") or "").lower() == S10_ARRAY_RESULT_MULTIPLIER
        )

    def _is_s10_array_additive_binding(self, binding: StatBinding):
        return bool(
            binding.resolver
            and str(binding.resolver.get("kind") or "").lower() == S10_ARRAY_RESULT_ADDITIVE
        )

    def _is_s10_result_binding(self, binding: StatBinding):
        return bool(
            self._is_s10_array_result_binding(binding)
            or self._is_s10_array_additive_binding(binding)
            or self._is_s10_scalar_result_binding(binding)
        )

    def _is_s10_scalar_result_binding(self, binding: StatBinding):
        return bool(
            binding.resolver
            and str(binding.resolver.get("kind") or "").lower() == S10_SCALAR_RESULT_MULTIPLIER
        )

    def _is_density_binding(self, binding: StatBinding):
        return bool(
            binding.resolver
            and str(binding.resolver.get("kind") or "").lower() == DENSITY_RESOLVER
        )

    @staticmethod
    def _ror64(value: int, count: int):
        count &= 63
        value &= UINT64_MASK
        return ((value >> count) | (value << (64 - count))) & UINT64_MASK

    @classmethod
    def _s10_integrity_value(cls, value_bits: int, xor_key: int):
        mixed = cls._ror64((int(xor_key) ^ AC_DLL_INTEGRITY_SEED) & UINT64_MASK, 0x33)
        mixed ^= mixed >> 7
        mixed = (mixed * AC_DLL_INTEGRITY_MULTIPLIER) & UINT64_MASK
        mixed ^= mixed >> 0x11
        return (mixed ^ int(value_bits)) & UINT64_MASK

    def _verify_module_fingerprint(self, module: dict, expected_sha256: str, label: str):
        expected = str(expected_sha256 or "").strip().lower()
        if not expected:
            raise RuntimeError(f"{label}: missing Season 10 module fingerprint")
        actual = self._module_fingerprint(module, label)
        if actual != expected:
            raise RuntimeError(
                f"{label}: unsupported Season 10 module build ({actual[:12]}). "
                "Patch blocked instead of writing an unverified layout."
            )
        return actual

    def _module_fingerprint(self, module: dict, label: str = "module"):
        path = str(module.get("path") or "")
        if not path or not os.path.exists(path):
            raise RuntimeError(f"{label}: module path is unavailable")
        stat = os.stat(path)
        cache_key = f"{os.path.normcase(os.path.abspath(path))}|{stat.st_size}|{stat.st_mtime_ns}"
        actual = self.verified_module_hashes.get(cache_key)
        if actual is None:
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            actual = digest.hexdigest().lower()
            self.verified_module_hashes[cache_key] = actual
        return actual

    def _decode_exe_patch_value(self, raw_data: bytes):
        if len(raw_data) >= 10 and raw_data[:2] == b"\x48\xbb":
            return struct.unpack("<d", raw_data[2:10])[0]
        return None

    def _encode_exe_patch_value(self, value: float):
        return b"\x48\xbb" + struct.pack("<d", float(value))

    def _hero_module(self, module_name: str):
        if module_name.lower() == PROCESS_NAME.lower():
            cached = getattr(self, "_main_module_cache", None)
            if cached:
                return cached
            module = resolve_main_module(self.pm, PROCESS_NAME)
            if module:
                self._main_module_cache = module
            return module
        modules = list_modules(self.pm.process_id)
        return next((m for m in modules if m["name"].lower() == module_name.lower()), None)

    def _read_ascii_process(self, address: int, max_len: int = 256):
        try:
            raw = self._read_raw(address, max_len)
            end = raw.find(b"\x00")
            if end >= 0:
                raw = raw[:end]
            return raw.decode("ascii", errors="ignore")
        except Exception:
            return ""

    def _load_pe_sections(self, module: dict):
        path = module.get("path") or ""
        if not path or not os.path.exists(path):
            raise RuntimeError(f"module path unavailable for {module.get('name')}")
        stat = os.stat(path)
        cache_key = (os.path.normcase(os.path.abspath(path)), stat.st_size, stat.st_mtime_ns, int(module["base"]))
        with self.runtime_cache_lock:
            cached = self.pe_sections_cache.get(cache_key)
            if cached is not None:
                return cached
            # PE headers are small; avoid loading the entire game executable for
            # every toggle just to translate one RVA.
            with open(path, "rb") as handle:
                exe_bytes = handle.read(0x10000)
            pe_offset = struct.unpack_from("<I", exe_bytes, 0x3C)[0]
            if exe_bytes[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                raise RuntimeError("invalid PE header")
            coff = pe_offset + 4
            section_count = struct.unpack_from("<H", exe_bytes, coff + 2)[0]
            optional_size = struct.unpack_from("<H", exe_bytes, coff + 16)[0]
            section_offset = coff + 20 + optional_size
            required = section_offset + section_count * 40
            if required > len(exe_bytes):
                with open(path, "rb") as handle:
                    exe_bytes = handle.read(required)
            sections = {}
            for index in range(section_count):
                off = section_offset + index * 40
                name = exe_bytes[off:off + 8].split(b"\x00")[0].decode(errors="ignore")
                virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", exe_bytes, off + 8)
                sections[name] = {
                    "rva": virtual_address,
                    "va": module["base"] + virtual_address,
                    "size": max(virtual_size, raw_size),
                    "raw_size": raw_size,
                    "raw_ptr": raw_ptr,
                }
            self.pe_sections_cache[cache_key] = sections
            return sections

    def _discover_function_addresses(self, module: dict):
        cache_key = (int(self.pm.process_id), int(module["base"]), str(module.get("path") or ""))
        with self.runtime_cache_lock:
            cached = self.function_addresses_cache.get(cache_key)
            if cached is not None:
                return cached
            sections = self._load_pe_sections(module)
            data_section = sections.get(".data")
            text_section = sections.get(".text")
            if not data_section or not text_section:
                raise RuntimeError("required PE sections not found")
            raw = self._read_raw(data_section["va"], data_section["size"])
            text_va = text_section["va"]
            text_end = text_va + text_section["size"]
            names = {}
            for off in range(0, max(0, len(raw) - 24), 8):
                name_ptr = struct.unpack_from("<Q", raw, off + 8)[0]
                code_ptr = struct.unpack_from("<Q", raw, off + 16)[0]
                if not (text_va <= code_ptr < text_end):
                    continue
                name = self._read_ascii_process(name_ptr)
                if name.startswith(("gml_Script_", "gml_GlobalScript_")):
                    names.setdefault(name, code_ptr)
            self.function_addresses_cache[cache_key] = names
            return names

    def _find_unique_bytes_in_function(self, function_address: int, function_addresses: list[int], needle: bytes):
        next_function = next((addr for addr in sorted(function_addresses) if addr > function_address), None)
        scan_size = 0x40000 if next_function is None else min(0x40000, max(0, next_function - function_address))
        code = self._read_raw(function_address, scan_size)
        matches = []
        pos = code.find(needle)
        while pos >= 0:
            matches.append(pos)
            if len(matches) > 1:
                return None
            pos = code.find(needle, pos + 1)
        return function_address + matches[0] if matches else None

    def _find_calls_to(self, function_address: int, function_addresses: list[int], target_address: int):
        next_function = next((addr for addr in sorted(function_addresses) if addr > function_address), None)
        scan_size = 0x40000 if next_function is None else min(0x40000, max(0, next_function - function_address))
        code = self._read_raw(function_address, scan_size)
        calls = []
        for offset in range(0, max(0, len(code) - 5)):
            if code[offset] != 0xE8:
                continue
            rel = struct.unpack_from("<i", code, offset + 1)[0]
            destination = function_address + offset + 5 + rel
            if destination == target_address:
                calls.append(function_address + offset)
        return calls

    def _read_movsd_constant(self, load_address: int):
        raw = self._read_raw(load_address, ANGELIC_MOVSD_SIZE)
        if raw[:4] != ANGELIC_MOVSD_PREFIX:
            raise RuntimeError(f"unexpected movsd bytes at {hex(load_address)}: {raw.hex(' ')}")
        disp = struct.unpack("<i", raw[4:8])[0]
        constant_address = load_address + ANGELIC_MOVSD_SIZE + disp
        return constant_address, struct.unpack("<d", self._read_raw(constant_address, 8))[0]

    def _rva_from_address(self, module: dict, address: int):
        return int(address) - int(module["base"])

    def _read_module_file_bytes(self, module: dict, rva: int, size: int):
        path = module.get("path") or ""
        if not path or not os.path.exists(path):
            raise RuntimeError(f"module path unavailable for {module.get('name')}")
        for section in self._load_pe_sections(module).values():
            virtual_address = int(section["rva"])
            section_size = int(section["size"])
            if virtual_address <= rva < virtual_address + section_size:
                file_offset = int(section["raw_ptr"]) + (rva - virtual_address)
                with open(path, "rb") as handle:
                    handle.seek(file_offset)
                    return handle.read(size)
        raise RuntimeError(f"RVA 0x{rva:x} is not inside a PE section")

    def _original_module_bytes(self, module: dict, address: int, size: int):
        return self._read_module_file_bytes(module, self._rva_from_address(module, address), size)

    @staticmethod
    def _function_extent(function_address: int, function_addresses: list[int], cap: int = 0x40000):
        next_function = next((addr for addr in sorted(set(function_addresses)) if addr > function_address), None)
        if next_function is None:
            return cap
        return max(0, min(cap, next_function - function_address))

    @staticmethod
    def _s10_has_bool_test_suffix(code: bytes, jump_offset: int):
        prefix = code[max(0, jump_offset - 3):jump_offset]
        return any(prefix.endswith(test) for test in S10_BOOL_TEST_SUFFIXES)

    @staticmethod
    def _is_s10_exp_factor_store(raw: bytes) -> bool:
        """Match MOVSD [rsp+0x40], xmmN for the verified EXP factor slot."""
        return bool(
            len(raw) == 7
            and raw[0] == 0xF2
            and 0x40 <= raw[1] <= 0x4F
            and raw[2:4] == b"\x0f\x11"
            and (raw[4] & 0xC7) == 0x44
            and raw[5:7] == b"\x24\x40"
        )

    def _resolve_s10_exp_factor_site(self, binding: StatBinding):
        resolver = binding.resolver or {}
        module_name = str(resolver.get("module") or PROCESS_NAME)
        module = self._hero_module(module_name)
        if not module:
            raise RuntimeError(f"{module_name} is not loaded")
        functions = self._discover_function_addresses(module)
        function_name = str(resolver.get("function_name") or "gml_Script_EnemyCalculateExperience")
        function_address = functions.get(function_name)
        if not function_address:
            raise RuntimeError(f"{function_name} was not found in the S10 runtime table")
        extent = self._function_extent(function_address, list(functions.values()))
        code = self._read_module_file_bytes(module, function_address - module["base"], extent)
        context = bytes.fromhex(str(resolver.get("context_hex") or S10_EXP_FACTOR_CONTEXT.hex(" ")))
        positions = []
        position = code.find(context)
        while position >= 0:
            positions.append(position)
            position = code.find(context, position + 1)

        store = bytes.fromhex(str(resolver.get("store_hex") or S10_EXP_FACTOR_STORE.hex(" ")))
        if len(positions) == 1:
            position = positions[0]
        elif not positions:
            # Hero Siege 7.0.5.0 assigns the same native 1.0 EXP factor to
            # XMM9 instead of XMM11.  Resolve the operation semantically: a
            # RIP-relative MOVSD loading the double 1.0 into an XMM register,
            # followed by that register being stored to the factor RValue at
            # [rsp+0x40] immediately before the same ownership-bit update.
            semantic_positions = []
            for candidate in range(0, max(0, len(code) - 10)):
                if code[candidate] != 0xF2 or not (0x40 <= code[candidate + 1] <= 0x4F):
                    continue
                if code[candidate + 2:candidate + 4] != b"\x0f\x11":
                    continue
                rex = code[candidate + 1]
                modrm = code[candidate + 4]
                if (modrm & 0xC7) != 0x44 or code[candidate + 5:candidate + 7] != b"\x24\x40":
                    continue
                if code[candidate + 7:candidate + 10] != b"\x83\xce\x10":
                    continue
                stored_register = ((modrm >> 3) & 7) + (8 if rex & 0x04 else 0)
                loaded_one = False
                for load_at in range(0, candidate):
                    if code[load_at] != 0xF2 or not (0x40 <= code[load_at + 1] <= 0x4F):
                        continue
                    if code[load_at + 2:load_at + 4] != b"\x0f\x10":
                        continue
                    load_rex = code[load_at + 1]
                    load_modrm = code[load_at + 4]
                    if (load_modrm & 0xC7) != 0x05:
                        continue
                    loaded_register = ((load_modrm >> 3) & 7) + (8 if load_rex & 0x04 else 0)
                    if loaded_register != stored_register:
                        continue
                    relative = struct.unpack_from("<i", code, load_at + 5)[0]
                    constant_rva = function_address - module["base"] + load_at + 9 + relative
                    constant_raw = self._read_module_file_bytes(module, constant_rva, 8)
                    if len(constant_raw) == 8 and struct.unpack("<d", constant_raw)[0] == 1.0:
                        loaded_one = True
                        break
                if loaded_one:
                    semantic_positions.append(candidate)
            if len(semantic_positions) != 1:
                raise RuntimeError(
                    "S10 EXP factor store must be unique; "
                    f"found {len(semantic_positions)} semantic matches"
                )
            position = semantic_positions[0]
            store = code[position:position + 7]
            context = store + b"\x83\xce\x10"
        else:
            raise RuntimeError(f"S10 EXP factor store must be unique; found {len(positions)} matches")

        site = function_address + position
        if code[position:position + len(store)] != store or not self._is_s10_exp_factor_store(store):
            raise RuntimeError("S10 EXP factor store bytes do not match the verified build")
        live_context = self._read_raw(site, len(context))
        live_is_owned_proxy = (
            len(live_context) == len(context)
            and live_context[:1] == b"\xe8"
            and live_context[5:7] == b"\x90\x90"
            and live_context[len(store):] == context[len(store):]
        )
        if live_context != context and not live_is_owned_proxy:
            raise RuntimeError(
                f"S10 EXP factor context is not clean at {hex(site)}: {live_context.hex(' ')}"
            )
        return module, site, store

    def _build_s10_exp_cave(self, multiplier: float):
        value_bits = struct.unpack("<Q", struct.pack("<d", float(multiplier)))[0]
        # A CALL lowers RSP by 8 and PUSH RAX lowers it by another 8.  The
        # caller's [rsp+0x40] factor slot is therefore [rsp+0x50] in the cave.
        return (
            b"\x50"
            + b"\x48\xb8" + struct.pack("<Q", value_bits)
            + bytes.fromhex("48 89 44 24 50")
            + b"\x58\xc3"
        )

    def _resolve_s10_rarity_proxy_sites(self, binding: StatBinding):
        resolver = binding.resolver or {}
        module_name = str(resolver.get("module") or PROCESS_NAME)
        module = self._hero_module(module_name)
        if not module:
            raise RuntimeError(f"{module_name} is not loaded")
        functions = self._discover_function_addresses(module)
        load_name = str(resolver.get("load_function") or "gml_Script_LoadDrops")
        source_name = str(resolver.get("source_function") or "gml_Script_DropFlask")
        target_name = str(resolver.get("target_function") or "gml_Script_DropItemAngelicChance")
        loot_name = str(resolver.get("loot_create_function") or "gml_Script_LootGroundCreate")
        load_drops = functions.get(load_name)
        source = functions.get(source_name)
        target = functions.get(target_name)
        loot_create = functions.get(loot_name)
        if None in (load_drops, source, target, loot_create):
            raise RuntimeError("S10 Angelic carrier symbols are incomplete")

        addresses = list(functions.values())
        load_extent = self._function_extent(load_drops, addresses)
        load_code = self._read_module_file_bytes(module, load_drops - module["base"], load_extent)
        source_calls = []
        for off in range(0, max(0, len(load_code) - 5)):
            if load_code[off] != 0xE8:
                continue
            relative = struct.unpack_from("<i", load_code, off + 1)[0]
            if load_drops + off + 5 + relative == source:
                source_calls.append(off)
        if len(source_calls) != 1:
            raise RuntimeError(f"Expected one S10 Flask carrier call; found {len(source_calls)}")
        call_off = source_calls[0]
        expected_argc = b"\x41\xb9" + struct.pack("<I", S10_RARITY_SOURCE_ARGC)
        setup_off = load_code.rfind(expected_argc, max(0, call_off - 0x80), call_off)
        if setup_off < 0:
            raise RuntimeError("S10 Flask four-argument setup was not found")

        original_call = load_code[call_off:call_off + 5]
        target_relative = target - (load_drops + call_off + 5)
        if not -(2**31) <= target_relative < 2**31:
            raise RuntimeError("S10 Angelic target is outside rel32 range")
        patched_call = b"\xe8" + struct.pack("<i", target_relative)

        outer_candidates = []
        for jump_off in range(max(0, call_off - 0x180), call_off - 5):
            if load_code[jump_off:jump_off + 2] not in (b"\x0f\x84", b"\x0f\x85"):
                continue
            if not self._s10_has_bool_test_suffix(load_code, jump_off):
                continue
            relative = struct.unpack_from("<i", load_code, jump_off + 2)[0]
            target_off = jump_off + 6 + relative
            if target_off > call_off + 0x100:
                outer_candidates.append((call_off - jump_off, jump_off))
        if not outer_candidates:
            raise RuntimeError("S10 Flask outer eligibility gate was not found")
        _distance, outer_off = min(outer_candidates)
        outer_original = load_code[outer_off:outer_off + 6]

        target_extent = self._function_extent(target, addresses)
        target_code = self._read_module_file_bytes(module, target - module["base"], target_extent)
        loot_calls = []
        for off in range(0, max(0, len(target_code) - 5)):
            if target_code[off] != 0xE8:
                continue
            relative = struct.unpack_from("<i", target_code, off + 1)[0]
            if target + off + 5 + relative == loot_create:
                loot_calls.append(off)
        if len(loot_calls) != 1:
            raise RuntimeError(f"Expected one Angelic LootGroundCreate call; found {len(loot_calls)}")
        loot_call_off = loot_calls[0]
        cmp_je = []
        test_jns = []
        for jump_off in range(0, max(0, loot_call_off - 5)):
            opcode = target_code[jump_off:jump_off + 2]
            if opcode not in (b"\x0f\x84", b"\x0f\x89"):
                continue
            relative = struct.unpack_from("<i", target_code, jump_off + 2)[0]
            target_off = jump_off + 6 + relative
            if not (loot_call_off < target_off <= loot_call_off + 0x80):
                continue
            if opcode == b"\x0f\x84" and target_code[max(0, jump_off - 3):jump_off] == b"\x83\xf8\xfe":
                cmp_je.append(jump_off)
            elif opcode == b"\x0f\x89" and target_code[max(0, jump_off - 2):jump_off] == b"\x85\xc0":
                test_jns.append(jump_off)
        if not cmp_je or not test_jns:
            raise RuntimeError("The two verified Angelic result exits were not found")

        result_offsets = (max(cmp_je), max(test_jns))
        sites = [
            (target + off, target_code[off:off + 6], NOP6)
            for off in result_offsets
        ]
        sites.append((load_drops + outer_off, outer_original, NOP6))
        sites.append((load_drops + call_off, original_call, patched_call))
        return module, sites

    def _original_movsd_constant(self, module: dict, load_address: int):
        original = self._original_module_bytes(module, load_address, ANGELIC_MOVSD_SIZE)
        if original[:4] != ANGELIC_MOVSD_PREFIX:
            raise RuntimeError(f"original file bytes are not movsd at {hex(load_address)}: {original.hex(' ')}")
        disp = struct.unpack("<i", original[4:8])[0]
        constant_address = load_address + ANGELIC_MOVSD_SIZE + disp
        constant_value = struct.unpack("<d", self._read_raw(constant_address, 8))[0]
        return original, constant_address, constant_value

    def _encode_movsd_constant(self, load_address: int, constant_address: int):
        rel = constant_address - (load_address + ANGELIC_MOVSD_SIZE)
        if not (-(1 << 31) <= rel <= (1 << 31) - 1):
            raise RuntimeError(f"allocated constant is too far from {hex(load_address)}")
        return ANGELIC_MOVSD_PREFIX + struct.pack("<i", rel)

    def _all_rel32_reachable(self, sites: list[int], target: int, instruction_size: int = ANGELIC_MOVSD_SIZE):
        return all((-(1 << 31) <= target - (site + instruction_size) <= (1 << 31) - 1) for site in sites)

    def _alloc_near_sites(self, sites: list[int], size: int, instruction_size: int = ANGELIC_MOVSD_SIZE):
        center = min(sites) & ~0xFFFF
        candidates = []
        # Try dense allocation-granularity slots first. This tolerates DLL/code
        # movement between builds without depending on executable padding.
        for step in range(1, 2049):
            distance = step * 0x10000
            candidates.append(center + distance)
            candidates.append(center - distance)
        # Then cover the remainder of rel32 range with sparse hints.
        for distance in range(0x09000000, 0x70000000, 0x01000000):
            candidates.append(center + distance)
            candidates.append(center - distance)
        candidates.append(0)
        for hint in candidates:
            address_hint = None if hint <= 0 else ctypes.c_void_p(hint & ~0xFFFF)
            allocated = kernel32.VirtualAllocEx(
                self.pm.process_handle,
                address_hint,
                ctypes.c_size_t(size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
            if not allocated:
                continue
            allocated_int = int(allocated)
            if self._all_rel32_reachable(sites, allocated_int, instruction_size):
                return allocated_int
            kernel32.VirtualFreeEx(self.pm.process_handle, ctypes.c_void_p(allocated_int), 0, MEM_RELEASE)
        raise RuntimeError("could not allocate a nearby Angelic rate constant")

    def _resolve_angelic_rate_sites(self, binding: StatBinding, resolver: dict):
        module_name = str(resolver.get("module") or PROCESS_NAME)
        mod = self._hero_module(module_name)
        if not mod:
            modules = list_modules(self.pm.process_id)
            seen = ", ".join(m["name"] for m in modules[:10]) or "none"
            raise RuntimeError(f"{module_name} not loaded. Seen modules: {seen}")
        sites = []
        try:
            functions = self._discover_function_addresses(mod)
            drop_item_name = str(resolver.get("drop_item_function") or "gml_Script_DropItem")
            chance_name = str(resolver.get("chance_function") or "gml_Script_DropItemAngelicChance")
            drop_item_address = functions.get(drop_item_name)
            chance_address = functions.get(chance_name)
            if not drop_item_address or not chance_address:
                raise RuntimeError("required Angelic functions were not found")
            calls = self._find_calls_to(drop_item_address, list(functions.values()), chance_address)
            if not calls:
                raise RuntimeError("DropItem -> DropItemAngelicChance call was not found")
            outer_delta = self._parse_int_setting(resolver.get("outer_call_to_load_delta", -0x123), "outer_call_to_load_delta")
            raw_inner_deltas = resolver.get("inner_load_deltas")
            if not bool(resolver.get("patch_inner_loads", True)):
                inner_deltas = []
            elif isinstance(raw_inner_deltas, list):
                inner_deltas = [self._parse_int_setting(delta, "inner_load_deltas") for delta in raw_inner_deltas]
            else:
                inner_deltas = [self._parse_int_setting(resolver.get("inner_load_delta", 0x105A), "inner_load_delta")]
            sites = [calls[0] + outer_delta] + [chance_address + delta for delta in inner_deltas]
            sites = list(dict.fromkeys(sites))
            for site in sites:
                raw = self._read_raw(site, ANGELIC_MOVSD_SIZE)
                if raw[:4] != ANGELIC_MOVSD_PREFIX:
                    raise RuntimeError(f"unexpected Angelic chance load bytes at {hex(site)}: {raw.hex(' ')}")
            return sites
        except Exception as exc:
            self.log_line(f"{binding.name}: function resolver fallback: {exc}")
            fallback_rvas = resolver.get("fallback_load_rvas") or []
            sites = [mod["base"] + self._parse_int_setting(rva, "fallback_load_rvas") for rva in fallback_rvas]
            for site in sites:
                raw = self._read_raw(site, ANGELIC_MOVSD_SIZE)
                if raw[:4] != ANGELIC_MOVSD_PREFIX:
                    raise RuntimeError(f"{binding.name}: fallback bytes do not match at {hex(site)}: {raw.hex(' ')}")
            if not sites:
                raise RuntimeError(f"{binding.name}: no fallback Angelic rate sites configured")
            return sites

    def _resolve_angelic_gate_sites(self, binding: StatBinding, resolver: dict):
        module_name = str(resolver.get("module") or PROCESS_NAME)
        mod = self._hero_module(module_name)
        if not mod:
            modules = list_modules(self.pm.process_id)
            seen = ", ".join(m["name"] for m in modules[:10]) or "none"
            raise RuntimeError(f"{module_name} not loaded. Seen modules: {seen}")
        try:
            functions = self._discover_function_addresses(mod)
            drop_item_name = str(resolver.get("drop_item_function") or "gml_Script_DropItem")
            chance_name = str(resolver.get("chance_function") or "gml_Script_DropItemAngelicChance")
            drop_item_address = functions.get(drop_item_name)
            chance_address = functions.get(chance_name)
            if not drop_item_address or not chance_address:
                raise RuntimeError("required Angelic functions were not found")
            calls = self._find_calls_to(drop_item_address, list(functions.values()), chance_address)
            if not calls:
                raise RuntimeError("DropItem -> DropItemAngelicChance call was not found")
            inner_delta = self._parse_int_setting(resolver.get("inner_gate_delta", 0x107C), "inner_gate_delta")
            sites = [chance_address + inner_delta]
            if bool(resolver.get("open_outer_gate", False)):
                outer_delta = self._parse_int_setting(resolver.get("outer_call_to_gate_delta", -0xE5), "outer_call_to_gate_delta")
                sites.insert(0, calls[0] + outer_delta)
        except Exception as exc:
            self.log_line(f"{binding.name}: gate resolver fallback: {exc}")
            fallback_key = "fallback_gate_rvas" if bool(resolver.get("open_outer_gate", False)) else "fallback_inner_gate_rvas"
            fallback_rvas = resolver.get(fallback_key) or resolver.get("fallback_gate_rvas") or []
            sites = [mod["base"] + self._parse_int_setting(rva, "fallback_gate_rvas") for rva in fallback_rvas]
        sites = list(dict.fromkeys(sites))
        if not sites:
            raise RuntimeError(f"{binding.name}: no Angelic gate sites configured")
        for site in sites:
            raw = self._read_raw(site, ANGELIC_GATE_SIZE)
            if raw != NOP6 and raw[:2] not in (b"\x0f\x8e", b"\x0f\x89"):
                raise RuntimeError(f"{binding.name}: unexpected Angelic gate bytes at {hex(site)}: {raw.hex(' ')}")
        return sites

    def _resolve_angelic_rate_address(self, binding: StatBinding, resolver: dict):
        return self._resolve_angelic_rate_sites(binding, resolver)[0]

    def _current_patch_bytes_are_compatible(self, raw_data: bytes, binding: StatBinding):
        decoded = self._decode_exe_patch_value(raw_data)
        if decoded is None:
            return False
        max_value = float(binding.resolver.get("max", binding.slider_max)) if binding.resolver else binding.slider_max
        return 0 < decoded <= max_value

    def _resolve_hero_exe_patch_address(self, binding: StatBinding, resolver: dict):
        module_name = str(resolver.get("module") or PROCESS_NAME)
        mod = self._hero_module(module_name)
        if not mod:
            modules = list_modules(self.pm.process_id)
            seen = ", ".join(m["name"] for m in modules[:10]) or "none"
            raise RuntimeError(f"{module_name} not loaded. Seen modules: {seen}")
        original = self._original_exe_patch_bytes(binding)
        function_name = str(resolver.get("function_name") or "").strip()
        if function_name:
            try:
                functions = self._discover_function_addresses(mod)
                function_address = functions.get(function_name)
                if function_address:
                    delta = self._parse_int_setting(resolver.get("function_delta", 0), "function_delta")
                    address = function_address + delta
                    current = self._read_raw(address, len(original))
                    if current == original or self._current_patch_bytes_are_compatible(current, binding):
                        return address
                    found = self._find_unique_bytes_in_function(function_address, list(functions.values()), original)
                    if found is not None:
                        return found
            except Exception as exc:
                self.log_line(f"{binding.name}: function resolver fallback: {exc}")
        rva = self._parse_int_setting(resolver.get("rva"), "rva")
        return mod["base"] + rva

    def _original_exe_patch_bytes(self, binding: StatBinding):
        original_hex = str(binding.resolver.get("original_hex") or "").strip() if binding.resolver else ""
        if not original_hex:
            raise RuntimeError(f"{binding.name}: missing original patch bytes.")
        return bytes.fromhex(original_hex)

    def _read_raw(self, address: int, size: int):
        return pymem.memory.read_bytes(self.pm.process_handle, address, size)

    def _resolve_ac_dll_table_entry(self, binding: StatBinding, resolver: dict):
        module_name = str(resolver.get("module") or "ac_dll_gm.dll")
        modules = list_modules(self.pm.process_id)
        mod = next((m for m in modules if m["name"].lower() == module_name.lower()), None)
        if not mod:
            seen = ", ".join(m["name"] for m in modules[:10]) or "none"
            raise RuntimeError(f"{module_name} not loaded yet. Seen modules: {seen}")

        self._verify_module_fingerprint(mod, resolver.get("module_sha256"), binding.name)

        table_rva = self._parse_int_setting(resolver.get("table_rva", AC_DLL_TABLE_RVA), "table_rva")
        key = self._parse_int_setting(resolver.get("key"), "key")
        page_size = self._parse_int_setting(resolver.get("page_size", AC_DLL_TABLE_PAGE_SIZE), "page_size")
        entry_size = self._parse_int_setting(resolver.get("entry_size", AC_DLL_TABLE_ENTRY_SIZE), "entry_size")

        page = key >> 9
        slot = key & 0x1FF
        entry = mod["base"] + table_rva + (page * page_size) + (slot * entry_size)
        try:
            value_address = read_ptr(self.pm.process_handle, entry)
        except Exception as exc:
            raise RuntimeError(
                f"{binding.name}: cannot read stat table entry {module_name}+0x{table_rva:x} key=0x{key:x}: {exc}"
            ) from exc
        if not value_address:
            raise RuntimeError(
                f"{binding.name}: stat table entry is empty. Enter a character/map once, then press Refresh Status."
            )
        return entry, value_address

    def _resolve_ac_dll_table_address(self, binding: StatBinding, resolver: dict):
        _entry, value_address = self._resolve_ac_dll_table_entry(binding, resolver)
        return value_address

    def _read_s10_ac_binding(self, binding: StatBinding):
        resolver = binding.resolver or {}
        entry, value_address = self._resolve_ac_dll_table_entry(binding, resolver)
        xor_offset = self._parse_int_setting(
            resolver.get("value_xor_offset", AC_DLL_VALUE_XOR_OFFSET), "value_xor_offset"
        )
        undefined_offset = self._parse_int_setting(
            resolver.get("undefined_offset", AC_DLL_UNDEFINED_OFFSET), "undefined_offset"
        )
        undefined = self._read_raw(entry + undefined_offset, 1)[0]
        if undefined:
            raise RuntimeError(f"{binding.name}: protected value is undefined")
        encrypted_bits = struct.unpack("<Q", self._read_raw(value_address, 8))[0]
        xor_key = struct.unpack("<Q", self._read_raw(entry + xor_offset, 8))[0]
        value_bits = encrypted_bits ^ xor_key
        return struct.unpack("<d", struct.pack("<Q", value_bits))[0]

    @staticmethod
    def _build_s10_stat_return_patch(value: float):
        # GameMaker YYC script ABI: R8 points to the 16-byte result RValue.
        # VALUE_REAL is kind 0.  The older kind 13 patch was VALUE_BOOL, which
        # made large Magic Find / Movement Speed values collapse to true/1 in
        # callers that honored the RValue type tag.
        value_bits = struct.unpack("<Q", struct.pack("<d", float(value)))[0]
        return (
            b"\x48\xb8" + struct.pack("<Q", value_bits)
            + S10_STAT_RETURN_PATCH_TAIL
        )

    @staticmethod
    def _is_supported_s10_stat_entry(raw: bytes):
        for prefix in S10_STAT_ENTRY_PREFIXES:
            for pushes in S10_STAT_ENTRY_PUSH_VARIANTS:
                expected = prefix + pushes
                if not raw.startswith(expected):
                    continue
                # The stack displacement may change between builds, while this
                # LEA shape and the YYC argument-save/push sequence remain
                # stable.
                tail = raw[len(expected):]
                if tail.startswith(b"\x48\x8d") and len(tail) >= 3 and tail[2] in (0xA8, 0xAC):
                    return True
        return False

    @staticmethod
    def _is_owned_s10_stat_return_patch(raw: bytes):
        if len(raw) != 10 + len(S10_STAT_RETURN_PATCH_TAIL):
            return False
        if raw[:2] != b"\x48\xb8" or raw[10:] not in (
            S10_STAT_RETURN_PATCH_TAIL,
            S10_STAT_LEGACY_BOOL_RETURN_PATCH_TAIL,
        ):
            return False
        value = struct.unpack("<d", raw[2:10])[0]
        return math.isfinite(value)

    def _resolve_s10_stat_return_site(self, binding: StatBinding):
        resolver = binding.resolver or {}
        module_name = str(resolver.get("module") or PROCESS_NAME)
        module = self._hero_module(module_name)
        if not module:
            raise RuntimeError(f"{module_name} not loaded")
        function_name = str(resolver.get("function_name") or "").strip()
        if not function_name:
            raise RuntimeError(f"{binding.name}: missing S10 stat function name")
        functions = self._discover_function_addresses(module)
        site = functions.get(function_name)
        if not site:
            raise RuntimeError(f"{binding.name}: {function_name} was not found in this build")
        patch_size = len(self._build_s10_stat_return_patch(0.0))
        original = self._original_module_bytes(module, site, patch_size)
        if not original or len(original) != patch_size:
            raise RuntimeError(f"{binding.name}: could not read original function entry")
        if not self._is_supported_s10_stat_entry(original):
            raise RuntimeError(
                f"{binding.name}: {function_name} has an unsupported entry layout; no write was made"
            )
        live = self._read_raw(site, patch_size)
        if live != original and not self._is_owned_s10_stat_return_patch(live):
            raise RuntimeError(
                f"{binding.name}: {function_name} entry differs from the executable; no write was made"
            )
        return module, site, original

    def _resolve_s10_result_epilogue_site(self, binding: StatBinding, function_name_override: str | None = None):
        """Find the unique final RValue-pointer load in a native YYC function."""
        resolver = binding.resolver or {}
        module_name = str(resolver.get("module") or PROCESS_NAME)
        module = self._hero_module(module_name)
        if not module:
            raise RuntimeError(f"{module_name} is not loaded")
        functions = self._discover_function_addresses(module)
        function_name = str(function_name_override or resolver.get("function_name") or "").strip()
        if not function_name:
            raise RuntimeError(f"{binding.name}: missing native result function name")
        function_address = functions.get(function_name)
        if not function_address:
            raise RuntimeError(f"{function_name} was not found in the Season 10 runtime table")
        extent = self._function_extent(function_address, list(functions.values()))
        code = self._read_module_file_bytes(
            module,
            function_address - int(module["base"]),
            extent,
        )
        candidates: list[tuple[int, bytes]] = []
        # The runtime name table contains only named YYC scripts; anonymous
        # helper code may sit between two named entries, so the real epilogue
        # is not guaranteed to be within a small tail window.
        scan_start = 0

        def has_verified_unwind(end: int) -> bool:
            tail = code[end:end + 0x90]
            return bool(
                b"\xc3" in tail
                and (
                    b"\x48\x81\xc4" in tail
                    or b"\x48\x83\xc4" in tail
                    or b"\x49\x8b\xe3" in tail
                )
            )

        for offset in range(scan_start, max(scan_start, len(code) - 14)):
            original = code[offset:offset + S10_RESULT_EPILOGUE_PATCH_SIZE]
            if original[:3] != b"\x48\x8b\x85":
                continue
            # A seven-byte MOV RAX,[RBP+disp32] is already large enough for
            # our CALL patch. The following instruction is used only to
            # prove this is a real function epilogue. CalculateEndDamage
            # restores its large frame with LEA R11,[RSP+disp32], while the
            # smaller Stat* functions restore XMM6 with MOVAPS.
            if code[offset + 7:offset + 11] not in (
                b"\x0f\x28\xb4\x24",
                b"\x4c\x8d\x9c\x24",
            ):
                continue
            if not has_verified_unwind(offset + 7):
                continue
            candidates.append((function_address + offset, original))

        if not candidates:
            # Several large Season 10 scripts keep the result pointer in R14
            # or R15.  The hook covers MOV RAX,R14/R15 plus exactly one full
            # adjacent epilogue instruction so no instruction is split.
            for offset in range(scan_start, max(scan_start, len(code) - 12)):
                if code[offset:offset + 2] != b"\x49\x8b" or code[offset + 2] not in (0xC6, 0xC7):
                    continue
                replay = code[offset + 3:offset + 7]
                if replay in (
                    b"\x0f\x28\xb4\x24",
                    b"\x4c\x8d\x9c\x24",
                    b"\x48\x8b\x9c\x24",
                ):
                    size = 11
                elif replay == b"\x48\x8b\x6c\x24":
                    size = 8
                else:
                    continue
                original = code[offset:offset + size]
                if not _is_verified_s10_result_prelude(original) or not has_verified_unwind(offset + size):
                    continue
                candidates.append((function_address + offset, original))
        if not candidates:
            # StatAttackSpeed keeps its huge calculated array in RBX and then
            # restores XMM6 from the stack.  This exact two-instruction shape
            # is distinct from ordinary internal MOV RAX,RBX uses.
            for offset in range(scan_start, max(scan_start, len(code) - 12)):
                original = code[offset:offset + 11]
                if original[:7] != b"\x48\x8b\xc3\x0f\x28\xb4\x24":
                    continue
                if not has_verified_unwind(offset + 11):
                    continue
                candidates.append((function_address + offset, original))
        if len(candidates) != 1:
            raise RuntimeError(
                f"{binding.name}: expected one native result epilogue in {function_name}, found {len(candidates)}"
            )
        site, original = candidates[0]
        if original[:3] == b"\x48\x8b\x85":
            # The adjacent instruction is part of the epilogue proof even
            # though the seven-byte CALL patch intentionally leaves it native.
            # Fail closed if another tool changed that live instruction.
            offset = site - function_address
            expected_context = code[offset + len(original):offset + len(original) + 8]
            live_context = self._read_raw(site + len(original), len(expected_context))
            if len(expected_context) != 8 or live_context != expected_context:
                raise RuntimeError(
                    f"{binding.name}: native result epilogue context differs from the executable"
                )
        live = self._read_raw(site, len(original))
        owned = len(live) == len(original) and live[:1] == b"\xe8" and all(byte == 0x90 for byte in live[5:])
        if live != original and not owned:
            raise RuntimeError(f"{binding.name}: native result epilogue contains an unknown patch")
        return module, site, original

    def _resolve_binding_address(self, binding: StatBinding):
        if binding.resolver:
            kind = str(binding.resolver.get("kind") or "").lower()
            if kind in (
                S10_ARRAY_RESULT_MULTIPLIER,
                S10_ARRAY_RESULT_ADDITIVE,
                S10_SCALAR_RESULT_MULTIPLIER,
            ):
                names = binding.resolver.get("function_names") or []
                first_name = str(names[0]).strip() if names else None
                _module, site, _original = self._resolve_s10_result_epilogue_site(binding, first_name)
                return site
            if kind == "ac_dll_table":
                return self._resolve_ac_dll_table_address(binding, binding.resolver)
            if kind == "s10_exp_factor_proxy":
                _module, site, _original = self._resolve_s10_exp_factor_site(binding)
                return site
            if kind == "s10_stat_return_proxy":
                _module, site, _original = self._resolve_s10_stat_return_site(binding)
                return site
            if kind == "s10_rarity_proxy":
                _module, sites = self._resolve_s10_rarity_proxy_sites(binding)
                return sites[0][0]
            if kind == "hero_exe_patch_double":
                return self._resolve_hero_exe_patch_address(binding, binding.resolver)
            if kind == "angelic_rate_multiplier":
                return self._resolve_angelic_rate_address(binding, binding.resolver)
            if kind == DENSITY_RESOLVER:
                return 0
            raise RuntimeError(f"{binding.name}: unknown resolver kind: {kind}")
        if binding.pointer:
            address, reason = explain_pointer_resolution(self.pm.process_handle, self.pm.process_id, binding.pointer)
            if not address:
                raise RuntimeError(reason)
            return address
        if binding.addr:
            text = binding.addr.strip()
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        raise RuntimeError(f"{binding.name}: no address or pointer binding set.")

    def _read_binding_value(self, binding: StatBinding, address: int):
        try:
            if self._is_density_binding(binding):
                if self.density_state and self.density_state.status == DENSITY_STATUS_READY:
                    return float(self.density_state.multiplier) if self.density_state.enabled else 1.0
                return 1.0
            if self._is_s10_result_binding(binding):
                payload = self.stat_multi_patches.get(binding.key)
                if not payload:
                    return 0.0 if self._is_s10_array_additive_binding(binding) else 1.0
                if "input_value" in payload:
                    return float(payload["input_value"])
                hook = (payload.get("hooks") or [payload])[0]
                raw = self._read_raw(int(hook["data_address"]), 32)
                native, scaled, counter, factor = struct.unpack("<ddQd", raw)
                if counter and math.isfinite(native) and math.isfinite(scaled):
                    return float(factor)
                return float(payload.get("factor", factor))
            if self._is_ac_dll_table_binding(binding):
                return self._read_s10_ac_binding(binding)
            if self._is_s10_exp_proxy_binding(binding):
                _module, site, original = self._resolve_s10_exp_factor_site(binding)
                current = self._read_raw(site, len(original))
                if current == original:
                    return 1.0
                if len(current) == 7 and current[0] == 0xE8 and current[5:] == b"\x90\x90":
                    relative = struct.unpack_from("<i", current, 1)[0]
                    cave = site + 5 + relative
                    cave_head = self._read_raw(cave, 11)
                    if cave_head[:3] == b"\x50\x48\xb8":
                        return struct.unpack("<d", cave_head[3:11])[0]
                raise RuntimeError(f"unexpected S10 EXP proxy bytes: {current.hex(' ')}")
            if self._is_s10_stat_return_proxy_binding(binding):
                _module, site, original = self._resolve_s10_stat_return_site(binding)
                current = self._read_raw(site, len(original))
                if current == original:
                    raise RuntimeError("native value is calculated at runtime")
                if self._is_owned_s10_stat_return_patch(current):
                    return struct.unpack("<d", current[2:10])[0]
                raise RuntimeError(f"unexpected S10 stat proxy bytes: {current.hex(' ')}")
            if self._is_s10_rarity_proxy_binding(binding):
                _module, sites = self._resolve_s10_rarity_proxy_sites(binding)
                states = []
                for site, original, patched in sites:
                    current = self._read_raw(site, len(original))
                    if current == original:
                        states.append(0)
                    elif current == patched:
                        states.append(1)
                    else:
                        raise RuntimeError(f"rarity proxy mismatch at {hex(site)}: {current.hex(' ')}")
                if all(state == 0 for state in states):
                    return 0.0
                if all(state == 1 for state in states):
                    return 1.0
                raise RuntimeError("rarity proxy is only partially applied")
            if self._is_angelic_rate_binding(binding):
                base_chance = float(binding.resolver.get("base_chance", ANGELIC_BASE_CHANCE))
                _constant_address, chance_value = self._read_movsd_constant(address)
                return chance_value / base_chance if base_chance else chance_value
            if self._is_exe_patch_binding(binding):
                raw = self._read_raw(address, len(self._original_exe_patch_bytes(binding)))
                decoded = self._decode_exe_patch_value(raw)
                if decoded is None:
                    raise RuntimeError(f"unexpected bytes: {raw.hex(' ')}")
                return decoded
            return read_value(self.pm.process_handle, address, binding.type_name)
        except Exception as exc:
            raise RuntimeError(f"{binding.name}: cannot read {hex(address)} ({exc})") from exc

    def _sync_slider_to_entry(self, key: str, value):
        var = self.stat_value_vars.get(key)
        if not var:
            return
        try:
            numeric = float(value)
            if abs(numeric - int(numeric)) < 1e-9:
                var.set(str(int(numeric)))
            else:
                var.set(f"{numeric:.4f}")
        except Exception:
            pass

    def _sync_entry_to_slider(self, key: str):
        var = self.stat_value_vars.get(key)
        slider = self.stat_slider_vars.get(key)
        if not var or not slider:
            return
        text = var.get().strip()
        if not text:
            return
        try:
            numeric = float(text)
        except Exception:
            return
        binding = self._find_binding(key)
        max_value = binding.slider_max if binding else 1000
        min_value = float((binding.resolver or {}).get("min", 0)) if binding else 0
        slider.set(max(min_value, min(max_value, numeric)))

    def _set_active_text(self):
        if not self.active_stat_keys:
            self.active_profile.set("NONE  •  NATIVE GAME VALUES")
            return
        names = []
        for key in self.active_stat_keys:
            binding = self._find_binding(key)
            if binding:
                names.append(binding.name)
        self.active_profile.set("  •  ".join(sorted(name.upper() for name in names)))

    def refresh_status(self):
        for binding in self.stat_bindings:
            btn = self.stat_buttons.get(binding.key)
            if not btn:
                continue
            is_on = binding.key in self.active_stat_keys
            self._configure_stat_toggle(binding, is_on)
            if self.attached and self.pm and binding.key not in self.active_stat_keys:
                if self._is_s10_stat_return_proxy_binding(binding):
                    current_var = self.stat_current_vars.get(binding.key)
                    if current_var:
                        current_var.set("Current: native")
                    continue
                try:
                    address = self._resolve_binding_address(binding)
                    value = self._read_binding_value(binding, address)
                    current_var = self.stat_current_vars.get(binding.key)
                    if current_var:
                        current_var.set(f"Current: {format_value(value, binding.type_name)}")
                except Exception:
                    current_var = self.stat_current_vars.get(binding.key)
                    if current_var:
                        current_var.set("Current: ?")
        self._set_active_text()
        self._sync_status_indicator()

    def _require(self):
        if not self.attached or not self.pm:
            messagebox.showwarning("Not Attached", "Attach to the game first!")
            return False
        return True

    def _detach_dead_process(self):
        """Forget runtime-only state after the target process has exited."""
        old_pid = self.selected_pid
        self._close_density_ipc()
        try:
            if self.pm:
                self.pm.close_process()
        except Exception:
            pass
        self.pm = None
        self.attached = False
        self.selected_pid = None
        self._main_module_cache = None
        self.function_addresses_cache.clear()
        self.pe_sections_cache.clear()
        self.active_stat_keys.clear()
        self.stat_multi_patches.clear()
        self.stat_original_bytes.clear()
        self.stat_frozen_bytes.clear()
        self.stat_frozen_addresses.clear()
        self.status.set("Hero_Siege.exe closed. Start the game, then press Attach / Select.")
        self.details.set("The game process ended. Runtime boosts were discarded with that process.")
        self.log_line(f"Game process ended (PID {old_pid}); stale runtime state cleared.")
        self.refresh_status()

    def toggle_stat(self, key: str):
        binding = self._find_binding(key)
        if not binding:
            return
        if key in self.active_stat_keys:
            self._disable_stat(binding)
        else:
            self._enable_stat(binding)
        self.refresh_status()

    def _enable_angelic_rate(self, binding: StatBinding, value_text: str):
        resolver = binding.resolver or {}
        module_name = str(resolver.get("module") or PROCESS_NAME)
        mod = self._hero_module(module_name)
        if not mod:
            raise RuntimeError(f"{module_name} not loaded.")
        multiplier = float(parse_value(value_text, binding.type_name))
        if multiplier <= 0:
            raise RuntimeError("multiplier must be greater than 0")
        base_chance = float(resolver.get("base_chance", ANGELIC_BASE_CHANCE))
        chance_value = base_chance * multiplier
        sites = self._resolve_angelic_rate_sites(binding, resolver)
        gate_sites = self._resolve_angelic_gate_sites(binding, resolver)
        originals = []
        original_multiplier = None
        for site in sites:
            raw, _original_constant_address, original_chance = self._original_movsd_constant(mod, site)
            originals.append(raw)
            if original_multiplier is None:
                original_multiplier = original_chance / base_chance if base_chance else original_chance

        constant_address = self._alloc_near_sites(sites, 8)
        self._write_memory(constant_address, struct.pack("<d", chance_value))
        patch_bytes = [self._encode_movsd_constant(site, constant_address) for site in sites]
        for site, raw in zip(sites, patch_bytes):
            self._write_memory(site, raw)
        gate_originals = [self._original_module_bytes(mod, site, ANGELIC_GATE_SIZE) for site in gate_sites]
        gate_patches = [NOP6 for _site in gate_sites]
        for site, raw in zip(gate_sites, gate_patches):
            self._write_memory(site, raw)

        self.stat_multi_patches[binding.key] = {
            "sites": sites,
            "originals": originals,
            "patches": patch_bytes,
            "gate_sites": gate_sites,
            "gate_originals": gate_originals,
            "gate_patches": gate_patches,
            "constant_address": constant_address,
            "constant_raw": struct.pack("<d", chance_value),
            "multiplier": multiplier,
        }
        binding.default_write = value_text
        self.active_stat_keys.add(binding.key)
        self._save_bindings()
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set(f"Current: {original_multiplier:.4g}x -> {multiplier:.4g}x")
        self.details.set(
            f"{binding.name}: {multiplier:.4g}x applied at {len(sites)} chance load site(s), "
            f"{len(gate_sites)} gate(s) opened."
        )
        self.log_line(
            f"{binding.name}: ON | {original_multiplier:.4g}x -> {multiplier:.4g}x "
            f"(chance {chance_value:.8g}) loads={', '.join(hex(site) for site in sites)} "
            f"gates={', '.join(hex(site) for site in gate_sites)}"
        )

    def _disable_angelic_rate(self, binding: StatBinding):
        payload = self.stat_multi_patches.get(binding.key)
        if payload:
            for site, raw in zip(payload.get("sites", []), payload.get("originals", [])):
                self._write_memory(site, raw)
            for site, raw in zip(payload.get("gate_sites", []), payload.get("gate_originals", [])):
                self._write_memory(site, raw)
            constant_address = payload.get("constant_address")
            if constant_address:
                kernel32.VirtualFreeEx(self.pm.process_handle, ctypes.c_void_p(int(constant_address)), 0, MEM_RELEASE)
        self.stat_multi_patches.pop(binding.key, None)
        self.active_stat_keys.discard(binding.key)
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            try:
                address = self._resolve_binding_address(binding)
                value = self._read_binding_value(binding, address)
                current_var.set(f"Current: {value:.4g}x")
            except Exception:
                current_var.set("Current: ?")
        self.details.set(f"{binding.name}: restored.")
        self.log_line(f"{binding.name}: OFF | Angelic rate loads restored.")

    def _enable_s10_ac_stat(self, binding: StatBinding, value_text: str):
        resolver = binding.resolver or {}
        entry, value_address = self._resolve_ac_dll_table_entry(binding, resolver)
        xor_offset = self._parse_int_setting(
            resolver.get("value_xor_offset", AC_DLL_VALUE_XOR_OFFSET), "value_xor_offset"
        )
        integrity_offset = self._parse_int_setting(
            resolver.get("integrity_offset", AC_DLL_INTEGRITY_OFFSET), "integrity_offset"
        )
        undefined_offset = self._parse_int_setting(
            resolver.get("undefined_offset", AC_DLL_UNDEFINED_OFFSET), "undefined_offset"
        )
        new_value = float(parse_value(value_text, binding.type_name))
        if not math.isfinite(new_value) or new_value < 0:
            raise RuntimeError(f"{binding.name}: value must be a finite number greater than or equal to zero")
        if "max" in resolver:
            max_value = float(resolver["max"])
            new_value = min(new_value, max_value)
        original_value = self._read_s10_ac_binding(binding)
        original_encrypted = self._read_raw(value_address, 8)
        original_integrity = self._read_raw(entry + integrity_offset, 8)
        original_undefined = self._read_raw(entry + undefined_offset, 1)
        original_xor = self._read_raw(entry + xor_offset, 8)
        xor_key = struct.unpack("<Q", original_xor)[0]
        value_bits = struct.unpack("<Q", struct.pack("<d", new_value))[0]
        encrypted_raw = struct.pack("<Q", value_bits ^ xor_key)
        integrity_raw = struct.pack("<Q", self._s10_integrity_value(value_bits, xor_key))
        # Freeze the XOR seed together with the encrypted value and integrity
        # word.  S10 may rotate the seed; writing only the value would then
        # decode to garbage and trip the integrity check.
        sites = [value_address, entry + integrity_offset, entry + xor_offset, entry + undefined_offset]
        originals = [original_encrypted, original_integrity, original_xor, original_undefined]
        patches = [encrypted_raw, integrity_raw, original_xor, b"\x00"]

        self._write_patch_group(sites, patches)
        confirmed = self._read_s10_ac_binding(binding)
        if not abs(confirmed - new_value) <= max(1e-9, abs(new_value) * 1e-12):
            self._write_patch_group(sites, originals)
            raise RuntimeError(f"protected value verification failed ({confirmed!r} != {new_value!r})")

        self.stat_multi_patches[binding.key] = {
            "kind": "s10_ac_dll_table",
            "sites": sites,
            "originals": originals,
            "patches": patches,
        }
        binding.default_write = value_text
        self.active_stat_keys.add(binding.key)
        self._save_bindings()
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set(
                f"Current: {format_value(original_value, binding.type_name)} -> "
                f"{format_value(new_value, binding.type_name)}"
            )
        self.details.set(f"{binding.name}: Season 10 protected value applied and frozen.")
        self.log_line(
            f"{binding.name}: ON | {format_value(original_value, binding.type_name)} -> "
            f"{format_value(new_value, binding.type_name)} @ {hex(value_address)} (S10 protected table)"
        )

    def _disable_s10_ac_stat(self, binding: StatBinding):
        payload = self.stat_multi_patches.get(binding.key)
        if payload and payload.get("kind") == "s10_ac_dll_table":
            self._write_patch_group(payload.get("sites", []), payload.get("originals", []))
        self.stat_multi_patches.pop(binding.key, None)
        self.active_stat_keys.discard(binding.key)
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            try:
                current_var.set(f"Current: {format_value(self._read_s10_ac_binding(binding), binding.type_name)}")
            except Exception:
                current_var.set("Current: ?")
        self.details.set(f"{binding.name}: original Season 10 protected value restored.")
        self.log_line(f"{binding.name}: OFF | original S10 protected value restored.")

    def _enable_s10_stat_return_proxy(self, binding: StatBinding, value_text: str):
        new_value = float(parse_value(value_text, binding.type_name))
        if not math.isfinite(new_value):
            raise RuntimeError(f"{binding.name}: value must be finite")
        resolver = binding.resolver or {}
        if "max" in resolver:
            new_value = min(new_value, float(resolver["max"]))
        _module, site, original = self._resolve_s10_stat_return_site(binding)
        patch = self._build_s10_stat_return_patch(new_value)
        current = self._read_raw(site, len(original))
        if current != original:
            if not self._is_owned_s10_stat_return_patch(current):
                raise RuntimeError(f"{binding.name}: stat function entry is not clean; no write was made")
        self._write_patch_group([site], [patch])
        if self._read_raw(site, len(patch)) != patch:
            self._write_patch_group([site], [original])
            raise RuntimeError(f"{binding.name}: S10 return proxy verification failed")
        self.stat_multi_patches[binding.key] = {
            "kind": "s10_stat_return_proxy",
            "sites": [site],
            "originals": [original],
            "patches": [patch],
        }
        binding.default_write = str(int(new_value) if new_value.is_integer() else new_value)
        self.active_stat_keys.add(binding.key)
        self._save_bindings()
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set(f"Current: native -> {new_value:g}")
        self.details.set(f"{binding.name}: native S10 stat result set to {new_value:g}.")
        self.log_line(f"{binding.name}: ON | native S10 return -> {new_value:g} @ {hex(site)}")

    def _disable_s10_stat_return_proxy(self, binding: StatBinding):
        payload = self.stat_multi_patches.get(binding.key)
        if payload and payload.get("kind") == "s10_stat_return_proxy":
            sites = payload.get("sites", [])
            originals = payload.get("originals", [])
            self._write_patch_group(sites, originals)
            if any(self._read_raw(site, len(original)) != original for site, original in zip(sites, originals)):
                raise RuntimeError(f"{binding.name}: native entry restore verification failed")
        self.stat_multi_patches.pop(binding.key, None)
        self.active_stat_keys.discard(binding.key)
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set("Current: native")
        self.details.set(f"{binding.name}: native S10 calculation restored.")
        self.log_line(f"{binding.name}: OFF | native S10 stat function restored.")

    def _enable_s10_exp_proxy(self, binding: StatBinding, value_text: str):
        resolver = binding.resolver or {}
        multiplier = float(parse_value(value_text, binding.type_name))
        if not math.isfinite(multiplier) or multiplier <= 0:
            raise RuntimeError("EXP multiplier must be greater than zero")
        max_value = float(resolver.get("max", binding.slider_max))
        multiplier = min(multiplier, max_value)
        module, site, original = self._resolve_s10_exp_factor_site(binding)
        current = self._read_raw(site, len(original))
        cave_raw = self._build_s10_exp_cave(multiplier)
        cave = 0
        if current == original:
            cave = self._alloc_near_sites([site], len(cave_raw), instruction_size=5)
        elif len(current) == 7 and current[0] == 0xE8 and current[5:] == b"\x90\x90":
            existing_relative = struct.unpack_from("<i", current, 1)[0]
            existing_cave = site + 5 + existing_relative
            existing_raw = self._read_raw(existing_cave, len(cave_raw))
            if (
                existing_raw[:3] != b"\x50\x48\xb8"
                or existing_raw[11:] != bytes.fromhex("48 89 44 24 50 58 c3")
            ):
                raise RuntimeError("S10 EXP site contains an unknown proxy; no write was made")
            cave = existing_cave
        else:
            raise RuntimeError(f"S10 EXP factor site is not clean: {current.hex(' ')}")

        relative = cave - (site + 5)
        if not -(2**31) <= relative < 2**31:
            kernel32.VirtualFreeEx(self.pm.process_handle, ctypes.c_void_p(cave), 0, MEM_RELEASE)
            raise RuntimeError("S10 EXP cave is outside rel32 range")
        patch = b"\xe8" + struct.pack("<i", relative) + b"\x90\x90"
        try:
            self._write_patch_group([cave, site], [cave_raw, patch])
            if self._read_raw(site, len(patch)) != patch:
                raise RuntimeError("S10 EXP proxy write did not stick")
        except Exception:
            try:
                self._write_patch_group([site], [original])
            finally:
                kernel32.VirtualFreeEx(self.pm.process_handle, ctypes.c_void_p(cave), 0, MEM_RELEASE)
            raise

        self.stat_multi_patches[binding.key] = {
            "kind": "s10_exp_factor_proxy",
            "sites": [site],
            "originals": [original],
            "patches": [patch],
            "constant_address": cave,
            "constant_raw": cave_raw,
            "module_path": module.get("path"),
            "multiplier": multiplier,
        }
        binding.default_write = str(int(multiplier) if multiplier.is_integer() else multiplier)
        self.active_stat_keys.add(binding.key)
        self._save_bindings()
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set(f"Current: 1 -> {multiplier:g}x")
        self.details.set(f"{binding.name}: native S10 final experience factor set to {multiplier:g}x.")
        self.log_line(f"{binding.name}: ON | S10 final factor 1 -> {multiplier:g}x @ {hex(site)}")

    def _disable_s10_exp_proxy(self, binding: StatBinding):
        payload = self.stat_multi_patches.get(binding.key)
        if payload and payload.get("kind") == "s10_exp_factor_proxy":
            sites = payload.get("sites", [])
            originals = payload.get("originals", [])
            self._write_patch_group(sites, originals)
            if any(self._read_raw(site, len(original)) != original for site, original in zip(sites, originals)):
                raise RuntimeError(f"{binding.name}: native EXP store restore verification failed")
            cave = payload.get("constant_address")
            if cave:
                kernel32.VirtualFreeEx(self.pm.process_handle, ctypes.c_void_p(int(cave)), 0, MEM_RELEASE)
        self.stat_multi_patches.pop(binding.key, None)
        self.active_stat_keys.discard(binding.key)
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set("Current: 1")
        self.details.set(f"{binding.name}: native S10 experience factor restored.")
        self.log_line(f"{binding.name}: OFF | native S10 factor restored.")

    def _enable_s10_rarity_proxy(self, binding: StatBinding):
        _module, site_records = self._resolve_s10_rarity_proxy_sites(binding)
        sites = [site for site, _original, _patched in site_records]
        originals = [original for _site, original, _patched in site_records]
        patches = [patched for _site, _original, patched in site_records]
        for site, original, patched in site_records:
            current = self._read_raw(site, len(original))
            if current not in (original, patched):
                raise RuntimeError(f"S10 rarity proxy mismatch at {hex(site)}: {current.hex(' ')}")
        self._write_patch_group(sites, patches)
        if any(self._read_raw(site, len(patch)) != patch for site, patch in zip(sites, patches)):
            self._write_patch_group(list(reversed(sites)), list(reversed(originals)))
            raise RuntimeError("S10 rarity proxy verification failed")
        self.stat_multi_patches[binding.key] = {
            "kind": "s10_rarity_proxy",
            "sites": sites,
            "originals": originals,
            "patches": patches,
        }
        self.active_stat_keys.add(binding.key)
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set("Current: S10 route active")
        self.details.set(f"{binding.name}: verified S10 Flask carrier redirected to AngelicChance.")
        self.log_line(f"{binding.name}: ON | verified S10 rarity proxy ({len(sites)} sites).")

    def _disable_s10_rarity_proxy(self, binding: StatBinding):
        payload = self.stat_multi_patches.get(binding.key)
        if payload and payload.get("kind") == "s10_rarity_proxy":
            sites = list(reversed(payload.get("sites", [])))
            originals = list(reversed(payload.get("originals", [])))
            self._write_patch_group(sites, originals)
            if any(self._read_raw(site, len(original)) != original for site, original in zip(sites, originals)):
                raise RuntimeError(f"{binding.name}: rarity route restore verification failed")
        self.stat_multi_patches.pop(binding.key, None)
        self.active_stat_keys.discard(binding.key)
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set("Current: S10 route off")
        self.details.set(f"{binding.name}: verified S10 rarity proxy restored.")
        self.log_line(f"{binding.name}: OFF | S10 rarity proxy restored.")

    def _enable_s10_result_modifier(self, binding: StatBinding, value_text: str):
        resolver = binding.resolver or {}
        input_value = float(parse_value(value_text, binding.type_name))
        if not math.isfinite(input_value) or input_value < 0:
            raise RuntimeError(f"{binding.name}: value must be zero or greater")
        input_value = min(input_value, float(resolver.get("max", binding.slider_max)))
        input_mode = str(resolver.get("input_mode") or "multiplier").lower()
        kind = str(resolver.get("kind") or "").lower()
        additive = kind == S10_ARRAY_RESULT_ADDITIVE or input_mode == "additive"
        array_result = kind in (S10_ARRAY_RESULT_MULTIPLIER, S10_ARRAY_RESULT_ADDITIVE)
        modifier = input_value if additive else (1.0 + input_value / 100.0 if input_mode == "bonus_percent" else input_value)
        if not additive and modifier <= 0:
            raise RuntimeError(f"{binding.name}: multiplier must be greater than zero")

        raw_names = resolver.get("function_names")
        if raw_names:
            function_names = [str(item).strip() for item in raw_names if str(item).strip()]
        else:
            name = str(resolver.get("function_name") or "").strip()
            function_names = [name] if name else []
        if not function_names:
            raise RuntimeError(f"{binding.name}: no native result function configured")

        with self.runtime_cache_lock:
            resolved = []
            seen_sites = set()
            for function_name in function_names:
                _module, site, original = self._resolve_s10_result_epilogue_site(binding, function_name)
                if site in seen_sites:
                    raise RuntimeError(f"{binding.name}: duplicate native hook site for {function_name}")
                seen_sites.add(site)
                current = self._read_raw(site, len(original))
                if current != original:
                    raise RuntimeError(
                        f"{binding.name}: {function_name} is already occupied; close old StatForge copies or restart the game"
                    )
                resolved.append((function_name, site, original))

            hooks = []
            for function_name, site, original in resolved:
                cave = self._alloc_near_sites(
                    [site],
                    S10_RESULT_HOOK_ALLOCATION_SIZE,
                    instruction_size=5,
                )
                if array_result:
                    blob = build_s10_array_result_hook_blob(
                        cave,
                        original,
                        modifier,
                        additive=additive,
                    )
                else:
                    blob = build_s10_scalar_result_hook_blob(cave, original, modifier)
                patch = build_s10_result_epilogue_patch(cave, site, len(original))
                self._write_memory(cave, blob)
                hooks.append({
                    "function_name": function_name,
                    "code_site": int(site),
                    "code_original": bytes(original),
                    "code_patch": bytes(patch),
                    "cave": int(cave),
                    "data_address": int(cave) + S10_RESULT_HOOK_DATA_OFFSET,
                })

            installed = []
            try:
                for hook in hooks:
                    self._write_code_when_quiescent(hook["code_site"], hook["code_patch"])
                    if self._read_raw(hook["code_site"], len(hook["code_patch"])) != hook["code_patch"]:
                        raise RuntimeError(
                            f"{binding.name}: {hook['function_name']} result hook verification failed"
                        )
                    installed.append(hook)
            except Exception:
                for hook in reversed(installed):
                    try:
                        if self._read_raw(hook["code_site"], len(hook["code_original"])) == hook["code_patch"]:
                            self._write_code_when_quiescent(hook["code_site"], hook["code_original"])
                    except Exception:
                        pass
                raise

            payload = {
                "kind": kind,
                "hooks": hooks,
                "modifier": float(modifier),
                "factor": float(modifier),
                "input_value": float(input_value),
                "input_mode": input_mode,
                "additive": bool(additive),
                "array_result": bool(array_result),
            }
            self.stat_multi_patches[binding.key] = payload
            self.active_stat_keys.add(binding.key)
            binding.default_write = str(int(input_value) if input_value.is_integer() else input_value)
            self._save_bindings()

        current_var = self.stat_current_vars.get(binding.key)
        if additive:
            summary = f"native + {modifier:g}"
        elif input_mode == "bonus_percent":
            summary = f"native + {input_value:g}% (× {modifier:g})"
        else:
            summary = f"native × {modifier:g}"
        if current_var:
            current_var.set(f"Current: {summary} (waiting for game call)")
        self.details.set(f"{binding.name}: {summary} will be applied to the game's final native result.")
        sites_text = ", ".join(hex(hook["code_site"]) for hook in hooks)
        self.log_line(
            f"{binding.name}: ON | {summary} @ {sites_text} | "
            f"{len(hooks)} verified native function(s)"
        )

    def _disable_s10_result_modifier(self, binding: StatBinding):
        with self.runtime_cache_lock:
            payload = self.stat_multi_patches.get(binding.key)
            if payload:
                hooks = list(payload.get("hooks") or [payload])
                array_result = bool(payload.get("array_result", self._is_s10_array_result_binding(binding)))
                if array_result:
                    for hook in hooks:
                        data = int(hook["data_address"])
                        try:
                            before = struct.unpack("<Q", self._read_raw(data + 0x38, 8))[0]
                            self._write_memory(data + 0x30, struct.pack("<Q", 0))
                            deadline = time.time() + 0.35
                            while time.time() < deadline:
                                after = struct.unpack("<Q", self._read_raw(data + 0x38, 8))[0]
                                if after != before:
                                    break
                                time.sleep(0.01)
                        except Exception:
                            pass
                for hook in reversed(hooks):
                    site = int(hook["code_site"])
                    original = bytes(hook["code_original"])
                    patch = bytes(hook["code_patch"])
                    current = self._read_raw(site, len(original))
                    if current == patch:
                        self._write_code_when_quiescent(site, original)
                    elif current != original:
                        raise RuntimeError(
                            f"{binding.name}: {hook.get('function_name', 'result hook')} is no longer owned by StatForge"
                        )
                    if self._read_raw(site, len(original)) != original:
                        raise RuntimeError(
                            f"{binding.name}: {hook.get('function_name', 'native result')} restore verification failed"
                        )
            self.stat_multi_patches.pop(binding.key, None)
            self.active_stat_keys.discard(binding.key)

        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set("Current: native calculation")
        self.details.set(f"{binding.name}: native game calculation restored.")
        self.log_line(f"{binding.name}: OFF | all native result hooks restored.")

    def _density_module_loaded(self):
        if not self.selected_pid:
            return False
        try:
            return any(
                module.get("name", "").lower() == DENSITY_DLL_NAME.lower()
                for module in list_modules(self.selected_pid)
            )
        except Exception:
            return False

    @staticmethod
    def _density_message(state: DensitySharedState):
        return bytes(state.message).split(b"\0", 1)[0].decode("utf-8", errors="replace")

    def _close_density_ipc(self):
        mapping = self.density_mapping
        self.density_state = None
        self.density_mapping = None
        if mapping:
            try:
                mapping.close()
            except Exception:
                pass

    def _enable_density(self, binding: StatBinding, value_text: str):
        resolver_mode = "loaded runtime"
        multiplier = float(parse_value(value_text, binding.type_name))
        minimum = float((binding.resolver or {}).get("min", 1))
        maximum = float((binding.resolver or {}).get("max", 5))
        step = float((binding.resolver or {}).get("step", 0.5))
        if not math.isfinite(multiplier) or not minimum <= multiplier <= maximum:
            raise RuntimeError(f"choose a value between {minimum:g}x and {maximum:g}x")
        snapped = round((multiplier - minimum) / step) * step + minimum
        if abs(snapped - multiplier) > 1e-6:
            raise RuntimeError(f"use {step:g}x steps (for example 1.5x, 2x, or 2.5x)")
        multiplier = snapped

        if self.density_state and self.density_state.status == DENSITY_STATUS_READY:
            state = self.density_state
        else:
            if self._density_module_loaded():
                raise RuntimeError(
                    "an older standalone density runtime is still unloading; wait a few seconds or restart the game"
                )
            self._close_density_ipc()
            mapping = mmap.mmap(
                -1,
                ctypes.sizeof(DensitySharedState),
                tagname=f"Local\\HSStatForgeDensity_{self.selected_pid}",
                access=mmap.ACCESS_WRITE,
            )
            state = DensitySharedState.from_buffer(mapping)
            ctypes.memset(ctypes.addressof(state), 0, ctypes.sizeof(state))
            state.magic = DENSITY_MAGIC
            state.version = DENSITY_VERSION
            state.size = ctypes.sizeof(state)
            state.multiplier = 1.0
            state.host_heartbeat = kernel32.GetTickCount64()
            resolver_mode = "adaptive scan"
            try:
                game_module = self._hero_module(PROCESS_NAME)
                fingerprint = self._module_fingerprint(game_module, "Monster Density")
                fast_path = DENSITY_FAST_PATHS.get(fingerprint)
                if fast_path:
                    module_base = int(game_module["base"])
                    state.depth_address = module_base + int(fast_path["depth_rva"])
                    state.layer_address = module_base + int(fast_path["layer_rva"])
                    creator_indices = tuple(int(value) for value in fast_path["creator_indices"])
                    state.creator_count = len(creator_indices)
                    for index, object_index in enumerate(creator_indices):
                        state.creator_indices[index] = object_index
                    resolver_mode = "verified fast path"
            except Exception:
                # Fingerprinting is only an optimization. If the executable is
                # unusual or temporarily locked, the DLL's adaptive resolver
                # remains the safe fallback.
                pass
            self.density_mapping = mapping
            self.density_state = state

            dll_path = os.path.abspath(runtime_resource_path(DENSITY_DLL_NAME))
            if not os.path.isfile(dll_path):
                self._close_density_ipc()
                raise RuntimeError(f"{DENSITY_DLL_NAME} is missing from the StatForge package")
            pymem.process.inject_dll_from_path(self.pm.process_handle, dll_path)
            deadline = time.time() + 30.0
            while time.time() < deadline:
                state.host_heartbeat = kernel32.GetTickCount64()
                if state.status == DENSITY_STATUS_READY:
                    break
                if state.status >= DENSITY_STATUS_ERROR:
                    break
                time.sleep(0.05)
            if state.status != DENSITY_STATUS_READY:
                error = self._density_message(state) or "standalone density resolver timed out"
                code = int(state.last_error)
                state.enabled = 0
                state.multiplier = 1.0
                state.shutdown = 1
                time.sleep(0.2)
                self._close_density_ipc()
                raise RuntimeError(f"{error} (error {code})")
            if state.creator_count < 7 or not state.depth_address or not state.layer_address:
                state.shutdown = 1
                time.sleep(0.2)
                self._close_density_ipc()
                raise RuntimeError("standalone density verification failed; no boost was enabled")

        state.multiplier = multiplier
        state.host_heartbeat = kernel32.GetTickCount64()
        state.enabled = 1
        self.stat_multi_patches[binding.key] = {
            "kind": DENSITY_RESOLVER,
            "last_creator_matches": int(state.creator_matches),
            "last_extra_creators": int(state.extra_creators),
            "last_capacity_skips": int(state.capacity_skips),
        }
        self.active_stat_keys.add(binding.key)
        binding.default_write = str(int(multiplier) if multiplier.is_integer() else multiplier)
        self._save_bindings()
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set(f"Current: {multiplier:g}x | waiting for a new zone")
        self.details.set(
            f"{binding.name}: {multiplier:g}x ready. Enter or reload a zone to create the extra enemies."
        )
        self.log_line(
            f"{binding.name}: ON | {multiplier:g}x | standalone runtime, "
            f"{state.creator_count} creator routes verified ({resolver_mode}), no YYToolkit dependency."
        )

    def _disable_density(self, binding: StatBinding):
        if self.density_state:
            self.density_state.enabled = 0
            self.density_state.multiplier = 1.0
            self.density_state.shutdown = 1
            deadline = time.time() + 4.0
            while time.time() < deadline and self._density_module_loaded():
                time.sleep(0.05)
        self._close_density_ipc()
        self.stat_multi_patches.pop(binding.key, None)
        self.active_stat_keys.discard(binding.key)
        current_var = self.stat_current_vars.get(binding.key)
        if current_var:
            current_var.set("Current: 1x native")
        self.details.set(f"{binding.name}: native 1x enemy creation restored.")
        self.log_line(f"{binding.name}: OFF | hooks removed and standalone DLL unloaded.")

    def _enable_stat(self, binding: StatBinding):
        if not self._require():
            return
        blocker_key = self._conflicting_active_key(binding)
        if blocker_key:
            blocker = self._find_binding(blocker_key)
            blocker_name = blocker.name if blocker else blocker_key
            self.log_line(f"{binding.name}: turn off {blocker_name} first; both modes patch StatAllSkills.")
            self.details.set(f"{binding.name}: disable {blocker_name} before enabling this mode.")
            return
        value_text = self.stat_value_vars.get(binding.key).get().strip() if self.stat_value_vars.get(binding.key) else ""
        if not value_text:
            self.log_line(f"{binding.name}: enter a value first.")
            return
        try:
            if self._is_density_binding(binding):
                self._enable_density(binding, value_text)
                return
            if self._is_s10_result_binding(binding):
                self._enable_s10_result_modifier(binding, value_text)
                return
            if self._is_ac_dll_table_binding(binding):
                self._enable_s10_ac_stat(binding, value_text)
                return
            if self._is_s10_stat_return_proxy_binding(binding):
                self._enable_s10_stat_return_proxy(binding, value_text)
                return
            if self._is_s10_exp_proxy_binding(binding):
                self._enable_s10_exp_proxy(binding, value_text)
                return
            if self._is_s10_rarity_proxy_binding(binding):
                self._enable_s10_rarity_proxy(binding)
                return
            if self._is_angelic_rate_binding(binding):
                self._enable_angelic_rate(binding, value_text)
                return
            address = self._resolve_binding_address(binding)
            new_value = parse_value(value_text, binding.type_name)
            if binding.resolver and "max" in binding.resolver and not self._is_exe_patch_binding(binding):
                max_value = float(binding.resolver["max"])
                if float(new_value) > max_value:
                    new_value = max_value
                    value_text = str(int(max_value) if max_value.is_integer() else max_value)
                    value_var = self.stat_value_vars.get(binding.key)
                    if value_var:
                        value_var.set(value_text)
            if self._is_exe_patch_binding(binding):
                original_raw = self._original_exe_patch_bytes(binding)
                current_raw = self._read_raw(address, len(original_raw))
                current_value = self._decode_exe_patch_value(current_raw)
                if current_value is None:
                    raise RuntimeError(f"unexpected bytes at EXP patch site: {current_raw.hex(' ')}")
                new_raw = self._encode_exe_patch_value(float(new_value))
                original_value = current_value
            else:
                original_value = self._read_binding_value(binding, address)
                original_raw = pack_value(original_value, binding.type_name)
                new_raw = pack_value(new_value, binding.type_name)

            self.stat_original_bytes[binding.key] = original_raw
            self.stat_frozen_bytes[binding.key] = new_raw
            self.stat_frozen_addresses[binding.key] = address
            self._write_memory(address, new_raw)

            binding.default_write = value_text
            self.active_stat_keys.add(binding.key)
            self._save_bindings()
            current_var = self.stat_current_vars.get(binding.key)
            if current_var:
                current_var.set(
                    f"Current: {format_value(original_value, binding.type_name)} -> {format_value(new_value, binding.type_name)}"
                )
            self.details.set(f"{binding.name}: {format_value(new_value, binding.type_name)} applied and frozen at {hex(address)}.")
            self.log_line(
                f"{binding.name}: ON | {format_value(original_value, binding.type_name)} -> "
                f"{format_value(new_value, binding.type_name)} @ {hex(address)}"
            )
        except Exception as exc:
            self.details.set(f"{binding.name}: failed - {exc}")
            self.log_line(f"{binding.name}: enable failed: {exc}")

    def _disable_stat(self, binding: StatBinding):
        if not self._require():
            return
        try:
            if self._is_density_binding(binding):
                self._disable_density(binding)
                return
            if self._is_s10_result_binding(binding):
                self._disable_s10_result_modifier(binding)
                return
            if self._is_ac_dll_table_binding(binding):
                self._disable_s10_ac_stat(binding)
                return
            if self._is_s10_stat_return_proxy_binding(binding):
                self._disable_s10_stat_return_proxy(binding)
                return
            if self._is_s10_exp_proxy_binding(binding):
                self._disable_s10_exp_proxy(binding)
                return
            if self._is_s10_rarity_proxy_binding(binding):
                self._disable_s10_rarity_proxy(binding)
                return
            if self._is_angelic_rate_binding(binding):
                self._disable_angelic_rate(binding)
                return
            address = self.stat_frozen_addresses.get(binding.key)
            original_raw = self.stat_original_bytes.get(binding.key)
            if address is not None and original_raw is not None:
                self._write_memory(address, original_raw)
            self.active_stat_keys.discard(binding.key)
            self.stat_original_bytes.pop(binding.key, None)
            self.stat_frozen_bytes.pop(binding.key, None)
            self.stat_frozen_addresses.pop(binding.key, None)
            try:
                restored_value = self._read_binding_value(binding, address)
                current_var = self.stat_current_vars.get(binding.key)
                if current_var:
                    current_var.set(f"Current: {format_value(restored_value, binding.type_name)}")
            except Exception:
                pass
            self.details.set(f"{binding.name}: restored.")
            self.log_line(f"{binding.name}: OFF | original value restored.")
        except Exception as exc:
            self.details.set(f"{binding.name}: restore failed - {exc}")
            self.log_line(f"{binding.name}: disable failed: {exc}")

    def _poll_result_telemetry(self):
        """Show evidence from the game calls instead of only reporting a patch write."""
        try:
            now = time.time()
            if self.attached and self.selected_pid and now - self._last_process_liveness_check >= 1.0:
                self._last_process_liveness_check = now
                live_pids = {pid for pid, _name in list_processes()}
                if self.selected_pid not in live_pids:
                    self._detach_dead_process()
                    return
            if self.attached and self.pm:
                if self.density_state:
                    self.density_state.host_heartbeat = kernel32.GetTickCount64()
                    density_payload = self.stat_multi_patches.get("monster_density")
                    if density_payload and "monster_density" in self.active_stat_keys:
                        matches = int(self.density_state.creator_matches)
                        extras = int(self.density_state.extra_creators)
                        previous_matches = int(density_payload.get("last_creator_matches", 0))
                        previous_extras = int(density_payload.get("last_extra_creators", 0))
                        capacity_skips = int(self.density_state.capacity_skips)
                        previous_skips = int(density_payload.get("last_capacity_skips", 0))
                        if (matches != previous_matches or extras != previous_extras or
                                capacity_skips != previous_skips):
                            density_payload["last_creator_matches"] = matches
                            density_payload["last_extra_creators"] = extras
                            density_payload["last_capacity_skips"] = capacity_skips
                            current_var = self.stat_current_vars.get("monster_density")
                            if current_var:
                                guard = ""
                                if self.density_state.protected_pool_used:
                                    guard = f" | pool {self.density_state.protected_pool_used}/262144"
                                if capacity_skips:
                                    guard += f" | safely capped {capacity_skips}"
                                current_var.set(
                                    f"Current: {self.density_state.multiplier:g}x | "
                                    f"creators {matches} | extras {extras}{guard}"
                                )
                            if extras > previous_extras:
                                self.log_line(
                                    f"Monster Density Multiplier: LIVE | creator routes {matches}, "
                                    f"extra creators {extras}, pool {self.density_state.protected_pool_used}/262144, "
                                    f"safely capped {capacity_skips}."
                                )
                for key, payload in list(self.stat_multi_patches.items()):
                    if payload.get("kind") not in (
                        S10_ARRAY_RESULT_MULTIPLIER,
                        S10_ARRAY_RESULT_ADDITIVE,
                        S10_SCALAR_RESULT_MULTIPLIER,
                    ):
                        continue
                    hooks = list(payload.get("hooks") or [payload])
                    changed = []
                    for hook in hooks:
                        raw = self._read_raw(int(hook["data_address"]), 32)
                        native, modified, counter, modifier = struct.unpack("<ddQd", raw)
                        previous = int(hook.get("last_counter", 0))
                        if not counter or counter == previous:
                            continue
                        hook["last_counter"] = int(counter)
                        if not (math.isfinite(native) and math.isfinite(modified)):
                            continue
                        changed.append((hook, native, modified, counter, modifier, previous))
                    if not changed:
                        continue

                    additive = bool(payload.get("additive"))
                    operation = "+" if additive else "×"
                    displays = []
                    for hook, native, modified, counter, modifier, _previous in changed:
                        function_name = str(hook.get("function_name") or "game")
                        label = function_name.removeprefix("gml_Script_Stat").removeprefix("gml_Script_")
                        displays.append(
                            f"{label}: {native:g} {operation} {modifier:g} = {modified:g} ({counter})"
                        )
                    current_var = self.stat_current_vars.get(key)
                    if current_var:
                        current_var.set("Current: " + " | ".join(displays))

                    binding = self._find_binding(key)
                    name = binding.name if binding else key
                    for hook, native, modified, counter, modifier, previous in changed:
                        if previous == 0:
                            self.log_line(
                                f"{name}: LIVE {hook.get('function_name', 'game')} | "
                                f"{native:g} {operation} {modifier:g} = {modified:g}; "
                                f"game function called {counter} time(s)."
                            )
        except Exception as exc:
            try:
                self.log_line(f"Telemetry warning: {exc}")
            except Exception:
                pass
        finally:
            try:
                self.root.after(250, self._poll_result_telemetry)
            except Exception:
                pass

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
                for _key, payload in list(self.stat_multi_patches.items()):
                    try:
                        constant_address = payload.get("constant_address")
                        constant_raw = payload.get("constant_raw")
                        if constant_address and constant_raw:
                            self._write_memory(int(constant_address), constant_raw)
                        sites = list(payload.get("sites", [])) + list(payload.get("gate_sites", []))
                        patches = list(payload.get("patches", [])) + list(payload.get("gate_patches", []))
                        self._write_patch_group(sites, patches, skip_if_current=True)
                    except Exception:
                        pass
            time.sleep(0.08)

    def restore_all(self):
        if not self._require():
            return
        restored = 0
        for binding in list(self.stat_bindings):
            if binding.key in self.active_stat_keys:
                try:
                    self._disable_stat(binding)
                    restored += 1
                except Exception as exc:
                    self.log_line(f"{binding.name}: restore skipped: {exc}")
        self.details.set("Clean state ready.")
        self.log_line(f"Restore All complete. Stats restored: {restored}.")
        self.refresh_status()

    def attach(self):
        processes = list_processes()
        if not processes:
            self.status.set("Hero_Siege.exe not found. Open the game, then press Attach.")
            self._sync_status_indicator()
            self.log_line("Process not found.")
            return False
        selected = self.choose_process(processes)
        if not selected:
            self.log_line("Attach cancelled.")
            return False
        return self.attach_to_process(selected)

    def choose_process(self, processes):
        selected = {"process": None}
        dialog = tk.Toplevel(self.root)
        dialog.title("Select Hero Siege process")
        dialog.configure(bg="#07070b")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.geometry("760x390")
        dialog.minsize(640, 260)

        header = tk.Frame(dialog, bg="#0a0910", height=82)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Frame(header, bg="#c6923c", height=2).pack(fill="x")
        tk.Label(
            header,
            text="PROCESS GATE",
            fg="#cda85f",
            bg="#0a0910",
            anchor="w",
            font=("Segoe UI", 8, "bold"),
        ).pack(fill="x", padx=22, pady=(14, 1))
        tk.Label(
            header,
            text="SELECT HERO SIEGE INSTANCE",
            fg="#f5f2e9",
            bg="#0a0910",
            anchor="w",
            font=("Segoe UI", 16, "bold"),
        ).pack(fill="x", padx=22)

        tk.Label(
            dialog,
            text="Choose the offline process that will receive reversible memory-only overrides.",
            fg="#948d9e",
            bg="#07070b",
            anchor="w",
            font=("Segoe UI", 9),
        ).pack(fill="x", padx=22, pady=(16, 8))

        listbox = tk.Listbox(
            dialog,
            bg="#0d0c13",
            fg="#e5dfea",
            selectbackground="#553c76",
            selectforeground="#ffffff",
            highlightthickness=1,
            highlightbackground="#302b38",
            highlightcolor="#7f5bb5",
            relief="flat",
            bd=0,
            font=("Consolas", 10),
            height=8,
        )
        listbox.pack(fill="both", expand=True, padx=22, pady=(0, 12))
        hero_processes = [(pid, name) for pid, name in processes if name.lower() == PROCESS_NAME.lower()]
        if not hero_processes:
            hero_processes = processes
        for pid, name in hero_processes:
            listbox.insert("end", f"PID {pid:<7} {name}")
        listbox.selection_set(0)

        buttons = tk.Frame(dialog, bg="#07070b")
        buttons.pack(fill="x", padx=22, pady=(0, 18))

        def use_selected():
            selection = listbox.curselection()
            if selection:
                selected["process"] = hero_processes[int(selection[0])]
            dialog.destroy()

        attach_button = self._create_forge_button(buttons, "ATTACH SELECTED", use_selected, "#238b7e")
        attach_button.config(width=20)
        attach_button.pack(side="right", padx=(8, 0))
        cancel_button = self._create_forge_button(buttons, "CANCEL", dialog.destroy, "#5b5364")
        cancel_button.config(width=12)
        cancel_button.pack(side="right")
        listbox.bind("<Double-Button-1>", lambda _event: use_selected())
        listbox.bind("<Return>", lambda _event: use_selected())
        listbox.bind("<Escape>", lambda _event: dialog.destroy())
        self.root.wait_window(dialog)
        return selected["process"]

    def attach_to_process(self, process):
        pm = None
        try:
            pid, name = process
            self._close_density_ipc()
            pm = pymem.Pymem(pid)
            try:
                main_module = resolve_main_module(pm, PROCESS_NAME)
            except Exception as exc:
                raise RuntimeError(
                    "Hero_Siege.exe memory is not readable. Fully close the game, launch Without EAC, "
                    "and accept StatForge's administrator prompt."
                ) from exc
            if not main_module:
                raise RuntimeError(
                    "Hero_Siege.exe main module could not be resolved. Fully close duplicate game processes "
                    "and relaunch Without EAC."
                )
            self.pm = pm
            self.attached = True
            self.function_addresses_cache.clear()
            self.pe_sections_cache.clear()
            self._main_module_cache = main_module
            self.selected_pid = pid
            self.selected_process_name = name
            self.status.set(f"Attached: {name} (PID {pid})")
            self._sync_status_indicator()
            self.log_line(
                f"Attached: {name} PID={pid} | base=0x{main_module['base']:x} "
                f"via {main_module.get('source', 'module resolver')}."
            )
            return True
        except Exception as exc:
            if pm:
                try:
                    pm.close_process()
                except Exception:
                    pass
            self.pm = None
            self.attached = False
            self._main_module_cache = None
            self.status.set(f"Attach failed: {exc}")
            self._sync_status_indicator()
            self.log_line(f"Attach failed: {exc}")
            return False

    def close(self):
        try:
            if self.pm and self.attached:
                self.restore_all()
        except Exception:
            pass
        self._save_bindings()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    StatForge().run()
