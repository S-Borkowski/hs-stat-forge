#!/usr/bin/env python3
"""Read-only discovery probe for the standalone Monster Density route."""

from __future__ import annotations

import argparse
import ctypes
import json
import mmap
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pymem
import pymem.memory
import pefile

import hs_valuescanner as scan


BUILTINS = ("instance_create_depth", "instance_create_layer")
CREATORS = (
    "Enemy_Creator_Ambush_obj",
    "Enemy_Creator_Ancient_obj",
    "Enemy_Creator_Champion_obj",
    "Enemy_Creator_Colossal_Chest_obj",
    "Enemy_Creator_Legion_obj",
    "Enemy_Creator_Miniboss_obj",
    "Enemy_Creator_obj",
)


MEM_PRIVATE = 0x20000


def iter_candidate_regions(handle):
    mbi = scan.MBI()
    address = 0
    while address < 0x7FFFFFFFFFFF:
        result = scan.kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if not result:
            break
        if (
            mbi.State == scan.MEM_COMMIT
            and mbi.Type == MEM_PRIVATE
            and mbi.Protect in scan.PAGE_READABLE
            and 0 < mbi.RegionSize <= scan.MAX_REGION
        ):
            yield int(mbi.BaseAddress), int(mbi.RegionSize)
        address = int(mbi.BaseAddress + mbi.RegionSize)


def find_patterns_in_process(handle, patterns: dict[bytes, object]):
    if not patterns:
        return []
    expression = re.compile(b"|".join(re.escape(value) for value in patterns))
    results = []
    for base, size in iter_candidate_regions(handle):
        try:
            data = pymem.memory.read_bytes(handle, int(base), int(size))
        except Exception:
            continue
        for match in expression.finditer(data):
            raw = match.group(0)
            results.append((base + match.start(), patterns[raw]))
    return results


def find_module_string_addresses(module: dict, names):
    path = Path(module["path"])
    pe = pefile.PE(str(path), fast_load=False)
    result = {}
    with path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as file_bytes:
        for name in names:
            needle = name.encode("ascii") + b"\0"
            offset = file_bytes.find(needle)
            while offset >= 0:
                try:
                    address = int(module["base"]) + int(pe.get_rva_from_offset(offset))
                    result.setdefault(name, []).append(address)
                except Exception:
                    pass
                offset = file_bytes.find(needle, offset + 1)
    return result


def read_qword(handle, address):
    return struct.unpack("<Q", pymem.memory.read_bytes(handle, int(address), 8))[0]


def read_i32(handle, address):
    return struct.unpack("<i", pymem.memory.read_bytes(handle, int(address), 4))[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.pid:
        pm = pymem.Pymem()
        pm.open_process_from_id(args.pid)
    else:
        pm = pymem.Pymem("Hero_Siege.exe")

    module = scan.resolve_main_module(pm, "Hero_Siege.exe")
    if not module:
        raise RuntimeError("Hero_Siege.exe main module was not resolved")
    text_start = int(module["base"])
    text_end = text_start + int(module["size"])

    addresses_by_name = find_module_string_addresses(module, BUILTINS + CREATORS)
    missing_creators = [name for name in CREATORS if not addresses_by_name.get(name)]
    if missing_creators:
        print("Scanning PID for runtime creator names...", flush=True)
        runtime_names = {
            name.encode("ascii") + b"\0": name for name in missing_creators
        }
        for address, name in find_patterns_in_process(pm.process_handle, runtime_names):
            addresses_by_name.setdefault(name, []).append(address)

    pointer_patterns = {}
    for name, addresses in addresses_by_name.items():
        for address in addresses:
            pointer_patterns[struct.pack("<Q", address)] = (name, address)
    print(f"Scanning PID {pm.process_id} for live name references...", flush=True)
    pointer_hits = find_patterns_in_process(pm.process_handle, pointer_patterns)

    builtins = {}
    for name in BUILTINS:
        # Season 10 uses either an inline 80-byte row or a referential 24-byte row.
        for address in addresses_by_name.get(name, []):
            try:
                routine = read_qword(pm.process_handle, address + 64)
                if text_start <= routine < text_end:
                    builtins.setdefault(name, routine)
            except Exception:
                pass
        for row, (hit_name, _string_address) in pointer_hits:
            if hit_name != name:
                continue
            try:
                routine = read_qword(pm.process_handle, row + 8)
                if text_start <= routine < text_end:
                    builtins.setdefault(name, routine)
            except Exception:
                pass

    resource_candidates = {}
    for address, (name, _string_address) in pointer_hits:
        if name in CREATORS:
            resource_candidates.setdefault(address, name)
    resource_patterns = {
        struct.pack("<Q", address): (name, address)
        for address, name in resource_candidates.items()
    }
    print("Scanning live resource references...", flush=True)
    resource_hits = find_patterns_in_process(pm.process_handle, resource_patterns)

    creator_indices = {}
    evidence = []
    for resource_ref, (name, resource_address) in resource_hits:
        node = resource_ref - 0x18
        try:
            object_index = read_i32(pm.process_handle, node + 0x10)
            next_node = read_qword(pm.process_handle, node + 0x08)
        except Exception:
            continue
        if not (0 <= object_index < 100000):
            continue
        if next_node and not (0x10000 <= next_node < 0x0000800000000000):
            continue
        creator_indices.setdefault(name, object_index)
        evidence.append({
            "name": name,
            "index": object_index,
            "resource": resource_address,
            "node": node,
        })

    result = {
        "pid": int(pm.process_id),
        "module_base": int(module["base"]),
        "builtins": {
            name: {"address": int(address), "rva": int(address - module["base"])}
            for name, address in sorted(builtins.items())
        },
        "creator_indices": creator_indices,
        "evidence": evidence,
        "string_hits": {name: len(addresses) for name, addresses in addresses_by_name.items()},
    }
    rendered = json.dumps(result, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")

    if len(builtins) != len(BUILTINS) or len(creator_indices) != len(CREATORS):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
