#!/usr/bin/env python3
"""Safe x1 resolver/hook lifecycle test for the standalone density runtime."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import mmap
import sys
import time
from pathlib import Path

import pymem
import pymem.process

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from hs_valuescanner import list_modules


MAGIC = 0x44465348
VERSION = 3
STATUS_READY = 2
STATUS_ERROR = 3
ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_ulonglong
FAST_PATHS = {
    "438bf4848688c5be52ac15f26f02b46da620d90587c28e766a9cea190f3a7de4": {
        "depth_rva": 0x0B51C210,
        "layer_rva": 0x0B51C330,
        "creator_indices": (1409, 1410, 1411, 1412, 1413, 1414, 1415),
    },
}


class DensityState(ctypes.Structure):
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--multiplier", type=float, default=1.0)
    parser.add_argument("--observe-seconds", type=float, default=0.0)
    parser.add_argument(
        "--dll",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "native_density"
        / "bin"
        / "HSStatForgeDensity.dll",
    )
    args = parser.parse_args()
    if ctypes.sizeof(DensityState) != 432:
        raise RuntimeError(f"unexpected IPC size: {ctypes.sizeof(DensityState)}")

    mapping = mmap.mmap(
        -1,
        ctypes.sizeof(DensityState),
        tagname=f"Local\\HSStatForgeDensity_{args.pid}",
        access=mmap.ACCESS_WRITE,
    )
    state = DensityState.from_buffer(mapping)
    ctypes.memset(ctypes.addressof(state), 0, ctypes.sizeof(state))
    state.magic = MAGIC
    state.version = VERSION
    state.size = ctypes.sizeof(state)
    state.multiplier = 1.0
    state.host_heartbeat = ctypes.windll.kernel32.GetTickCount64()

    module = next(
        item for item in list_modules(args.pid)
        if item.get("name", "").lower() == "hero_siege.exe"
    )
    with open(module["path"], "rb") as handle:
        fingerprint = hashlib.file_digest(handle, "sha256").hexdigest()
    fast_path = FAST_PATHS.get(fingerprint)
    if fast_path:
        state.depth_address = int(module["base"]) + int(fast_path["depth_rva"])
        state.layer_address = int(module["base"]) + int(fast_path["layer_rva"])
        state.creator_count = len(fast_path["creator_indices"])
        for index, object_index in enumerate(fast_path["creator_indices"]):
            state.creator_indices[index] = object_index

    pm = pymem.Pymem()
    pm.open_process_from_id(args.pid)
    pymem.process.inject_dll_from_path(pm.process_handle, str(args.dll.resolve()))
    deadline = time.time() + 30
    while time.time() < deadline and state.status not in (STATUS_READY, STATUS_ERROR):
        state.host_heartbeat = ctypes.windll.kernel32.GetTickCount64()
        time.sleep(0.05)

    result = {
        "status": state.status,
        "error": state.last_error,
        "message": bytes(state.message).split(b"\0", 1)[0].decode(errors="replace"),
        "depth_address": hex(state.depth_address),
        "layer_address": hex(state.layer_address),
        "creator_indices": list(state.creator_indices[: state.creator_count]),
        "hook_generation": state.hook_generation,
        "protected_pool_used": state.protected_pool_used,
        "capacity_skips": state.capacity_skips,
    }
    print(json.dumps(result, indent=2))
    success = state.status == STATUS_READY and state.creator_count >= 7
    if success and args.multiplier > 1.0:
        state.multiplier = args.multiplier
        state.enabled = 1
        deadline = time.time() + max(0.0, args.observe_seconds)
        last = None
        while time.time() < deadline:
            state.host_heartbeat = ctypes.windll.kernel32.GetTickCount64()
            current = (
                state.depth_calls,
                state.layer_calls,
                state.creator_matches,
                state.extra_creators,
                state.protected_pool_used,
                state.capacity_skips,
            )
            if current != last:
                print(
                    json.dumps(
                        {
                            "depth_calls": current[0],
                            "layer_calls": current[1],
                            "creator_matches": current[2],
                            "extra_creators": current[3],
                            "protected_pool_used": current[4],
                            "capacity_skips": current[5],
                        }
                    ),
                    flush=True,
                )
                last = current
            time.sleep(0.1)
        success = success and state.extra_creators > 0
    state.enabled = 0
    state.multiplier = 1.0
    state.shutdown = 1
    time.sleep(1.0)
    del state
    mapping.close()
    pm.close_process()
    return 0 if success else 2


if __name__ == "__main__":
    raise SystemExit(main())
