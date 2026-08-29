# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, messagebox
import threading, struct, time, ctypes, sys, json, os, csv
from ctypes import wintypes

try:
    import pymem, pymem.memory
except ImportError:
    messagebox.showerror(
        "Missing dependency",
        "The 'pymem' package is required.\n\nInstall it with:\npython -m pip install pymem"
    )
    sys.exit(1)

# ── Constants ─────────────────────────────────
PROCESS_NAME  = "Hero_Siege.exe"
APP_TITLE     = "HS Value Scanner"
APP_DISCLAIMER = "Unofficial tool for Hero Siege. Not affiliated with or endorsed by the game's developers."
ANGELIC_DROP_GATE_RVA = 0x2070F5A
ANGELIC_DROP_GATE_ORIGINAL = bytes.fromhex("0F 8E E4 00 00 00")
ANGELIC_DROP_GATE_PATCHED = bytes.fromhex("90 90 90 90 90 90")
DBG_CONTINUE = 0x00010002
EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
EXCEPTION_SINGLE_STEP = 0x80000004
TH32CS_SNAPTHREAD = 0x00000004
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002
CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010
HWBP_MODE_WRITE = "write"
HWBP_MODE_ACCESS = "access"
HWBP_MAX_HITS = 200
TARGET_DEBUG_MODULES = {"hero_siege.exe", "ac_dll_gm.dll"}
def runtime_app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

APP_DIR       = runtime_app_dir()
FAVORITES_FILE = os.path.join(APP_DIR, "hs_favorites.json")
MEM_COMMIT    = 0x1000
PAGE_READABLE = {0x02, 0x04, 0x20, 0x40}   # RO, RW, ExR, ExRW
MAX_REGION    = 50_000_000                  # 50 MB single-region limit
MAX_RESULTS   = 2_000_000
PTR_MAX_OFFSET = 0x2000
PTR_MAX_DEPTH  = 3
PTR_MAX_PATHS  = 8
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260

# ── Colors ────────────────────────────────────
BG, PANEL       = "#0d0d1a", "#13132b"
ACCENT, ACCENT2 = "#7c3aed", "#a855f7"
GREEN, RED      = "#22c55e", "#ef4444"
YELLOW          = "#eab308"
TEXT, SUBTEXT   = "#e2e8f0", "#94a3b8"
VALUE_FORMATS = {"Float": "f", "Double": "d", "4 Bytes": "i", "Int32": "i", "Int64": "q"}
VISIBLE_VALUE_TYPES = ["Float", "Double", "4 Bytes"]
INTEGER_TYPES = {"4 Bytes", "Int32", "Int64"}

# ── WinAPI Structure ──────────────────────────
class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_ulonglong),
        ("AllocationBase",    ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",        ctypes.c_ulonglong),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ProcessID",       wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.c_size_t),
        ("th32ModuleID",        wintypes.DWORD),
        ("cntThreads",          wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase",      wintypes.LONG),
        ("dwFlags",             wintypes.DWORD),
        ("szExeFile",           wintypes.WCHAR * MAX_PATH),
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",        wintypes.DWORD),
        ("th32ModuleID",  wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage",  wintypes.DWORD),
        ("ProccntUsage",  wintypes.DWORD),
        ("modBaseAddr",   ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize",   wintypes.DWORD),
        ("hModule",       wintypes.HMODULE),
        ("szModule",      wintypes.WCHAR * 256),
        ("szExePath",     wintypes.WCHAR * MAX_PATH),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.c_size_t),
        ("Reserved3", ctypes.c_void_p),
    ]

class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]

class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]

class XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wintypes.WORD),
        ("StatusWord", wintypes.WORD),
        ("TagWord", ctypes.c_ubyte),
        ("Reserved1", ctypes.c_ubyte),
        ("ErrorOpcode", wintypes.WORD),
        ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.WORD),
        ("Reserved2", wintypes.WORD),
        ("DataOffset", wintypes.DWORD),
        ("DataSelector", wintypes.WORD),
        ("Reserved3", wintypes.WORD),
        ("MxCsr", wintypes.DWORD),
        ("MxCsr_Mask", wintypes.DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", ctypes.c_ubyte * 96),
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("FltSave", XMM_SAVE_AREA32),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]

class EXCEPTION_RECORD(ctypes.Structure):
    pass

EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD),
    ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_ulonglong * 15),
]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", wintypes.DWORD),
    ]

class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread", wintypes.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    ]

class U_DEBUG_EVENT(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("_pad", ctypes.c_byte * 160),
    ]

class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", U_DEBUG_EVENT),
    ]

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
kernel32.QueryFullProcessImageNameW.argtypes = (
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
)
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
ntdll.NtQueryInformationProcess.argtypes = (
    wintypes.HANDLE,
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
)
ntdll.NtQueryInformationProcess.restype = ctypes.c_long
kernel32.Thread32First.argtypes = (wintypes.HANDLE, ctypes.POINTER(THREADENTRY32))
kernel32.Thread32First.restype = wintypes.BOOL
kernel32.Thread32Next.argtypes = (wintypes.HANDLE, ctypes.POINTER(THREADENTRY32))
kernel32.Thread32Next.restype = wintypes.BOOL
kernel32.OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
kernel32.OpenThread.restype = wintypes.HANDLE
kernel32.SuspendThread.argtypes = (wintypes.HANDLE,)
kernel32.SuspendThread.restype = wintypes.DWORD
kernel32.ResumeThread.argtypes = (wintypes.HANDLE,)
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.GetThreadContext.argtypes = (wintypes.HANDLE, ctypes.POINTER(CONTEXT))
kernel32.GetThreadContext.restype = wintypes.BOOL
kernel32.SetThreadContext.argtypes = (wintypes.HANDLE, ctypes.POINTER(CONTEXT))
kernel32.SetThreadContext.restype = wintypes.BOOL
kernel32.DebugActiveProcess.argtypes = (wintypes.DWORD,)
kernel32.DebugActiveProcess.restype = wintypes.BOOL
kernel32.DebugActiveProcessStop.argtypes = (wintypes.DWORD,)
kernel32.DebugActiveProcessStop.restype = wintypes.BOOL
kernel32.DebugSetProcessKillOnExit.argtypes = (wintypes.BOOL,)
kernel32.DebugSetProcessKillOnExit.restype = wintypes.BOOL
kernel32.WaitForDebugEvent.argtypes = (ctypes.POINTER(DEBUG_EVENT), wintypes.DWORD)
kernel32.WaitForDebugEvent.restype = wintypes.BOOL
kernel32.ContinueDebugEvent.argtypes = (wintypes.DWORD, wintypes.DWORD, wintypes.DWORD)
kernel32.ContinueDebugEvent.restype = wintypes.BOOL

def list_processes():
    processes = []
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        return processes

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    try:
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return processes
        while True:
            pid = int(entry.th32ProcessID)
            name = entry.szExeFile
            if pid and name:
                processes.append((pid, name))
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)

    return sorted(processes, key=lambda item: (item[1].lower(), item[0]))

def list_modules(pid):
    modules = []
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot == wintypes.HANDLE(-1).value:
        return modules

    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32)
    try:
        if not kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
            return modules
        while True:
            base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
            modules.append({
                "name": entry.szModule,
                "base": int(base),
                "size": int(entry.modBaseSize),
                "path": entry.szExePath,
            })
            if not kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)

    return modules


def _module_base_value(module):
    value = getattr(module, "lpBaseOfDll", 0)
    if isinstance(value, int):
        return value
    try:
        return int(ctypes.cast(value, ctypes.c_void_p).value or 0)
    except Exception:
        return 0


def _process_image_path_from_handle(process_handle):
    size = wintypes.DWORD(32768)
    buffer = ctypes.create_unicode_buffer(size.value)
    if kernel32.QueryFullProcessImageNameW(process_handle, 0, buffer, ctypes.byref(size)):
        return buffer.value
    return ""


def _image_size_from_memory(process_handle, image_base):
    header = pymem.memory.read_bytes(process_handle, image_base, 0x1000)
    if header[:2] != b"MZ":
        raise RuntimeError("main image does not contain an MZ header")
    pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    required = pe_offset + 24 + 60
    if required > len(header):
        header = pymem.memory.read_bytes(process_handle, image_base, required)
    if header[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise RuntimeError("main image does not contain a PE header")
    optional_offset = pe_offset + 24
    return struct.unpack_from("<I", header, optional_offset + 56)[0]


def _peb_image_base(process_handle):
    """Return the native 64-bit image base without using a module snapshot."""
    info = PROCESS_BASIC_INFORMATION()
    returned = wintypes.ULONG()
    status = ntdll.NtQueryInformationProcess(
        process_handle,
        0,
        ctypes.byref(info),
        ctypes.sizeof(info),
        ctypes.byref(returned),
    )
    if status != 0 or not info.PebBaseAddress:
        return 0
    raw = pymem.memory.read_bytes(process_handle, int(info.PebBaseAddress) + 0x10, 8)
    return struct.unpack("<Q", raw)[0]


def resolve_main_module(pm, expected_name=PROCESS_NAME):
    """Resolve the process image through Toolhelp, Pymem, then the PEB.

    The fallback is version-independent: it asks Windows for the process image
    base and validates the in-memory PE header instead of relying on one module
    enumeration API.
    """
    expected_lower = expected_name.lower()
    candidates = []
    for module in list_modules(pm.process_id):
        if str(module.get("name") or "").lower() == expected_lower:
            candidates.append((module, "Toolhelp"))
            break

    for finder_name, finder in (
        ("Pymem module", lambda: pymem.process.module_from_name(pm.process_handle, expected_name)),
        ("Pymem base", lambda: pymem.process.base_module(pm.process_handle)),
    ):
        try:
            module = finder()
            if module:
                candidates.append(({
                    "name": str(getattr(module, "name", "") or expected_name),
                    "base": _module_base_value(module),
                    "size": int(getattr(module, "SizeOfImage", 0) or 0),
                    "path": str(getattr(module, "filename", "") or ""),
                }, finder_name))
        except Exception:
            pass

    try:
        peb_base = _peb_image_base(pm.process_handle)
        if peb_base:
            candidates.append(({
                "name": expected_name,
                "base": peb_base,
                "size": 0,
                "path": _process_image_path_from_handle(pm.process_handle),
            }, "PEB"))
    except Exception:
        pass

    seen = set()
    last_error = None
    for module, source in candidates:
        base = int(module.get("base") or 0)
        if not base or base in seen:
            continue
        seen.add(base)
        try:
            size = int(module.get("size") or 0) or _image_size_from_memory(pm.process_handle, base)
            if pymem.memory.read_bytes(pm.process_handle, base, 2) != b"MZ":
                continue
            path = str(module.get("path") or "") or _process_image_path_from_handle(pm.process_handle)
            return {
                "name": expected_name,
                "base": base,
                "size": size,
                "path": path,
                "source": source,
            }
        except Exception as exc:
            last_error = exc
    if last_error:
        raise RuntimeError(f"main module memory is not readable: {last_error}") from last_error
    return None

def list_threads(pid):
    threads = []
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        return threads

    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(THREADENTRY32)
    try:
        if not kernel32.Thread32First(snapshot, ctypes.byref(entry)):
            return threads
        while True:
            if int(entry.th32OwnerProcessID) == int(pid):
                threads.append(int(entry.th32ThreadID))
            if not kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)

    return threads

def module_for_address(modules, address):
    for mod in modules:
        base, size = mod["base"], mod["size"]
        if base <= address < base + size:
            return mod
    return None

def hwbp_size_code(size):
    return {1: 0b00, 2: 0b01, 4: 0b11, 8: 0b10}.get(size, 0b11)

def hwbp_condition_code(mode):
    return 0b01 if mode == HWBP_MODE_WRITE else 0b11

# ── Memory Scan ───────────────────────────────
def scan_memory(handle, target_bytes, prev_addrs=None):
    """Search memory for the target byte sequence. If prev_addrs is given, only check those addresses."""
    size = len(target_bytes)
    found = []

    if prev_addrs is not None:
        for addr in prev_addrs:
            try:
                data = pymem.memory.read_bytes(handle, addr, size)
                if data == target_bytes:
                    found.append(addr)
            except:
                pass
        return found

    mbi  = MBI()
    addr = 0
    while addr < 0x7FFFFFFFFFFF:
        ret = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                      ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not ret:
            break
        if (mbi.State == MEM_COMMIT and
                mbi.Protect in PAGE_READABLE and
                0 < mbi.RegionSize <= MAX_REGION):
            try:
                data = pymem.memory.read_bytes(handle, mbi.BaseAddress, mbi.RegionSize)
                i = 0
                while True:
                    i = data.find(target_bytes, i)
                    if i == -1:
                        break
                    found.append(mbi.BaseAddress + i)
                    i += size
            except:
                pass
        addr = mbi.BaseAddress + mbi.RegionSize
    return found

def iter_readable_regions(handle):
    mbi  = MBI()
    addr = 0
    while addr < 0x7FFFFFFFFFFF:
        ret = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                      ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not ret:
            break
        if (mbi.State == MEM_COMMIT and
                mbi.Protect in PAGE_READABLE and
                0 < mbi.RegionSize <= MAX_REGION):
            yield mbi.BaseAddress, mbi.RegionSize
        addr = mbi.BaseAddress + mbi.RegionSize

def pack_value(value, vtype):
    fmt = VALUE_FORMATS[vtype]
    if vtype in INTEGER_TYPES:
        value = int(value)
    return struct.pack(fmt, value)

def unpack_value(data, vtype):
    fmt = VALUE_FORMATS[vtype]
    return struct.unpack(fmt, data)[0]

def value_size(vtype):
    return struct.calcsize(VALUE_FORMATS[vtype])

def parse_value(text, vtype):
    return int(text) if vtype in INTEGER_TYPES else float(text)

def format_value(value, vtype):
    return str(int(value)) if vtype in INTEGER_TYPES else f"{value:.4g}"

def values_equal(a, b, vtype):
    if vtype in INTEGER_TYPES:
        return int(a) == int(b)
    return abs(float(a) - float(b)) < 0.0001

def read_value(handle, address, vtype):
    raw = pymem.memory.read_bytes(handle, address, value_size(vtype))
    return unpack_value(raw, vtype)

def read_ptr(handle, address):
    raw = pymem.memory.read_bytes(handle, address, 8)
    return struct.unpack("<Q", raw)[0]

def find_pointer_parents(handle, target, max_offset=PTR_MAX_OFFSET, max_hits=256):
    parents = []
    needle_floor = max(0, target - max_offset)

    for base, region_size in iter_readable_regions(handle):
        try:
            data = pymem.memory.read_bytes(handle, base, region_size)
        except:
            continue

        limit = len(data) - 8 + 1
        for offset in range(0, limit, 8):
            try:
                ptr = struct.unpack_from("<Q", data, offset)[0]
            except:
                continue
            if needle_floor <= ptr <= target:
                parents.append((base + offset, target - ptr))
                if len(parents) >= max_hits:
                    return parents

    return parents

def find_pointer_paths(handle, pid, target, max_depth=PTR_MAX_DEPTH,
                       max_offset=PTR_MAX_OFFSET, max_paths=PTR_MAX_PATHS):
    modules = list_modules(pid)
    paths = []
    visited = set()

    def walk(current_target, depth_left, offsets):
        if len(paths) >= max_paths or depth_left <= 0:
            return
        for parent_addr, off in find_pointer_parents(handle, current_target, max_offset):
            state = (parent_addr, tuple(offsets))
            if state in visited:
                continue
            visited.add(state)

            mod = module_for_address(modules, parent_addr)
            new_offsets = [off] + offsets
            if mod:
                paths.append({
                    "module": mod["name"],
                    "rva": parent_addr - mod["base"],
                    "offsets": new_offsets,
                })
                if len(paths) >= max_paths:
                    return
            else:
                walk(parent_addr, depth_left - 1, new_offsets)

    walk(target, max_depth, [])
    return paths

def resolve_pointer_path(handle, pid, path):
    modules = list_modules(pid)
    mod_name = path.get("module", "").lower()
    mod = next((m for m in modules if m["name"].lower() == mod_name), None)
    if not mod:
        return None

    try:
        cur = read_ptr(handle, mod["base"] + int(path.get("rva", 0)))
        offsets = path.get("offsets", [])
        for idx, off in enumerate(offsets):
            cur = cur + int(off)
            if idx < len(offsets) - 1:
                cur = read_ptr(handle, cur)
        return cur
    except:
        return None

def explain_pointer_resolution(handle, pid, path):
    modules = list_modules(pid)
    mod_name = path.get("module", "").lower()
    mod = next((m for m in modules if m["name"].lower() == mod_name), None)
    if not mod:
        available = ", ".join(m["name"] for m in modules[:8]) or "none"
        return None, f"module not loaded: {path.get('module')} (seen: {available})"

    base_expr = mod["base"] + int(path.get("rva", 0))
    try:
        cur = read_ptr(handle, base_expr)
    except Exception as e:
        return None, f"cannot read base pointer at {mod['name']}+0x{int(path.get('rva', 0)):x}: {e}"

    offsets = path.get("offsets", [])
    for idx, off in enumerate(offsets):
        cur = cur + int(off)
        if idx < len(offsets) - 1:
            try:
                cur = read_ptr(handle, cur)
            except Exception as e:
                return None, f"cannot read pointer level {idx + 1} at {hex(cur)}: {e}"
    return cur, "ok"

def force_write_memory(handle, address, raw_data):
    size = len(raw_data)
    old_protect = ctypes.wintypes.DWORD()
    PAGE_EXECUTE_READWRITE = 0x40
    
    # Temporarily change protection.
    kernel32.VirtualProtectEx(handle, ctypes.c_void_p(address), 
                              ctypes.c_size_t(size), PAGE_EXECUTE_READWRITE, 
                              ctypes.byref(old_protect))
    try:
        import pymem
        pymem.memory.write_bytes(handle, address, raw_data, size)
    except:
        pass
        
    # Restore protection to avoid crashes.
    dummy = ctypes.wintypes.DWORD()
    kernel32.VirtualProtectEx(handle, ctypes.c_void_p(address), 
                              ctypes.c_size_t(size), old_protect.value, 
                              ctypes.byref(dummy))

# ══════════════════════════════════════════════
class Trainer:
    def __init__(self):
        self.pm          = None
        self.attached    = False
        self.selected_pid = None
        self.selected_process_name = PROCESS_NAME
        self.scan_addrs  = []          # addresses found by the last scan
        self.scan_values = {}          # addr -> last scanned value
        self.scan_status = {}          # addr -> compare marker for the result table
        self.snapshot_before = {}      # addr -> value captured by Before Snap
        self.snapshot_type = None
        self.frozen      = {}          # addr -> (bytes, type)
        self.favorites_meta = {}       # addr string -> saved pointer metadata
        self.favorite_frozen = set()   # favorite addresses frozen through the favorites panel
        self.loading_favorites = False
        self._freeze_on  = False
        self.access_monitor_stop = threading.Event()
        self.access_monitor_thread = None
        self.access_monitor_window = None
        self.access_monitor_text = None
        self._build_ui()

    # ── UI ────────────────────────────────────
    def _build_ui(self):
        r = tk.Tk()
        r.title(APP_TITLE)
        r.geometry("900x760")
        r.resizable(False, False)
        r.configure(bg=BG)
        r.protocol("WM_DELETE_WINDOW", self._close)
        self.root = r

        # Header
        h = tk.Frame(r, bg=ACCENT, height=60)
        h.pack(fill="x")
        h.pack_propagate(False)
        title_box = tk.Frame(h, bg=ACCENT)
        title_box.pack(side="left", padx=16)
        tk.Label(title_box, text=f"⚔  {APP_TITLE.upper()}", font=("Segoe UI", 15, "bold"),
                 bg=ACCENT, fg="white").pack(anchor="w")
        tk.Label(title_box, text=APP_DISCLAIMER, font=("Segoe UI", 7),
                 bg=ACCENT, fg="#ddd6fe").pack(anchor="w")
        self.status_lbl = tk.Label(h, text="● NOT ATTACHED",
                                   font=("Segoe UI", 10, "bold"),
                                   bg=ACCENT, fg="#fca5a5")
        self.status_lbl.pack(side="right", padx=16)

        body = tk.Frame(r, bg=BG)
        body.pack(fill="both", expand=True, padx=14, pady=10)

        left  = tk.Frame(body, bg=BG, width=325)
        right = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="y")
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))
        left.pack_propagate(False)

        # ── Left: Connection ──────────────────
        self._title(left, "🔌  CONNECTION")
        pf = tk.Frame(left, bg=PANEL, pady=10)
        pf.pack(fill="x", pady=(2, 10))
        tk.Label(pf, text="Selected process:", bg=PANEL, fg=SUBTEXT,
                 font=("Segoe UI", 8)).pack(anchor="w", padx=12, pady=(0, 2))
        self.process_lbl = tk.Label(pf, text=self.selected_process_name, bg=PANEL, fg=TEXT,
                                    font=("Segoe UI", 9, "bold"), anchor="w")
        self.process_lbl.pack(fill="x", padx=12, pady=(0, 8))
        self._btn(pf, "Select Process", self._open_process_picker, "#4f46e5").pack(fill="x", padx=12, pady=(0, 6))
        conn_actions = tk.Frame(pf, bg=PANEL)
        conn_actions.pack(fill="x", padx=12)
        conn_actions.columnconfigure((0, 1), weight=1, uniform="conn")
        self._btn(conn_actions, "Attach", self._connect, ACCENT).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self._btn(conn_actions, "Detach", self._disconnect, "#374151").grid(row=0, column=1, sticky="ew", padx=(4, 0))

        # ── Left: Scan ────────────────────────
        self._title(left, "🔍  MEMORY SCAN")
        sf = tk.Frame(left, bg=PANEL, pady=10)
        sf.pack(fill="x", pady=(2, 10))
        sf.columnconfigure(1, weight=1)

        tk.Label(sf, text="Value", bg=PANEL, fg=SUBTEXT, font=("Segoe UI", 8)).grid(row=0, column=0, sticky="w", padx=(12, 8), pady=(0, 6))
        value_box = tk.Frame(sf, bg=PANEL)
        value_box.grid(row=0, column=1, sticky="ew", padx=(0, 12), pady=(0, 6))
        value_box.columnconfigure(0, weight=1)
        self.scan_val = tk.Entry(value_box, width=10, bg="#1e1e3a", fg=TEXT,
                                 insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))
        self.scan_val.insert(0, "100")
        self.scan_val.grid(row=0, column=0, sticky="ew", ipady=3)
        self.scan_type = ttk.Combobox(value_box, values=VISIBLE_VALUE_TYPES,
                                      width=8, state="readonly")
        self.scan_type.set("Double")
        self.scan_type.grid(row=0, column=1, sticky="e", padx=(8, 0))

        tk.Label(sf, text="Next", bg=PANEL, fg=SUBTEXT, font=("Segoe UI", 8)).grid(row=1, column=0, sticky="w", padx=(12, 8), pady=6)
        self.compare_mode = ttk.Combobox(sf,
                                         values=["Exact Value", "Changed", "Unchanged", "Increased", "Decreased"],
                                         width=16, state="readonly")
        self.compare_mode.set("Exact Value")
        self.compare_mode.grid(row=1, column=1, sticky="ew", padx=(0, 12), pady=6)

        self.cb_live_var = tk.BooleanVar(value=True)
        self.cb_narrow_var = tk.BooleanVar(value=False)
        self.cb_narrow_var.trace("w", self._on_narrow_toggle)

        cb_frame = tk.Frame(sf, bg=PANEL)
        cb_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(4, 10))
        
        tk.Checkbutton(cb_frame, text="Live Watch", variable=self.cb_live_var, bg=PANEL, fg=TEXT, selectcolor=BG, activebackground=PANEL, activeforeground=TEXT, font=("Segoe UI", 8)).pack(side="left")
        tk.Checkbutton(cb_frame, text="Changed Only", variable=self.cb_narrow_var, bg=PANEL, fg=TEXT, selectcolor=BG, activebackground=PANEL, activeforeground=TEXT, font=("Segoe UI", 8)).pack(side="left", padx=8)

        scan_actions = tk.Frame(sf, bg=PANEL)
        scan_actions.grid(row=3, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 6))
        scan_actions.columnconfigure((0, 1), weight=1, uniform="scan")
        self._btn(scan_actions, "First Scan", self._first_scan, "#1d4ed8").grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self._btn(scan_actions, "Next Scan", self._next_scan, "#065f46").grid(row=0, column=1, sticky="ew", padx=(4, 0))
        snap_actions = tk.Frame(sf, bg=PANEL)
        snap_actions.grid(row=4, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 6))
        snap_actions.columnconfigure((0, 1), weight=1, uniform="snap")
        self._btn(snap_actions, "Before Snap", self._snapshot_before, "#7c2d12").grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self._btn(snap_actions, "After Compare", self._snapshot_after_compare, "#854d0e").grid(row=0, column=1, sticky="ew", padx=(4, 0))
        self._btn(sf, "Reset Scan", self._reset_scan, "#374151").grid(row=5, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 6))
        self.scan_info = tk.Label(sf, text="Results: —", bg=PANEL, fg=SUBTEXT, font=("Segoe UI", 9))
        self.scan_info.grid(row=6, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 0))

        self._title(left, "âš™  POINTER TOOLS")
        tf = tk.Frame(left, bg=PANEL, pady=10)
        tf.pack(fill="x", pady=(2, 10))
        tool_actions = tk.Frame(tf, bg=PANEL)
        tool_actions.pack(fill="x", padx=12)
        tool_actions.columnconfigure((0, 1), weight=1, uniform="tools")
        self._btn(tool_actions, "Resolve All", self._resolve_all_favorite_pointers, "#4f46e5").grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self._btn(tool_actions, "Clear Log", self._clear_log, "#374151").grid(row=0, column=1, sticky="ew", padx=(4, 0))

        self._title(left, "âœ¨  OFFLINE LOOT BOOST")
        lf = tk.Frame(left, bg=PANEL, pady=10)
        lf.pack(fill="x", pady=(2, 10))
        loot_actions = tk.Frame(lf, bg=PANEL)
        loot_actions.pack(fill="x", padx=12)
        loot_actions.columnconfigure((0, 1), weight=1, uniform="loot")
        self._btn(loot_actions, "Angelic ON", self._enable_angelic_drop_boost, "#047857").grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self._btn(loot_actions, "Restore", self._restore_angelic_drop_boost, "#991b1b").grid(row=0, column=1, sticky="ew", padx=(4, 0))
        self.loot_status_lbl = tk.Label(lf, text="Offline only. Runtime patch.", bg=PANEL, fg=SUBTEXT, font=("Segoe UI", 8))
        self.loot_status_lbl.pack(anchor="w", padx=12, pady=(6, 0))

        # ── Right: Results list ──────────────
        pw = tk.PanedWindow(right, orient="vertical", bg=BG, sashwidth=6)
        pw.pack(fill="both", expand=True, pady=(2, 6))

        top_pane = tk.Frame(pw, bg=BG)
        pw.add(top_pane, stretch="always")
        
        self._title(top_pane, "📋  RESULTS")
        lf = tk.Frame(top_pane, bg=BG)
        lf.pack(fill="both", expand=True)

        cols = ("Address", "Value", "Status")
        self.tree = ttk.Treeview(lf, columns=cols, show="headings", height=8)
        for c, w in zip(cols, [150, 110, 90]):
            if c == "Value":
                self.tree.heading(c, text=c, command=lambda _c=c: self._sort_tree(_c, False))
            else:
                self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="center")
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        
        # Context menu for results tree
        self.tree_menu = tk.Menu(self.root, tearoff=0, bg=PANEL, fg=TEXT, font=("Segoe UI", 9))
        self.tree_menu.add_command(label="⭐ Add to Favorites", command=self._add_to_favorites)
        self.tree_menu.add_command(label="Find Pointer Path", command=self._find_pointer_for_result)
        self.tree_menu.add_separator()
        self.tree_menu.add_command(label="Find what writes this address", command=lambda: self._start_access_monitor_from_result(HWBP_MODE_WRITE))
        self.tree_menu.add_command(label="Find what accesses this address", command=lambda: self._start_access_monitor_from_result(HWBP_MODE_ACCESS))
        self.tree.bind("<Button-3>", self._show_tree_menu)

        # ── Bottom Right: Favorites ──────────
        bot_pane = tk.Frame(pw, bg=BG)
        pw.add(bot_pane, stretch="always")
        
        self._title(bot_pane, "⭐  FAVORITE ADDRESSES")

        ff = tk.Frame(bot_pane, bg=BG)
        ff.pack(fill="both", expand=True)

        f_cols = ("Name", "Address", "Value", "Type", "Status")
        self.fav_tree = ttk.Treeview(ff, columns=f_cols, show="headings", height=6)
        for c, w in zip(f_cols, [120, 120, 80, 60, 80]):
            self.fav_tree.heading(c, text=c)
            self.fav_tree.column(c, width=w, anchor="center")
        f_sb = ttk.Scrollbar(ff, orient="vertical", command=self.fav_tree.yview)
        self.fav_tree.configure(yscrollcommand=f_sb.set)
        f_sb.pack(side="right", fill="y")
        self.fav_tree.pack(side="left", fill="both", expand=True)
        
        # Context menu for favorites
        self.fav_menu = tk.Menu(self.root, tearoff=0, bg=PANEL, fg=TEXT, font=("Segoe UI", 9))
        self.fav_menu.add_command(label="Write / Change", command=self._write_fav)
        self.fav_menu.add_command(label="Freeze", command=self._freeze_fav)
        self.fav_menu.add_command(label="Unfreeze", command=self._unfreeze_fav)
        self.fav_menu.add_command(label="⬆️ Move to Results", command=self._move_to_results)
        self.fav_menu.add_command(label="Find Pointer Path", command=self._find_pointer_for_fav)
        self.fav_menu.add_command(label="Resolve Pointer", command=self._resolve_selected_fav_pointer)
        self.fav_menu.add_separator()
        self.fav_menu.add_command(label="Find what writes this address", command=lambda: self._start_access_monitor_from_favorite(HWBP_MODE_WRITE))
        self.fav_menu.add_command(label="Find what accesses this address", command=lambda: self._start_access_monitor_from_favorite(HWBP_MODE_ACCESS))
        self.fav_menu.add_separator()
        self.fav_menu.add_command(label="Delete", command=self._delete_fav)
        self.fav_tree.bind("<Button-3>", self._show_fav_menu)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=PANEL, foreground=TEXT,
                        fieldbackground=PANEL, rowheight=24, font=("Consolas", 9))
        style.configure("Treeview.Heading", background=ACCENT,
                        foreground="white", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", ACCENT2)])

        # Write value / freeze
        af = tk.Frame(right, bg=BG)
        af.pack(fill="x", pady=(0, 6))
        tk.Label(af, text="New value:", bg=BG, fg=TEXT, font=("Segoe UI", 9)).pack(side="left")
        self.new_val = tk.Entry(af, width=14, bg="#1e1e3a", fg=TEXT,
                                insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))
        self.new_val.insert(0, "99999999")
        self.new_val.pack(side="left", padx=(6, 8), ipady=3)
        self._btn(af, "Write",     self._write_sel,   "#065f46").pack(side="left", padx=2)
        self._btn(af, "Freeze",  self._freeze_sel,  ACCENT).pack(side="left", padx=2)
        self._btn(af, "Unfreeze",     self._unfreeze_sel,"#374151").pack(side="left", padx=2)

        # Log
        self._title(right, "📜  LOG")
        self.log = tk.Text(right, height=5, bg="#0a0a18", fg=SUBTEXT,
                           font=("Consolas", 8), relief="flat",
                           state="disabled", wrap="word")
        self.log.pack(fill="x")

        self._log("Trainer ready. Click 'Select Process' to choose a running game, then attach.")
        self._log("Free unofficial tool for personal/offline use. Not endorsed by the game's developers.")
        threading.Thread(target=self._freeze_loop, daemon=True).start()
        threading.Thread(target=self._live_update_loop, daemon=True).start()
        self.root.after(500, self._load_favorites)

    # ── Helpers ───────────────────────────────
    def _title(self, p, t):
        tk.Label(p, text=t, bg=BG, fg=ACCENT2,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(6, 1))

    def _btn(self, p, t, cmd, color):
        return tk.Button(p, text=t, command=cmd, bg=color, fg="white",
                         relief="flat", font=("Segoe UI", 9, "bold"),
                         activebackground=color, activeforeground="white",
                         cursor="hand2", pady=5)

    def _log(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", f"► {msg}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _require(self):
        if not self.attached:
            messagebox.showwarning("Not Attached", "Attach to the game first!")
            return False
        return True

    def _vtype(self):
        return self.scan_type.get()

    def _status_text(self, addr, marker=""):
        parts = []
        if marker:
            parts.append(marker)
        if addr in self.frozen:
            parts.append("Frozen")
        return " | ".join(parts)

    def _update_tree(self, addrs, vals, markers=None):
        markers = markers or {}
        vtype = getattr(self, 'current_scan_type', self._vtype())
        self.tree.delete(*self.tree.get_children())
        for a, v in zip(addrs, vals):
            st = "❄ Frozen" if a in self.frozen else ""
            st = self._status_text(a, markers.get(a, ""))
            self.tree.insert("", "end", iid=str(a),
                             values=(hex(a), format_value(v, vtype), st))
        n = len(addrs)
        self.scan_info.config(text=f"Results: {n}" + (" (showing first 500)" if n > 500 else ""))

    def _sel_addr(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Selection", "Select an address from the list.")
            return None
        return int(sel[0])

    def _open_process_picker(self):
        d = tk.Toplevel(self.root)
        d.title("Select Process")
        d.geometry("560x500")
        d.minsize(520, 420)
        d.configure(bg=PANEL)
        d.grab_set()

        top = tk.Frame(d, bg=PANEL)
        top.pack(fill="x", padx=12, pady=(12, 6))
        tk.Label(top, text="Search:", bg=PANEL, fg=TEXT,
                 font=("Segoe UI", 9)).pack(side="left")
        query_var = tk.StringVar()
        search = tk.Entry(top, textvariable=query_var, width=26, bg="#1e1e3a", fg=TEXT,
                          insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))
        search.pack(side="left", padx=(6, 8), ipady=3)

        list_frame = tk.Frame(d, bg=PANEL)
        list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        cols = ("PID", "Process")
        tree = ttk.Treeview(list_frame, columns=cols, show="headings", height=12)
        tree.heading("PID", text="PID")
        tree.heading("Process", text="Process")
        tree.column("PID", width=90, anchor="center")
        tree.column("Process", width=410, anchor="w")
        sb = ttk.Scrollbar(list_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)

        actions = tk.Frame(d, bg=PANEL)
        actions.pack(side="bottom", fill="x", padx=12, pady=(0, 12))

        def refresh():
            self._populate_process_tree(tree, query_var.get())

        def attach_selected():
            self._choose_process_from_tree(tree, d, attach=True)

        query_var.trace_add("write", lambda *_: refresh())
        tree.bind("<Double-1>", lambda _: attach_selected())
        self._btn(actions, "Refresh", refresh, "#374151").pack(side="left", padx=(0, 6))
        self._btn(actions, "Attach", attach_selected, ACCENT).pack(side="right")
        self._btn(actions, "Cancel", d.destroy, "#374151").pack(side="right", padx=(0, 6))

        refresh()
        search.focus()

    def _populate_process_tree(self, tree, query):
        tree.delete(*tree.get_children())
        q = query.strip().lower()
        for pid, name in list_processes():
            if q and not name.lower().startswith(q) and not str(pid).startswith(q):
                continue
            tree.insert("", "end", iid=str(pid), values=(pid, name))

    def _choose_process_from_tree(self, tree, dialog, attach=False):
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("Selection", "Select a process from the list.")
            return

        pid = int(sel[0])
        name = tree.set(sel[0], "Process")
        self.selected_pid = pid
        self.selected_process_name = name
        self.process_lbl.config(text=f"{name}  (PID {pid})")
        self._log(f"Selected process: {name}  PID={pid}")
        dialog.destroy()

        if attach:
            self._connect()

    # ── Connection ────────────────────────────
    def _connect(self):
        if self.attached:
            self._disconnect()

        try:
            if self.selected_pid:
                self.pm = pymem.Pymem(self.selected_pid)
            else:
                self.pm = pymem.Pymem(self.selected_process_name)
            self.attached = True
            self.scan_addrs = []
            self.scan_values = {}
            self.scan_status = {}
            self.frozen.clear()
            self.favorite_frozen.clear()
            self.tree.delete(*self.tree.get_children())
            self.scan_info.config(text="Results: —")
            self.status_lbl.config(text="● ATTACHED", fg="#86efac")
            self.process_lbl.config(
                text=f"{self.selected_process_name}  (PID {self.pm.process_id})"
            )
            self._log(f"Attached: {self.selected_process_name}  PID={self.pm.process_id}")
            self._refresh_angelic_drop_status()
            self.root.after(300, self._resolve_all_favorite_pointers)
        except Exception as e:
            target = (f"{self.selected_process_name} PID={self.selected_pid}"
                      if self.selected_pid else self.selected_process_name)
            messagebox.showerror("Error", f"Could not attach to process:\n{target}\n\n{e}")
            self._log(f"Connection error: {e}")

    def _disconnect(self):
        self._stop_access_monitor()
        self._restore_angelic_drop_boost(silent=True)
        self.pm = None
        self.attached = False
        self.status_lbl.config(text="● NOT ATTACHED", fg="#fca5a5")
        if hasattr(self, "loot_status_lbl"):
            self.loot_status_lbl.config(text="Offline only. Runtime patch.", fg=SUBTEXT)
        self._log("Detached.")

    # ── Scan ──────────────────────────────────
    # Offline loot boost
    def _hero_module_base(self):
        if not self.pm or not self.attached:
            return None
        modules = list_modules(self.pm.process_id)
        mod = next((m for m in modules if m["name"].lower() == PROCESS_NAME.lower()), None)
        return mod["base"] if mod else None

    def _angelic_drop_gate_address(self):
        base = self._hero_module_base()
        if not base:
            return None
        return base + ANGELIC_DROP_GATE_RVA

    def _read_angelic_drop_gate(self):
        addr = self._angelic_drop_gate_address()
        if not addr:
            return None, None
        raw = pymem.memory.read_bytes(self.pm.process_handle, addr, len(ANGELIC_DROP_GATE_ORIGINAL))
        return addr, raw

    def _refresh_angelic_drop_status(self):
        if not hasattr(self, "loot_status_lbl"):
            return
        if not self.pm or not self.attached:
            self.loot_status_lbl.config(text="Attach required.", fg=SUBTEXT)
            return
        try:
            _addr, raw = self._read_angelic_drop_gate()
            if raw == ANGELIC_DROP_GATE_ORIGINAL:
                self.loot_status_lbl.config(text="Angelic boost: OFF", fg=SUBTEXT)
            elif raw == ANGELIC_DROP_GATE_PATCHED:
                self.loot_status_lbl.config(text="Angelic boost: ON", fg="#86efac")
            elif raw is None:
                self.loot_status_lbl.config(text="Hero_Siege.exe module not found.", fg="#fca5a5")
            else:
                self.loot_status_lbl.config(text="Version mismatch. Patch blocked.", fg="#fca5a5")
        except Exception as e:
            self.loot_status_lbl.config(text=f"Status error: {e}", fg="#fca5a5")

    def _enable_angelic_drop_boost(self):
        if not self._require():
            return
        try:
            addr, raw = self._read_angelic_drop_gate()
            if not addr:
                self._log("Angelic boost error: Hero_Siege.exe module not found.")
                self._refresh_angelic_drop_status()
                return
            if raw == ANGELIC_DROP_GATE_PATCHED:
                self._log("Angelic drop boost is already enabled.")
                self._refresh_angelic_drop_status()
                return
            if raw != ANGELIC_DROP_GATE_ORIGINAL:
                self._log(f"Angelic boost blocked: unexpected bytes at {hex(addr)} = {raw.hex(' ')}")
                messagebox.showwarning("Version mismatch", "This Hero Siege build does not match the known Angelic patch point.")
                self._refresh_angelic_drop_status()
                return
            force_write_memory(self.pm.process_handle, addr, ANGELIC_DROP_GATE_PATCHED)
            self._log(f"Angelic drop boost enabled at {PROCESS_NAME}+0x{ANGELIC_DROP_GATE_RVA:x}. Offline only.")
        except Exception as e:
            self._log(f"Angelic boost error: {e}")
            messagebox.showerror("Patch failed", str(e))
        self._refresh_angelic_drop_status()

    def _restore_angelic_drop_boost(self, silent=False):
        if not self.pm or not self.attached:
            return
        try:
            addr, raw = self._read_angelic_drop_gate()
            if not addr:
                if not silent:
                    self._log("Angelic restore error: Hero_Siege.exe module not found.")
                return
            if raw == ANGELIC_DROP_GATE_ORIGINAL:
                if not silent:
                    self._log("Angelic drop boost is already restored.")
                return
            if raw != ANGELIC_DROP_GATE_PATCHED:
                if not silent:
                    self._log(f"Angelic restore blocked: unknown bytes at {hex(addr)} = {raw.hex(' ')}")
                    messagebox.showwarning("Version mismatch", "Current bytes are not the scanner's Angelic patch.")
                return
            force_write_memory(self.pm.process_handle, addr, ANGELIC_DROP_GATE_ORIGINAL)
            if not silent:
                self._log("Angelic drop boost restored.")
        except Exception as e:
            if not silent:
                self._log(f"Angelic restore error: {e}")
                messagebox.showerror("Restore failed", str(e))
        self._refresh_angelic_drop_status()

    def _legacy_first_scan(self):
        if not self._require(): return
        try:
            v = float(self.scan_val.get())
        except:
            messagebox.showerror("Error", "Enter a valid number"); return
        self._log(f"First scan: {v} ({self._vtype()}) — please wait...")
        self.btn_info = "scanning"
        threading.Thread(target=self._do_scan, args=(v, None), daemon=True).start()

    def _legacy_next_scan(self):
        if not self._require(): return
        if not self.scan_addrs:
            messagebox.showinfo("Info", "Run First Scan first."); return
        try:
            v = float(self.scan_val.get())
        except:
            messagebox.showerror("Error", "Enter a valid number"); return
        self._log(f"Narrowing: searching for {v} in {len(self.scan_addrs)} addresses...")
        self.btn_info = "scanning"
        threading.Thread(target=self._do_scan, args=(v, self.scan_addrs), daemon=True).start()

    def _legacy_do_scan(self, target, prev):
        vtype = self._vtype()
        self.current_scan_type = vtype
        self.current_scan_val = target
        target_bytes = pack_value(target, vtype)
        sz = len(target_bytes)

        found_addrs = scan_memory(self.pm.process_handle, target_bytes, prev)

        # Read values.
        vals = []
        for a in found_addrs[:500]:
            try:
                raw = pymem.memory.read_bytes(self.pm.process_handle, a, sz)
                vals.append(unpack_value(raw, vtype))
            except:
                vals.append(0)

        self.scan_addrs = found_addrs
        self.root.after(0, self._update_tree, found_addrs[:500], vals)
        self.root.after(0, self._log,
                        f"Scan complete: {len(found_addrs)} results found.")
        self.btn_info = ""

    def _legacy_reset_scan(self):
        self.scan_addrs = []
        self.tree.delete(*self.tree.get_children())
        self.scan_info.config(text="Results: —")
        self._log("Scan reset.")

    # ── Write / Freeze ────────────────────────
    def _write_sel(self):
        if not self._require(): return
        a = self._sel_addr()
        if a is None: return
        vtype = self._vtype()
        try:
            v = parse_value(self.new_val.get(), vtype)
        except:
            messagebox.showerror("Error", "Enter a valid number"); return
        raw = pack_value(v, vtype)
        try:
            force_write_memory(self.pm.process_handle, a, raw)
            self._log(f"Wrote: {hex(a)} = {v}")
            self.tree.set(str(a), "Value", format_value(v, vtype))
        except Exception as e:
            self._log(f"Write error {hex(a)}: {e}")

    def _freeze_sel(self):
        if not self._require(): return
        a = self._sel_addr()
        if a is None: return
        vtype = self._vtype()
        try:
            v = parse_value(self.new_val.get(), vtype)
        except:
            messagebox.showerror("Error", "Enter a valid number"); return
        raw = pack_value(v, vtype)
        self.frozen[a] = (raw, vtype)
        self.tree.set(str(a), "Status", "❄ Frozen")
        # Write once immediately.
        try:
            force_write_memory(self.pm.process_handle, a, raw)
        except:
            pass
        self._log(f"Frozen: {hex(a)} = {v}")

    def _unfreeze_sel(self):
        a = self._sel_addr()
        if a is None: return
        if a in self.frozen:
            del self.frozen[a]
            self.tree.set(str(a), "Status", "")
            self._log(f"Unfrozen: {hex(a)}")

    def _freeze_loop(self):
        while True:
            if self.attached and self.frozen:
                for a, (raw, _) in list(self.frozen.items()):
                    try:
                        force_write_memory(self.pm.process_handle, a, raw)
                    except:
                        pass
            time.sleep(0.08)

    def _live_update_loop(self):
        import struct
        while True:
            if self.attached and self.scan_addrs and getattr(self, 'btn_info', '') != "scanning":
                live_on = getattr(self, 'cb_live_var', None) and self.cb_live_var.get()
                narrow_on = getattr(self, 'cb_narrow_var', None) and self.cb_narrow_var.get()
                
                if live_on or narrow_on:
                    updates = []
                    to_remove = []
                    try:
                        to_check = self.scan_addrs[:500]
                        vtype = getattr(self, 'current_scan_type', 'Double')
                        orig_val = getattr(self, 'current_scan_val', 0.0)
                        
                        if vtype in VALUE_FORMATS:
                            fmt = VALUE_FORMATS[vtype]
                            sz = struct.calcsize(fmt)
                            import pymem
                            
                            for a in to_check:
                                try:
                                    raw = pymem.memory.read_bytes(self.pm.process_handle, a, sz)
                                    v = struct.unpack(fmt, raw)[0]
                                    
                                    old_val = self.scan_values.get(a, orig_val)
                                    if narrow_on:
                                        if values_equal(v, old_val, vtype):
                                            to_remove.append(str(a))
                                        else:
                                            updates.append((str(a), format_value(v, vtype)))
                                    else:
                                        updates.append((str(a), format_value(v, vtype)))
                                except:
                                    to_remove.append(str(a))
                    except:
                        pass
                    
                    if updates or to_remove:
                        self.root.after(0, self._apply_live_updates, updates, to_remove, narrow_on)
            time.sleep(0.5)

    def _apply_live_updates(self, updates, to_remove, narrow_on):
        for iid, val in updates:
            if self.tree.exists(iid):
                self.tree.set(iid, "Value", val)
            elif narrow_on:
                a = int(iid)
                st = "❄ Frozen" if a in self.frozen else ""
                self.tree.insert("", "end", iid=iid, values=(hex(a), val, st))
                
        if narrow_on:
            for iid in to_remove:
                if self.tree.exists(iid):
                    self.tree.delete(iid)
                    
    def _on_narrow_toggle(self, *args):
        if not self.cb_narrow_var.get() and self.scan_addrs:
            threading.Thread(target=self._restore_view, daemon=True).start()

    def _restore_view(self):
        vtype = getattr(self, 'current_scan_type', 'Double')
        fmt = VALUE_FORMATS[vtype]
        sz = struct.calcsize(fmt)
        import pymem
        vals = []
        for a in self.scan_addrs[:500]:
            try:
                raw = pymem.memory.read_bytes(self.pm.process_handle, a, sz)
                vals.append(unpack_value(raw, vtype))
            except:
                vals.append(0)
        self.root.after(0, self._update_tree, self.scan_addrs[:500], vals)

    def _sort_tree(self, col, reverse):
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            l.sort(key=lambda t: float(t[0]), reverse=reverse)
        except ValueError:
            l.sort(reverse=reverse)
            
        for index, (val, k) in enumerate(l):
            self.tree.move(k, "", index)
            
        self.tree.heading(col, command=lambda: self._sort_tree(col, not reverse))

    # ── Favorites ─────────────────────────────
    def _favorite_entry_from_tree(self, item):
        meta = self.favorites_meta.get(str(item), {})
        return {
            "name": self.fav_tree.set(item, "Name"),
            "addr": self.fav_tree.set(item, "Address"),
            "type": self.fav_tree.set(item, "Type"),
            "pointer": meta.get("pointer"),
        }

    def _current_favorites(self):
        return [
            self._favorite_entry_from_tree(item)
            for item in self.fav_tree.get_children()
        ]

    def _write_favorites_file(self, favorites):
        os.makedirs(APP_DIR, exist_ok=True)
        data = {"version": 3, "favorites": favorites}
        tmp_file = FAVORITES_FILE + ".tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(tmp_file, FAVORITES_FILE)

    def _load_favorites_into_tree(self, favorites):
        self.loading_favorites = True
        try:
            for addr in list(self.favorite_frozen):
                self.frozen.pop(addr, None)
            self.favorite_frozen.clear()
            self.fav_tree.delete(*self.fav_tree.get_children())
            self.favorites_meta = {}

            for fav in favorites:
                try:
                    a_str = fav.get("addr", "0x0")
                    a = self._parse_saved_addr(a_str)
                except:
                    continue
                name = fav.get("name", "Unnamed")
                vtype = fav.get("type", "Double")
                pointer = fav.get("pointer")
                status = "Pointer" if pointer else ""
                self.fav_tree.insert("", "end", iid=str(a),
                                     values=(name, hex(a), "?", vtype, status))
                if pointer:
                    self.favorites_meta[str(a)] = {"pointer": pointer}
        finally:
            self.loading_favorites = False

    def _parse_saved_addr(self, value):
        text = str(value).strip()
        try:
            return int(text, 16)
        except ValueError:
            return int(text)

    def _favorites_from_file_data(self, data):
        if isinstance(data, list):
            return data, True
        if not isinstance(data, dict):
            return [], True
        if isinstance(data.get("favorites"), list):
            return data["favorites"], False
        presets = data.get("presets")
        if not isinstance(presets, dict):
            return [], True

        merged = []
        seen = set()
        active = data.get("active_preset")
        names = []
        if active in presets:
            names.append(active)
        names.extend(name for name in sorted(presets.keys(), key=str.lower) if name not in names)
        for name in names:
            favs = presets.get(name, [])
            if not isinstance(favs, list):
                continue
            for fav in favs:
                if not isinstance(fav, dict):
                    continue
                key = (str(fav.get("addr", "")), json.dumps(fav.get("pointer"), sort_keys=True, default=str))
                if key in seen:
                    continue
                seen.add(key)
                merged.append(fav)
        return merged, True

    def _show_tree_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.tree_menu.post(event.x_root, event.y_root)

    def _selected_favorite_target(self):
        sel = self.fav_tree.selection()
        if not sel:
            messagebox.showinfo("Selection", "Select a favorite address first.")
            return None, None
        resolved = self._resolve_fav_pointer(sel[0], update_ui=False)
        iid = str(resolved) if resolved else sel[0]
        try:
            address = int(iid)
        except Exception:
            return None, None
        vtype = self.fav_tree.set(sel[0], "Type") or "Double"
        return address, vtype

    def _start_access_monitor_from_result(self, mode):
        if not self._require():
            return
        address = self._sel_addr()
        if address is None:
            return
        vtype = getattr(self, "current_scan_type", self._vtype())
        self._start_access_monitor(address, vtype, mode)

    def _start_access_monitor_from_favorite(self, mode):
        if not self._require():
            return
        address, vtype = self._selected_favorite_target()
        if address is None:
            return
        self._start_access_monitor(address, vtype, mode)

    def _monitor_value_size(self, vtype):
        return max(1, min(8, value_size(vtype)))

    def _append_access_log(self, line):
        if not self.access_monitor_text or not self.access_monitor_window or not self.access_monitor_window.winfo_exists():
            self._log(line)
            return
        self.access_monitor_text.configure(state="normal")
        self.access_monitor_text.insert("end", line + "\n")
        self.access_monitor_text.see("end")
        self.access_monitor_text.configure(state="disabled")

    def _close_access_monitor_window(self):
        self._stop_access_monitor()
        if self.access_monitor_window and self.access_monitor_window.winfo_exists():
            self.access_monitor_window.destroy()
        self.access_monitor_window = None
        self.access_monitor_text = None

    def _show_access_monitor_window(self, title):
        if self.access_monitor_window and self.access_monitor_window.winfo_exists():
            self.access_monitor_window.destroy()
        w = tk.Toplevel(self.root)
        w.title(title)
        w.geometry("840x360")
        w.configure(bg=BG)
        w.protocol("WM_DELETE_WINDOW", self._close_access_monitor_window)
        top = tk.Frame(w, bg=BG)
        top.pack(fill="x", padx=10, pady=10)
        tk.Label(top, text=title, bg=BG, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(side="left")
        self._btn(top, "Stop", self._stop_access_monitor, "#991b1b").pack(side="right")
        text = tk.Text(w, height=16, bg="#0a0a18", fg=TEXT, font=("Consolas", 9), state="disabled", wrap="none")
        text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.access_monitor_window = w
        self.access_monitor_text = text

    def _stop_access_monitor(self):
        self.access_monitor_stop.set()

    def _open_thread_for_debug(self, tid):
        return kernel32.OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
            False,
            tid,
        )

    def _set_thread_breakpoint(self, tid, address, size, mode):
        h_thread = self._open_thread_for_debug(tid)
        if not h_thread:
            return False
        try:
            kernel32.SuspendThread(h_thread)
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
            if not kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                return False
            ctx.Dr0 = int(address)
            ctx.Dr1 = 0
            ctx.Dr2 = 0
            ctx.Dr3 = 0
            ctx.Dr6 = 0
            rw = hwbp_condition_code(mode)
            ln = hwbp_size_code(size)
            ctx.Dr7 = 0x1 | (rw << 16) | (ln << 18)
            return bool(kernel32.SetThreadContext(h_thread, ctypes.byref(ctx)))
        finally:
            kernel32.ResumeThread(h_thread)
            kernel32.CloseHandle(h_thread)

    def _clear_thread_breakpoint(self, tid):
        h_thread = self._open_thread_for_debug(tid)
        if not h_thread:
            return False
        try:
            kernel32.SuspendThread(h_thread)
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
            if not kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                return False
            ctx.Dr0 = 0
            ctx.Dr1 = 0
            ctx.Dr2 = 0
            ctx.Dr3 = 0
            ctx.Dr6 = 0
            ctx.Dr7 = 0
            return bool(kernel32.SetThreadContext(h_thread, ctypes.byref(ctx)))
        finally:
            kernel32.ResumeThread(h_thread)
            kernel32.CloseHandle(h_thread)

    def _read_instruction_bytes(self, rip):
        try:
            raw = pymem.memory.read_bytes(self.pm.process_handle, rip, 16)
            return raw.hex(" ")
        except Exception:
            return "??"

    def _read_instruction_window(self, rip, before=24, after=16):
        try:
            start = max(0, rip - before)
            size = before + after
            raw = pymem.memory.read_bytes(self.pm.process_handle, start, size)
            return f"{hex(start)}: {raw.hex(' ')}"
        except Exception:
            return "??"

    def _format_module_location(self, modules, rip):
        mod = module_for_address(modules, rip)
        if not mod:
            return f"{hex(rip)} | <unknown module>"
        return f"{mod['name']}+0x{rip - mod['base']:x} ({hex(rip)})"

    def _module_name_for_rip(self, modules, rip):
        mod = module_for_address(modules, rip)
        return (mod["name"].lower(), mod) if mod else ("", None)

    def _read_xmm_double(self, xmm_reg):
        try:
            raw = struct.pack("<QQ", int(xmm_reg.Low), int(xmm_reg.High & 0xFFFFFFFFFFFFFFFF))
            return struct.unpack("<d", raw[:8])[0]
        except Exception:
            return None

    def _format_registers(self, ctx, target_address=None):
        regs = {
            "RAX": int(ctx.Rax),
            "RBX": int(ctx.Rbx),
            "RCX": int(ctx.Rcx),
            "RDX": int(ctx.Rdx),
            "RSI": int(ctx.Rsi),
            "RDI": int(ctx.Rdi),
            "RBP": int(ctx.Rbp),
            "RSP": int(ctx.Rsp),
            "R8": int(ctx.R8),
            "R9": int(ctx.R9),
            "R10": int(ctx.R10),
            "R11": int(ctx.R11),
            "R12": int(ctx.R12),
            "R13": int(ctx.R13),
            "R14": int(ctx.R14),
            "R15": int(ctx.R15),
        }
        parts = []
        near_parts = []
        for name, value in regs.items():
            parts.append(f"{name}={hex(value)}")
            if target_address is not None:
                diff = value - int(target_address)
                if value == int(target_address):
                    near_parts.append(f"{name}=TARGET")
                elif abs(diff) <= 0x200:
                    sign = "+" if diff >= 0 else "-"
                    near_parts.append(f"{name}=TARGET{sign}0x{abs(diff):x}")

        xmm_parts = []
        for idx in range(16):
            value = self._read_xmm_double(ctx.FltSave.XmmRegisters[idx])
            if value is not None:
                xmm_parts.append(f"XMM{idx}={value:.6g}")

        lines = [" ".join(parts)]
        if near_parts:
            lines.append("near-target: " + " ".join(near_parts))
        if xmm_parts:
            lines.append(" ".join(xmm_parts))
        return lines

    def _format_stack_returns(self, modules, rsp, max_qwords=32):
        try:
            raw = pymem.memory.read_bytes(self.pm.process_handle, int(rsp), max_qwords * 8)
        except Exception:
            return []
        hits = []
        seen = set()
        for idx in range(max_qwords):
            value = struct.unpack_from("<Q", raw, idx * 8)[0]
            mod = module_for_address(modules, value)
            if not mod:
                continue
            name = mod["name"].lower()
            if name not in TARGET_DEBUG_MODULES:
                continue
            key = (name, value - mod["base"])
            if key in seen:
                continue
            seen.add(key)
            hits.append(f"[rsp+0x{idx * 8:x}] {mod['name']}+0x{value - mod['base']:x} ({hex(value)})")
            if len(hits) >= 8:
                break
        return hits

    def _debug_loop_for_address(self, pid, address, size, mode):
        thread_ids = set()
        debug_attached = False
        modules = list_modules(pid)
        try:
            if not kernel32.DebugActiveProcess(pid):
                err = ctypes.get_last_error()
                self.root.after(0, self._append_access_log, f"Debug attach failed. WinErr={err}")
                return
            debug_attached = True
            kernel32.DebugSetProcessKillOnExit(False)
            for tid in list_threads(pid):
                if self._set_thread_breakpoint(tid, address, size, mode):
                    thread_ids.add(tid)
            self.root.after(0, self._append_access_log, f"Monitoring {mode} on {hex(address)} ({size} byte).")
            event = DEBUG_EVENT()
            hit_count = 0
            while not self.access_monitor_stop.is_set():
                if not kernel32.WaitForDebugEvent(ctypes.byref(event), 200):
                    continue
                code = int(event.dwDebugEventCode)
                tid = int(event.dwThreadId)
                if code == CREATE_THREAD_DEBUG_EVENT:
                    if self._set_thread_breakpoint(tid, address, size, mode):
                        thread_ids.add(tid)
                elif code == EXCEPTION_DEBUG_EVENT:
                    exc = int(event.u.Exception.ExceptionRecord.ExceptionCode)
                    if exc == EXCEPTION_SINGLE_STEP:
                        h_thread = self._open_thread_for_debug(tid)
                        rip = 0
                        reg_lines = []
                        stack_lines = []
                        if h_thread:
                            try:
                                ctx = CONTEXT()
                                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
                                if kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                                    rip = int(ctx.Rip)
                                    reg_lines = self._format_registers(ctx, address)
                                    stack_lines = self._format_stack_returns(modules, ctx.Rsp)
                                    ctx.Dr6 = 0
                                    kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))
                            finally:
                                kernel32.CloseHandle(h_thread)
                        module_name, _mod = self._module_name_for_rip(modules, rip) if rip else ("", None)
                        if module_name in TARGET_DEBUG_MODULES:
                            hit_count += 1
                            loc = self._format_module_location(modules, rip) if rip else "?"
                            inst = self._read_instruction_bytes(rip) if rip else "??"
                            line = f"hit {hit_count:03d} | TID {tid} | {loc} | next={inst}"
                            self.root.after(0, self._append_access_log, line)
                            self.root.after(0, self._append_access_log, "    prev-window " + self._read_instruction_window(rip))
                            for reg_line in reg_lines:
                                self.root.after(0, self._append_access_log, "    " + reg_line)
                            if stack_lines:
                                self.root.after(0, self._append_access_log, "    stack callers:")
                                for stack_line in stack_lines:
                                    self.root.after(0, self._append_access_log, "      " + stack_line)
                            if hit_count >= HWBP_MAX_HITS:
                                self.root.after(0, self._append_access_log, f"Hit limit reached ({HWBP_MAX_HITS}).")
                                self.access_monitor_stop.set()
                kernel32.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE)
        finally:
            for tid in list(thread_ids):
                try:
                    self._clear_thread_breakpoint(tid)
                except Exception:
                    pass
            if debug_attached:
                kernel32.DebugActiveProcessStop(pid)
            self.root.after(0, self._append_access_log, "Monitor stopped.")

    def _start_access_monitor(self, address, vtype, mode):
        if self.access_monitor_thread and self.access_monitor_thread.is_alive():
            self._stop_access_monitor()
            time.sleep(0.25)
        self.access_monitor_stop = threading.Event()
        size = self._monitor_value_size(vtype)
        title = f"{'Writes' if mode == HWBP_MODE_WRITE else 'Accesses'} for {hex(address)} [{vtype}]"
        self._show_access_monitor_window(title)
        self.access_monitor_thread = threading.Thread(
            target=self._debug_loop_for_address,
            args=(self.pm.process_id, address, size, mode),
            daemon=True,
        )
        self.access_monitor_thread.start()

    def _add_to_favorites(self):
        a = self._sel_addr()
        if a is None: return
        
        d = tk.Toplevel(self.root)
        d.title("Add Favorite")
        d.geometry("300x120")
        d.configure(bg=PANEL)
        d.grab_set()
        tk.Label(d, text="Give this address a name:", bg=PANEL, fg=TEXT, font=("Segoe UI", 10)).pack(pady=10)
        e = tk.Entry(d, width=20, bg="#1e1e3a", fg=TEXT, insertbackground=TEXT, font=("Segoe UI", 11), relief="flat")
        e.pack(); e.focus()
        
        def ok():
            name = e.get().strip() or "Unnamed"
            val = self.tree.set(str(a), "Value")
            vtype = self._vtype()
            
            # Check if exists
            if self.fav_tree.exists(str(a)):
                self.fav_tree.delete(str(a))
                
            self.fav_tree.insert("", "end", iid=str(a), values=(name, hex(a), val, vtype, ""))
            self._save_favorites()
            self._log(f"Added to favorites: {name} ({hex(a)})")
            d.destroy()
            
        e.bind("<Return>", lambda _: ok())
        tk.Button(d, text="Add", command=ok, bg=ACCENT, fg="white", relief="flat").pack(pady=10)

    def _show_fav_menu(self, event):
        iid = self.fav_tree.identify_row(event.y)
        if iid:
            self.fav_tree.selection_set(iid)
            self.fav_menu.post(event.x_root, event.y_root)
            
    def _write_fav(self):
        sel = self.fav_tree.selection()
        if not sel: return
        a = int(sel[0])
        vtype = self.fav_tree.set(sel[0], "Type")
        name = self.fav_tree.set(sel[0], "Name")
        
        d = tk.Toplevel(self.root)
        d.title("Write Value")
        d.geometry("300x120")
        d.configure(bg=PANEL)
        d.grab_set()
        tk.Label(d, text=f"New value for {name}:", bg=PANEL, fg=TEXT).pack(pady=10)
        e = tk.Entry(d, bg="#1e1e3a", fg=TEXT, insertbackground=TEXT)
        e.pack(); e.focus()
        
        def ok():
            try:
                v = parse_value(e.get(), vtype)
                raw = pack_value(v, vtype)
                if self.pm and self.attached:
                    force_write_memory(self.pm.process_handle, a, raw)
                    self.fav_tree.set(sel[0], "Value", format_value(v, vtype))
                    self._log(f"Favorite {name} changed -> {v}")
                else:
                    self._log("Game is not attached!")
            except Exception as ex:
                self._log(f"Write error: {ex}")
            d.destroy()
            
        e.bind("<Return>", lambda _: ok())
        tk.Button(d, text="Write", command=ok, bg=ACCENT, fg="white").pack(pady=10)
        
    def _freeze_fav(self):
        sel = self.fav_tree.selection()
        if not sel: return
        a = int(sel[0])
        vtype = self.fav_tree.set(sel[0], "Type")
        name = self.fav_tree.set(sel[0], "Name")
        
        d = tk.Toplevel(self.root)
        d.title("Freeze")
        d.geometry("300x120")
        d.configure(bg=PANEL)
        d.grab_set()
        tk.Label(d, text=f"Value to freeze for {name}:", bg=PANEL, fg=TEXT).pack(pady=10)
        e = tk.Entry(d, bg="#1e1e3a", fg=TEXT, insertbackground=TEXT)
        e.pack(); e.focus()
        
        def ok():
            try:
                v = parse_value(e.get(), vtype)
                raw = pack_value(v, vtype)
                self.frozen[a] = (raw, vtype)
                self.favorite_frozen.add(a)
                self.fav_tree.set(sel[0], "Value", format_value(v, vtype))
                self.fav_tree.set(sel[0], "Status", "❄ Frozen")
                if self.pm and self.attached:
                    force_write_memory(self.pm.process_handle, a, raw)
                self._log(f"Favorite {name} frozen -> {v}")
            except Exception as ex:
                self._log(f"Error: {ex}")
            d.destroy()
            
        e.bind("<Return>", lambda _: ok())
        tk.Button(d, text="Freeze", command=ok, bg=ACCENT, fg="white").pack(pady=10)

    def _unfreeze_fav(self):
        sel = self.fav_tree.selection()
        if not sel: return
        a = int(sel[0])
        if a in self.frozen:
            del self.frozen[a]
            self.favorite_frozen.discard(a)
            self.fav_tree.set(sel[0], "Status", "")
            self._log(f"Favorite unfrozen.")

    def _delete_fav(self):
        sel = self.fav_tree.selection()
        if not sel: return
        a = int(sel[0])
        self.frozen.pop(a, None)
        self.favorite_frozen.discard(a)
        self.favorites_meta.pop(sel[0], None)
        self.fav_tree.delete(sel[0])
        self._save_favorites()
        self._log("Favorite deleted.")

    def _move_to_results(self):
        sel = self.fav_tree.selection()
        if not sel: return
        resolved = self._resolve_fav_pointer(sel[0], update_ui=False)
        if resolved:
            sel = (str(resolved),)
        a = int(sel[0])
        val = self.fav_tree.set(sel[0], "Value")
        
        if not self.tree.exists(str(a)):
            self.tree.insert("", "end", iid=str(a), values=(hex(a), val, ""))
            
        if a not in self.scan_addrs:
            self.scan_addrs.append(a)
            
        self._log(f"Address moved back to search results: {hex(a)}")

    def _find_pointer_for_result(self):
        a = self._sel_addr()
        if a is None: return
        self._start_pointer_scan(a, save_to_favorite=False)

    def _find_pointer_for_fav(self):
        sel = self.fav_tree.selection()
        if not sel: return
        self._start_pointer_scan(int(sel[0]), save_to_favorite=True)

    def _start_pointer_scan(self, address, save_to_favorite):
        if not self._require(): return
        self._log(f"Pointer scan started for {hex(address)}. Depth={PTR_MAX_DEPTH}, max offset=0x{PTR_MAX_OFFSET:x}")
        threading.Thread(target=self._do_pointer_scan,
                         args=(address, save_to_favorite), daemon=True).start()

    def _do_pointer_scan(self, address, save_to_favorite):
        try:
            paths = find_pointer_paths(self.pm.process_handle, self.pm.process_id, address)
        except Exception as e:
            self.root.after(0, self._log, f"Pointer scan error: {e}")
            return

        if not paths:
            self.root.after(0, self._log, "No stable module-based pointer path found.")
            return

        verified = []
        for path in paths:
            resolved = resolve_pointer_path(self.pm.process_handle, self.pm.process_id, path)
            if resolved == address:
                verified.append(path)

        if not verified:
            self.root.after(0, self._log, "Pointer candidates were found, but none resolved back to this address.")
            return

        best = verified[0]
        self.root.after(0, self._store_pointer_path, address, best, save_to_favorite, len(verified))

    def _store_pointer_path(self, address, path, save_to_favorite, count):
        key = str(address)
        meta = self.favorites_meta.get(key, {})
        meta["pointer"] = path
        self.favorites_meta[key] = meta

        if save_to_favorite and self.fav_tree.exists(key):
            self.fav_tree.set(key, "Status", "Pointer")
            self._save_favorites()

        offsets = " -> ".join(f"+0x{o:x}" for o in path.get("offsets", []))
        self._log(f"Pointer path found ({count}): {path['module']}+0x{path['rva']:x} {offsets}")
        if not save_to_favorite:
            self._log("Add this address to Favorites, then use Find Pointer Path there to save it.")

    def _resolve_selected_fav_pointer(self):
        sel = self.fav_tree.selection()
        if not sel: return
        self._resolve_fav_pointer(sel[0], update_ui=True)

    def _resolve_fav_pointer(self, iid, update_ui=False):
        if not self._require(): return None
        meta = self.favorites_meta.get(str(iid), {})
        path = meta.get("pointer")
        if not path:
            if update_ui:
                self._log("This favorite has no saved pointer path.")
            return None

        new_addr, reason = explain_pointer_resolution(self.pm.process_handle, self.pm.process_id, path)
        if not new_addr:
            if update_ui:
                self._log(f"Pointer could not be resolved: {reason}")
            return None

        old_iid = str(iid)
        new_iid = str(new_addr)
        old_addr = int(old_iid)
        frozen_data = self.frozen.get(old_addr)
        vals = self.fav_tree.item(old_iid, "values") if self.fav_tree.exists(old_iid) else None
        if vals:
            name, _addr, val, vtype, status = vals
            try:
                val = format_value(read_value(self.pm.process_handle, new_addr, vtype), vtype)
            except:
                val = "?"
            if old_iid != new_iid and self.fav_tree.exists(old_iid):
                self.fav_tree.delete(old_iid)
            if self.fav_tree.exists(new_iid):
                self.fav_tree.delete(new_iid)
            self.fav_tree.insert("", "end", iid=new_iid,
                                 values=(name, hex(new_addr), val, vtype, "Pointer"))

            if not self.tree.exists(new_iid):
                self.tree.insert("", "end", iid=new_iid,
                                 values=(hex(new_addr), val, "Pointer"))
            if new_addr not in self.scan_addrs:
                self.scan_addrs.append(new_addr)

        self.favorites_meta[new_iid] = meta
        if old_iid != new_iid:
            self.favorites_meta.pop(old_iid, None)
            if old_addr in self.favorite_frozen:
                self.favorite_frozen.discard(old_addr)
                self.favorite_frozen.add(new_addr)
                if frozen_data:
                    self.frozen.pop(old_addr, None)
                    self.frozen[new_addr] = frozen_data
        self._save_favorites()
        if update_ui:
            self._log(f"Pointer resolved: {hex(int(iid))} -> {hex(new_addr)}")
        return new_addr

    def _resolve_all_favorite_pointers(self):
        if not self.attached:
            return
        resolved = 0
        for iid in list(self.favorites_meta.keys()):
            if self.favorites_meta.get(iid, {}).get("pointer"):
                if self._resolve_fav_pointer(iid):
                    resolved += 1
        if resolved:
            self._log(f"Resolved {resolved} saved pointer favorite(s).")

    def _save_favorites(self):
        if getattr(self, "loading_favorites", False):
            return
        try:
            self._write_favorites_file(self._current_favorites())
        except Exception as e:
            self._log(f"Favorites could not be saved: {e}")

    def _load_favorites(self):
        if not os.path.exists(FAVORITES_FILE):
            try:
                self._write_favorites_file([])
                self._log(f"Favorites file ready: {FAVORITES_FILE}")
            except Exception as e:
                self._log(f"Favorites file could not be created: {e}")
            return
        try:
            with open(FAVORITES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            favorites, migrated = self._favorites_from_file_data(data)
            self._load_favorites_into_tree(favorites)
            self._save_favorites()
            if migrated:
                self._log("Old preset favorites migrated to single Favorites list.")
            self._log(f"Favorites loaded: {len(favorites)}")
            self.root.after(1000, self._resolve_all_favorite_pointers)
        except Exception as e:
            self._log(f"Favorites could not be loaded: {e}")

    # ──────────────────────────────────────────
    # Cheat Engine-style scan flow. These definitions intentionally live late
    # in the class so they replace the original exact-only scan handlers.
    def _first_scan(self):
        if not self._require(): return
        vtype = self._vtype()
        try:
            v = parse_value(self.scan_val.get(), vtype)
        except:
            messagebox.showerror("Error", "Enter a valid number"); return
        self._log(f"First scan: {v} ({vtype}) - please wait...")
        self.btn_info = "scanning"
        threading.Thread(target=self._do_scan, args=(v, None), daemon=True).start()

    def _next_scan(self):
        if not self._require(): return
        if not self.scan_addrs:
            messagebox.showinfo("Info", "Run First Scan first."); return

        vtype = getattr(self, 'current_scan_type', self._vtype())
        mode = self.compare_mode.get()
        v = None
        if mode == "Exact Value":
            try:
                v = parse_value(self.scan_val.get(), vtype)
            except:
                messagebox.showerror("Error", "Enter a valid number"); return

        self._log(f"Filtering ({mode}) in {len(self.scan_addrs)} addresses...")
        self.btn_info = "scanning"
        threading.Thread(target=self._do_compare_scan, args=(mode, v, vtype), daemon=True).start()

    def _do_scan(self, target, prev):
        vtype = self._vtype()
        self.current_scan_type = vtype
        self.current_scan_val = target
        target_bytes = pack_value(target, vtype)
        found_addrs = scan_memory(self.pm.process_handle, target_bytes, prev)

        vals = []
        snapshot = {}
        for a in found_addrs:
            try:
                val = read_value(self.pm.process_handle, a, vtype)
                snapshot[a] = val
                if len(vals) < 500:
                    vals.append(val)
            except:
                if len(vals) < 500:
                    vals.append(0)

        self.scan_addrs = found_addrs
        self.scan_values = snapshot
        self.scan_status = {}
        self.root.after(0, self._update_tree, found_addrs[:500], vals, self.scan_status)
        self.root.after(0, self._log,
                        f"Scan complete: {len(found_addrs)} results found.")
        self.btn_info = ""

    def _do_compare_scan(self, mode, target, vtype):
        found = []
        values = {}
        markers = {}

        if mode == "Exact Value":
            try:
                target_bytes = pack_value(target, vtype)
                exact_addrs = scan_memory(self.pm.process_handle, target_bytes, self.scan_addrs)
            except Exception as e:
                self.root.after(0, self._log, f"Exact filter error: {e}")
                self.btn_info = ""
                return

            for a in exact_addrs:
                try:
                    values[a] = read_value(self.pm.process_handle, a, vtype)
                except:
                    values[a] = target
                markers[a] = "Exact"

            self.scan_addrs = exact_addrs
            self.scan_values = values
            self.scan_status = markers
            shown = exact_addrs[:500]
            self.root.after(0, self._update_tree, shown, [values[a] for a in shown], markers)
            self.root.after(0, self._log,
                            f"Filter complete: {len(exact_addrs)} results remain.")
            self.btn_info = ""
            return

        for a in list(self.scan_addrs):
            old = self.scan_values.get(a)
            try:
                new = read_value(self.pm.process_handle, a, vtype)
            except:
                continue

            keep = False
            marker = ""
            if mode == "Changed":
                keep = old is not None and not values_equal(new, old, vtype)
                marker = "Changed"
            elif mode == "Unchanged":
                keep = old is not None and values_equal(new, old, vtype)
                marker = "Same"
            elif mode == "Increased":
                keep = old is not None and new > old
                marker = "Increased"
            elif mode == "Decreased":
                keep = old is not None and new < old
                marker = "Decreased"

            if keep:
                found.append(a)
                values[a] = new
                markers[a] = marker

        self.scan_addrs = found
        self.scan_values = values
        self.scan_status = markers
        shown = found[:500]
        self.root.after(0, self._update_tree, shown, [values[a] for a in shown], markers)
        self.root.after(0, self._log,
                        f"Filter complete: {len(found)} results remain.")
        self.btn_info = ""

    def _snapshot_before(self):
        if not self._require(): return
        if not self.scan_addrs:
            messagebox.showinfo("Snapshot", "Run a scan first, then take Before Snap.")
            return
        vtype = getattr(self, 'current_scan_type', self._vtype())
        self._log(f"Before snapshot started for {len(self.scan_addrs)} address(es) as {vtype}.")
        self.btn_info = "scanning"
        threading.Thread(target=self._do_snapshot_before, args=(vtype,), daemon=True).start()

    def _do_snapshot_before(self, vtype):
        snap = {}
        for a in list(self.scan_addrs):
            try:
                snap[a] = read_value(self.pm.process_handle, a, vtype)
            except:
                pass
        self.snapshot_before = snap
        self.snapshot_type = vtype
        self.scan_values = dict(snap)
        self.btn_info = ""
        self.root.after(0, self._log, f"Before snapshot captured: {len(snap)} readable address(es).")

    def _snapshot_after_compare(self):
        if not self._require(): return
        if not self.snapshot_before:
            messagebox.showinfo("Snapshot", "Take Before Snap first.")
            return
        vtype = self.snapshot_type or getattr(self, 'current_scan_type', self._vtype())
        self._log(f"After compare started against {len(self.snapshot_before)} snapshot address(es).")
        self.btn_info = "scanning"
        threading.Thread(target=self._do_snapshot_after_compare, args=(vtype,), daemon=True).start()

    def _do_snapshot_after_compare(self, vtype):
        changed = []
        values = {}
        markers = {}
        rows = []
        for a, old in list(self.snapshot_before.items()):
            try:
                new = read_value(self.pm.process_handle, a, vtype)
            except:
                continue
            if not values_equal(new, old, vtype):
                changed.append(a)
                values[a] = new
                markers[a] = "Snap Changed"
                rows.append({
                    "address": hex(a),
                    "type": vtype,
                    "before": format_value(old, vtype),
                    "after": format_value(new, vtype),
                    "delta": self._snapshot_delta(old, new),
                })

        out_path = os.path.join(APP_DIR, "snapshot_changes.csv")
        try:
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["address", "type", "before", "after", "delta"])
                writer.writeheader()
                writer.writerows(rows)
        except Exception as e:
            self.root.after(0, self._log, f"Snapshot CSV write error: {e}")

        self.scan_addrs = changed
        self.scan_values = values
        self.scan_status = markers
        shown = changed[:500]
        self.root.after(0, self._update_tree, shown, [values[a] for a in shown], markers)
        self.root.after(0, self._log, f"After compare complete: {len(changed)} changed address(es).")
        self.root.after(0, self._log, f"Snapshot diff saved: {out_path}")
        self.btn_info = ""

    def _snapshot_delta(self, old, new):
        try:
            return format(new - old, ".10g")
        except:
            return ""

    def _reset_scan(self):
        self.scan_addrs = []
        self.scan_values = {}
        self.scan_status = {}
        self.snapshot_before = {}
        self.snapshot_type = None
        self.tree.delete(*self.tree.get_children())
        self.scan_info.config(text="Results: -")
        self._log("Scan reset.")

    def _close(self):
        self._stop_access_monitor()
        self._restore_angelic_drop_boost(silent=True)
        self._save_favorites()
        self.attached = False
        self.root.destroy()

    def run(self):
        self.root.mainloop()

# ──────────────────────────────────────────────
if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False
        if not is_admin:
            params = "" if getattr(sys, "frozen", False) else f'"{__file__}"'
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                params, None, 1)
            sys.exit()
    Trainer().run()
