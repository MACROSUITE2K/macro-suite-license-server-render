from __future__ import annotations

import ctypes
import hashlib
import os
import sys
from pathlib import Path
from typing import Callable

import psutil

from .code_signing import verify_authenticode_signature


class TamperDetectedError(RuntimeError):
    pass


SUSPICIOUS_PROCESS_NAMES = {
    "cheatengine.exe",
    "ida64.exe",
    "ida.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "ghidra.exe",
    "processhacker.exe",
    "wireshark.exe",
}

SUSPICIOUS_MODULE_HINTS = {"frida", "dbghelp", "cheatengine", "x64dbg", "ollydbg"}


def _sentinel() -> int:
    value = 0x1234ABCD
    return ((value << 3) ^ 0x55AA11) & 0xFFFFFFFF


EXPECTED_SENTINEL_HASH = hashlib.sha256(_sentinel.__code__.co_code).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _is_debugger_present() -> bool:
    if sys.gettrace() is not None:
        return True

    if os.name != "nt":
        return False

    kernel32 = ctypes.windll.kernel32
    if kernel32.IsDebuggerPresent() != 0:
        return True

    process_handle = kernel32.GetCurrentProcess()
    debugger_present = ctypes.c_int(0)
    kernel32.CheckRemoteDebuggerPresent(process_handle, ctypes.byref(debugger_present))
    return debugger_present.value != 0


def _has_suspicious_processes() -> str | None:
    for proc in psutil.process_iter(attrs=["name"]):
        try:
            name = str(proc.info.get("name") or "").strip().lower()
        except Exception:
            continue
        if name in SUSPICIOUS_PROCESS_NAMES:
            return name
    return None


def _has_suspicious_modules() -> str | None:
    try:
        current = psutil.Process(os.getpid())
        for mmap in current.memory_maps():
            path = str(getattr(mmap, "path", "") or "").lower()
            if not path:
                continue
            for hint in SUSPICIOUS_MODULE_HINTS:
                if hint in path:
                    return path
    except Exception:
        return None
    return None


def run_anti_tamper_checks(
    *,
    executable_path: Path,
    expected_self_sha256: str | None,
    require_code_signature: bool,
    on_detection: Callable[[str], None] | None = None,
) -> None:
    def fail(reason: str) -> None:
        if on_detection is not None:
            try:
                on_detection(reason)
            except Exception:
                pass
        raise TamperDetectedError(reason)

    if _is_debugger_present():
        fail("Debugger detected")

    proc_name = _has_suspicious_processes()
    if proc_name:
        fail(f"Suspicious process detected: {proc_name}")

    module_path = _has_suspicious_modules()
    if module_path:
        fail(f"Suspicious injected module detected: {module_path}")

    if hashlib.sha256(_sentinel.__code__.co_code).hexdigest() != EXPECTED_SENTINEL_HASH:
        fail("Runtime code integrity check failed")

    if expected_self_sha256:
        actual_hash = _sha256_file(executable_path)
        if actual_hash.lower() != expected_self_sha256.strip().lower():
            fail("Self-hash verification failed")

    if require_code_signature:
        ok, detail = verify_authenticode_signature(executable_path)
        if not ok:
            fail(f"Code signature invalid: {detail}")
