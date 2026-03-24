from __future__ import annotations

import hashlib
import hmac
import platform
import socket
import subprocess
import uuid


def _run_powershell(command: str) -> str:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    if result.returncode != 0:
        return ""
    return (result.stdout or "").strip()


def collect_device_signals() -> dict[str, str]:
    cpu_id = _run_powershell("(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty ProcessorId)")
    board_serial = _run_powershell("(Get-CimInstance Win32_BaseBoard | Select-Object -First 1 -ExpandProperty SerialNumber)")
    disk_serial = _run_powershell("(Get-CimInstance Win32_DiskDrive | Select-Object -First 1 -ExpandProperty SerialNumber)")
    machine_guid = _run_powershell("(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid).MachineGuid")

    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "cpu_id": cpu_id,
        "board_serial": board_serial,
        "disk_serial": disk_serial,
        "machine_guid": machine_guid,
        "mac": f"{uuid.getnode():012x}",
    }


def build_device_fingerprint() -> str:
    signals = collect_device_signals()
    canonical = "|".join(f"{k}={signals.get(k, '').strip()}" for k in sorted(signals))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_device_id(device_fingerprint: str) -> str:
    return device_fingerprint[:40]


def derive_device_key(device_fingerprint: str, device_hmac_key: str) -> bytes:
    return hmac.new(
        device_hmac_key.encode("utf-8"),
        device_fingerprint.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def build_challenge_signature(
    *,
    challenge_id: str,
    nonce: str,
    timestamp: int,
    device_id: str,
    device_fingerprint: str,
    device_hmac_key: str,
) -> str:
    key = derive_device_key(device_fingerprint=device_fingerprint, device_hmac_key=device_hmac_key)
    payload = f"{challenge_id}\n{nonce}\n{int(timestamp)}\n{device_id}\n{device_fingerprint}".encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()
