from __future__ import annotations

import json
import subprocess
from pathlib import Path


class CodeSigningError(RuntimeError):
    pass


def verify_authenticode_signature(file_path: Path) -> tuple[bool, str]:
    path = str(file_path.resolve())
    escaped = path.replace("'", "''")
    command = (
        "$s = Get-AuthenticodeSignature -FilePath '"
        + escaped
        + "'; "
        "$s | Select-Object Status,StatusMessage,SignerCertificate | ConvertTo-Json -Depth 4"
    )

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    if result.returncode != 0:
        return False, (result.stderr or "PowerShell signature check failed").strip()

    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        return False, f"Unable to parse signature output: {exc}"

    status = str(data.get("Status") or "Unknown")
    message = str(data.get("StatusMessage") or "")

    if status.lower() == "valid":
        return True, message or "Valid"

    return False, f"Authenticode status: {status}. {message}".strip()
