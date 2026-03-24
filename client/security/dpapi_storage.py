from __future__ import annotations

import base64
import json
from pathlib import Path

import win32crypt


class DPAPIStorageError(RuntimeError):
    pass


class DPAPIStorage:
    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path

    def save_json(self, payload: dict) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        encrypted = win32crypt.CryptProtectData(raw, None, None, None, None, 0)
        blob = {
            "version": 1,
            "data": base64.b64encode(encrypted).decode("ascii"),
        }
        self.file_path.write_text(json.dumps(blob), encoding="utf-8")

    def load_json(self) -> dict | None:
        if not self.file_path.exists():
            return None
        try:
            blob = json.loads(self.file_path.read_text(encoding="utf-8"))
            encoded = str(blob.get("data") or "")
            encrypted = base64.b64decode(encoded.encode("ascii"))
            decrypted = win32crypt.CryptUnprotectData(encrypted, None, None, None, 0)[1]
            return json.loads(decrypted.decode("utf-8"))
        except Exception as exc:
            raise DPAPIStorageError(f"Unable to decrypt state: {exc}") from exc

    def clear(self) -> None:
        if self.file_path.exists():
            self.file_path.unlink(missing_ok=True)
