from __future__ import annotations

import threading
import time
from typing import Callable

from .license_client import LicenseClient, LicenseClientError


class HeartbeatWorker(threading.Thread):
    def __init__(
        self,
        *,
        client: LicenseClient,
        interval_seconds: int,
        token_getter: Callable[[], str],
        token_setter: Callable[[str], None],
        device_id: str,
        device_fingerprint: str,
        app_version: str,
        on_invalid: Callable[[str], None],
    ) -> None:
        super().__init__(daemon=True)
        self.client = client
        self.interval_seconds = int(interval_seconds)
        self.token_getter = token_getter
        self.token_setter = token_setter
        self.device_id = device_id
        self.device_fingerprint = device_fingerprint
        self.app_version = app_version
        self.on_invalid = on_invalid
        self.started_ts = time.time()
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        while not self._stop_event.is_set():
            token = self.token_getter()
            if not token:
                self.on_invalid("Missing activation token")
                return

            uptime = int(time.time() - self.started_ts)
            try:
                body = self.client.heartbeat(
                    activation_token=token,
                    device_id=self.device_id,
                    device_fingerprint=self.device_fingerprint,
                    app_version=self.app_version,
                    uptime_seconds=uptime,
                )
            except LicenseClientError as exc:
                self.on_invalid(f"Heartbeat transport error: {exc}")
                return

            if not body.get("valid"):
                self.on_invalid(str(body.get("reason") or "Heartbeat rejected"))
                return

            refreshed = str(body.get("activation_token") or "").strip()
            if refreshed:
                self.token_setter(refreshed)

            wait_until = time.time() + self.interval_seconds
            while time.time() < wait_until:
                if self._stop_event.wait(0.5):
                    return
