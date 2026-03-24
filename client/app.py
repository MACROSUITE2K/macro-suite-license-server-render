from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from .config import ClientConfig
from .licensing.heartbeat import HeartbeatWorker
from .licensing.license_client import LicenseClient, LicenseClientError
from .security.anti_tamper import TamperDetectedError, run_anti_tamper_checks
from .security.device_fingerprint import build_challenge_signature, build_device_fingerprint, build_device_id
from .security.dpapi_storage import DPAPIStorage, DPAPIStorageError


def _build_storage(config: ClientConfig) -> DPAPIStorage:
    return DPAPIStorage(config.state_dir / config.state_file)


def _runtime_executable_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable)
    return Path(__file__).resolve()


def main() -> int:
    config = ClientConfig()
    storage = _build_storage(config)
    client = LicenseClient(config)

    device_fingerprint = build_device_fingerprint()
    device_id = build_device_id(device_fingerprint)

    state: dict = {}
    try:
        loaded = storage.load_json()
        if loaded:
            state = loaded
    except DPAPIStorageError as exc:
        print(f"State load failed: {exc}")

    license_key = str(state.get("license_key") or "").strip().upper()
    activation_token = str(state.get("activation_token") or "").strip()

    def report_security(reason: str) -> None:
        try:
            client.report_security_event(
                event_type="client.tamper",
                severity="critical",
                detail=reason,
                activation_token=activation_token or None,
                license_key=license_key or None,
                device_id=device_id,
                device_fingerprint=device_fingerprint,
            )
        except Exception:
            pass

    try:
        run_anti_tamper_checks(
            executable_path=_runtime_executable_path(),
            expected_self_sha256=config.expected_self_sha256 or None,
            require_code_signature=bool(config.require_code_signature),
            on_detection=report_security,
        )
    except TamperDetectedError as exc:
        print(f"Tamper detection triggered: {exc}")
        return 1

    if activation_token:
        try:
            body = client.validate(
                activation_token=activation_token,
                device_id=device_id,
                device_fingerprint=device_fingerprint,
            )
        except LicenseClientError as exc:
            print(f"Validation failed: {exc.message} {exc.body or ''}")
            body = {}

        if body.get("valid"):
            refreshed = str(body.get("activation_token") or "").strip()
            if refreshed:
                activation_token = refreshed
                state.update(
                    {
                        "license_key": license_key,
                        "device_id": device_id,
                        "device_fingerprint": device_fingerprint,
                        "activation_token": activation_token,
                    }
                )
                storage.save_json(state)
        else:
            activation_token = ""

    if not activation_token:
        user_key = input("Enter license key (XXXX-XXXX-XXXX-XXXX): ").strip().upper()
        if not user_key:
            print("No key entered.")
            return 1

        try:
            challenge = client.request_challenge(
                license_key=user_key,
                device_id=device_id,
                device_name=os.environ.get("COMPUTERNAME", "Windows Device"),
                device_fingerprint=device_fingerprint,
            )
            ts = int(time.time())
            signature = build_challenge_signature(
                challenge_id=challenge["challenge_id"],
                nonce=challenge["nonce"],
                timestamp=ts,
                device_id=device_id,
                device_fingerprint=device_fingerprint,
                device_hmac_key=config.device_hmac_key,
            )
            verify = client.verify_challenge(
                challenge_id=challenge["challenge_id"],
                license_key=user_key,
                device_id=device_id,
                device_fingerprint=device_fingerprint,
                timestamp=ts,
                signature=signature,
            )
            launch_token = str(verify.get("launch_token") or "").strip()
            if not launch_token:
                print("Challenge verification did not return a launch token.")
                return 1

            activation = client.activate(
                license_key=user_key,
                device_id=device_id,
                device_name=os.environ.get("COMPUTERNAME", "Windows Device"),
                device_fingerprint=device_fingerprint,
                launch_token=launch_token,
            )
        except LicenseClientError as exc:
            print(f"Activation failed: {exc.message} {exc.body or ''}")
            return 1

        activation_token = str(activation.get("activation_token") or "").strip()
        if not activation_token:
            print("Activation succeeded but token was missing.")
            return 1

        license_key = user_key
        state = {
            "license_key": license_key,
            "device_id": device_id,
            "device_fingerprint": device_fingerprint,
            "activation_token": activation_token,
        }
        storage.save_json(state)

    invalid_event = threading.Event()
    invalid_reason = {"reason": ""}

    def on_invalid(reason: str) -> None:
        invalid_reason["reason"] = reason
        invalid_event.set()

    def token_getter() -> str:
        return state.get("activation_token") or activation_token

    def token_setter(new_token: str) -> None:
        state["activation_token"] = new_token
        storage.save_json(state)

    worker = HeartbeatWorker(
        client=client,
        interval_seconds=config.heartbeat_interval_seconds,
        token_getter=token_getter,
        token_setter=token_setter,
        device_id=device_id,
        device_fingerprint=device_fingerprint,
        app_version=config.app_version,
        on_invalid=on_invalid,
    )
    worker.start()

    print("License valid. Protected session started.")
    print("Heartbeat active. Press Ctrl+C to exit.")

    try:
        while not invalid_event.wait(0.5):
            pass
    except KeyboardInterrupt:
        worker.stop()
        worker.join(timeout=2)
        print("Session closed.")
        return 0

    worker.stop()
    worker.join(timeout=2)
    reason = invalid_reason["reason"] or "Session invalidated"
    print(f"Session terminated: {reason}")
    try:
        client.report_security_event(
            event_type="client.session_terminated",
            severity="warning",
            detail=reason,
            activation_token=state.get("activation_token"),
            license_key=state.get("license_key"),
            device_id=device_id,
            device_fingerprint=device_fingerprint,
        )
    except Exception:
        pass

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
