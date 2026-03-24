# Commercial-Grade Licensing System (Hardened)

This project now includes a hardened license server and hardened Windows client runtime.

## Architecture

- `server/`
  - `auth/token_manager.py`: HMAC key hashing, activation JWTs, launch JWTs.
  - `auth/challenge_system.py`: startup nonce challenge + HMAC verification.
  - `security_tools/secrets_policy.py`: startup secret entropy checks.
  - `security_tools/transport_guard.py`: HTTPS-only transport guard.
  - `security_tools/rate_limiter.py`: sliding-window rate limiter.
  - `security_tools/abuse_detection.py`: anomaly logging, auto-revocation.
  - `main.py`: full API (generate, challenge, activate, validate, heartbeat, revoke, events).
- `client/`
  - `security/dpapi_storage.py`: DPAPI encrypted token storage (user-bound).
  - `security/cert_pinning.py`: server certificate public-key pinning.
  - `security/device_fingerprint.py`: multi-signal hardware fingerprinting.
  - `security/anti_tamper.py`: debugger/signature/hash/injection checks.
  - `licensing/license_client.py`: signed HTTPS API client.
  - `licensing/heartbeat.py`: short-interval heartbeat thread.
  - `app.py`: launch flow with challenge-response + token persistence.

## Security Features Implemented

1. Secret enforcement on startup (`SECURE_STARTUP_ENFORCED=true`):
   - Blocks weak/default values for:
     - `ADMIN_TOKEN`
     - `LICENSE_KEY_SECRET`
     - `ACTIVATION_TOKEN_SECRET`
     - `CLIENT_SHARED_SECRET`
     - `JWT_SECRET`
     - `SERVER_SECRET`
     - `API_SECRET`
     - `HMAC_KEY`
     - `LICENSE_SIGNING_KEY`
2. HTTPS transport guard with localhost exception toggle.
3. Client certificate pinning using SHA256 of server public key (SPKI).
4. DPAPI token-at-rest encryption bound to Windows user profile.
5. 30-minute activation token TTL and 15-30 second heartbeat flow.
6. Startup challenge-response (`/challenge/request`, `/challenge/verify`) with nonce + timestamp + HMAC SHA256.
7. Strong device fingerprinting tied to CPU, board, disk, machine GUID, MAC.
8. Anti-tamper client checks (debugger, suspicious tools/modules, runtime code integrity, code signing).
9. Critical licensing logic remains server-authoritative.
10. Abuse controls:
    - per-IP rate limits
    - per-license rate limits
    - heartbeat failure tracking
    - IP-movement anomaly tracking
    - tamper event reporting
    - auto-revocation/flagging

## API Endpoints

- `POST /generate` (admin)
- `POST /challenge/request` (signed client)
- `POST /challenge/verify` (signed client)
- `POST /activate` (signed client)
- `POST /validate` (signed client)
- `POST /heartbeat` (signed client)
- `POST /security/event` (signed client)
- `POST /deactivate` (admin or activation token)
- `POST /revoke` (admin)
- `POST /revoke-by-id` (admin)
- `GET /licenses` (admin)
- `GET /license/{key}` (admin)
- `GET /security/events` (admin)

## Setup (Server)

```powershell
cd "C:\Users\jay\Downloads\macor tool\licensing-system"
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

1. Copy `.env.example` to `.env`.
2. Replace all placeholder secrets with strong random values.
3. Ensure `DEVICE_HMAC_KEY` matches `HMAC_KEY` in client environment.
4. Run with HTTPS in production (reverse proxy or uvicorn TLS certs).

Development launch:

```powershell
uvicorn server.main:app --host 127.0.0.1 --port 8000
```

## Setup (Client)

Required environment variables before running `python -m client.app`:

- `LICENSE_SERVER_URL=https://...`
- `PINNED_PUBLIC_KEY_SHA256=<64-char hex SPKI pin>`
- `CLIENT_SHARED_SECRET=<must match server CLIENT_SHARED_SECRET>`
- `DEVICE_HMAC_KEY=<must match server HMAC_KEY>`

Optional:

- `REQUIRE_CODE_SIGNATURE=true|false`
- `EXPECTED_SELF_SHA256=<sha256 of built exe/script>`
- `HEARTBEAT_INTERVAL_SECONDS=15`

Run client:

```powershell
python -m client.app
```

## Database Schema

See `schema.sql` for full schema including:

- `licenses`
- `activations`
- `challenge_sessions`
- `security_events`

## Notes

- If secret policy fails, server startup aborts by design.
- If certificate pinning fails, client aborts by design.
- If tampering is detected, client terminates and reports event.

## Public Download Distribution

After building a new installer, publish it for customer downloads:

```powershell
cd "C:\Users\jay\Downloads\macor tool"
.\installer\build_release.ps1 -Builder Nuitka -Version 1.0.0 -PublishDownload
```

This updates:

- `licensing-system/server/downloads/MacroSuiteSetup_latest.exe`
- `licensing-system/server/downloads/MacroSuiteSetup_v<version>.exe`
- `licensing-system/server/downloads/latest.json`

Public endpoints exposed by the server:

- `GET /download/latest` -> downloads latest installer
- `GET /download/latest.json` -> version/hash metadata
- `GET /download/install.ps1` -> PowerShell bootstrap installer script

Customer one-liner (replace domain):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://your-domain/download/install.ps1' | iex"
```
