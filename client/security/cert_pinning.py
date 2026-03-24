from __future__ import annotations

import hashlib
import secrets
import socket
import ssl
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class CertificatePinningError(RuntimeError):
    pass


def _public_key_sha256_hex_from_der_certificate(cert_der: bytes) -> str:
    cert = x509.load_der_x509_certificate(cert_der)
    public_key_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_key_der).hexdigest()


def fetch_server_public_key_sha256(*, host: str, port: int, timeout: int = 8) -> str:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)
    if not cert_der:
        raise CertificatePinningError("No TLS certificate presented by server.")
    return _public_key_sha256_hex_from_der_certificate(cert_der)


def assert_pinned_public_key(url: str, expected_pin_sha256_hex: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise CertificatePinningError("HTTPS is required for certificate pinning.")

    host = parsed.hostname or ""
    if not host:
        raise CertificatePinningError("Invalid server URL; missing host.")

    port = int(parsed.port or 443)
    expected = str(expected_pin_sha256_hex or "").strip().lower()
    if len(expected) != 64:
        raise CertificatePinningError("Pinned key fingerprint must be a 64-char SHA256 hex string.")

    actual = fetch_server_public_key_sha256(host=host, port=port)
    if not secrets.compare_digest(actual, expected):
        raise CertificatePinningError(
            "Certificate pin mismatch. Refusing connection. "
            f"expected={expected} actual={actual}"
        )
