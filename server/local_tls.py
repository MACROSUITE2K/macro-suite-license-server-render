from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class TlsMaterial:
    host: str
    cert_path: str
    key_path: str
    trust_path: str
    fingerprint_sha256: str
    public_key_pin_sha256: str
    not_before_utc: str
    not_after_utc: str


def _load_metadata(path: Path) -> TlsMaterial | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    try:
        return TlsMaterial(**payload)
    except Exception:
        return None


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _public_key_pin_sha256(cert: x509.Certificate) -> str:
    public_key_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_key_der).hexdigest()


def _load_existing_cert(cert_path: Path) -> x509.Certificate | None:
    if not cert_path.is_file():
        return None
    try:
        raw = cert_path.read_bytes()
        return x509.load_pem_x509_certificate(raw)
    except Exception:
        return None


def _cert_is_usable(cert: x509.Certificate | None, *, host: str, minimum_validity_days: int = 30) -> bool:
    if cert is None:
        return False

    now = datetime.now(timezone.utc)
    if cert.not_valid_before_utc > now:
        return False
    if cert.not_valid_after_utc <= now + timedelta(days=minimum_validity_days):
        return False

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False

    if _is_ip_address(host):
        try:
            return ipaddress.ip_address(host) in san.get_values_for_type(x509.IPAddress)
        except ValueError:
            return False

    return host in san.get_values_for_type(x509.DNSName)


def _generate_tls_material(*, host: str, cert_path: Path, key_path: Path, trust_path: Path, days: int) -> TlsMaterial:
    now = datetime.now(timezone.utc)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, host),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Macro Suite Local License"),
        ]
    )

    san_entries: list[x509.GeneralName]
    if _is_ip_address(host):
        san_entries = [x509.IPAddress(ipaddress.ip_address(host))]
    else:
        san_entries = [x509.DNSName(host)]

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    trust_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    return TlsMaterial(
        host=host,
        cert_path=str(cert_path.resolve()),
        key_path=str(key_path.resolve()),
        trust_path=str(trust_path.resolve()),
        fingerprint_sha256=_cert_fingerprint_sha256(cert),
        public_key_pin_sha256=_public_key_pin_sha256(cert),
        not_before_utc=cert.not_valid_before_utc.isoformat(),
        not_after_utc=cert.not_valid_after_utc.isoformat(),
    )


def ensure_local_tls_material(*, host: str, out_dir: Path, days: int = 825) -> TlsMaterial:
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / "license-server-cert.pem"
    key_path = out_dir / "license-server-key.pem"
    trust_path = out_dir / "license-server-cert.cer"
    metadata_path = out_dir / "license-server-cert.json"

    metadata = _load_metadata(metadata_path)
    if metadata:
        cert = _load_existing_cert(Path(metadata.cert_path))
        if (
            Path(metadata.cert_path).is_file()
            and Path(metadata.key_path).is_file()
            and Path(metadata.trust_path).is_file()
            and _cert_is_usable(cert, host=host)
        ):
            return metadata

    material = _generate_tls_material(
        host=host,
        cert_path=cert_path,
        key_path=key_path,
        trust_path=trust_path,
        days=days,
    )
    metadata_path.write_text(json.dumps(asdict(material), indent=2), encoding="utf-8")
    return material


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision local TLS material for the Macro Suite license server.")
    parser.add_argument("--host", required=True, help="DNS host or IP address clients will use to reach the local HTTPS server.")
    parser.add_argument("--out-dir", required=True, help="Directory where the cert/key pair should be stored.")
    parser.add_argument("--days", type=int, default=825, help="Validity period for newly generated certificates.")
    args = parser.parse_args()

    material = ensure_local_tls_material(host=str(args.host).strip(), out_dir=Path(args.out_dir), days=int(args.days))
    print(json.dumps(asdict(material)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
