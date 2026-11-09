"""TLS certificate handling shared by the HTTPS listener and SMTP submission.

Uses TLS_CERT/TLS_KEY when set (e.g. a Let's Encrypt cert copied from the NPM server);
otherwise generates a self-signed certificate in <data>/tls/ covering the configured
hostnames, regenerating it if those hostnames change.
"""
from __future__ import annotations

import datetime as dt
import logging
import os

from .config import Settings

log = logging.getLogger("relay.tls")


def cert_names(settings: Settings) -> list[str]:
    return list(dict.fromkeys(n for n in (settings.public_hostname, settings.submission_hostname,
                                          "email-relay", "localhost") if n))


def resolve_tls_files(settings: Settings) -> tuple[str, str]:
    if settings.tls_cert:
        return settings.tls_cert, settings.tls_key
    directory = os.path.join(os.path.dirname(os.path.abspath(settings.db_path)), "tls")
    return ensure_self_signed(directory, cert_names(settings))


def ensure_self_signed(directory: str, names: list[str]) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    cert_path, key_path = os.path.join(directory, "selfsigned.crt"), os.path.join(directory, "selfsigned.key")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        existing = describe_cert(cert_path)
        if set(names) <= set(existing.get("names", [])):
            return cert_path, key_path
        log.warning("Self-signed certificate does not cover %s; regenerating", names)
    os.makedirs(directory, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256()))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    log.warning("Generated self-signed certificate for %s at %s", ", ".join(names), cert_path)
    return cert_path, key_path


def describe_cert(path: str) -> dict:
    from cryptography import x509
    try:
        with open(path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        try:
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                "names": sans, "not_after": cert.not_valid_after_utc.timestamp(),
                "self_signed": cert.issuer == cert.subject}
    except Exception as e:  # surfaced in the admin UI
        return {"error": f"{type(e).__name__}: {e}"}
