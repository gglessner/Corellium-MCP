"""
Parley-MCP Certificate Manager

Auto-generates a root CA and per-host TLS certificates for full MITM
interception without requiring pre-existing certificates.

Copyright (C) 2025 Garland Glessner (gglessner@gmail.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later version.
"""

import os
import threading
import datetime
import ipaddress
from typing import Tuple, Optional

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class CertManager:
    """Manages a root CA and generates per-host TLS certificates on demand."""

    def __init__(self, certs_dir: str):
        self.certs_dir = certs_dir
        os.makedirs(certs_dir, exist_ok=True)
        self._ca_cert = None
        self._ca_key = None
        self._host_cache: dict = {}
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return HAS_CRYPTOGRAPHY

    @property
    def ca_cert_path(self) -> str:
        return os.path.join(self.certs_dir, "parley-ca.pem")

    @property
    def ca_key_path(self) -> str:
        return os.path.join(self.certs_dir, "parley-ca-key.pem")

    @property
    def has_ca(self) -> bool:
        return os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path)

    def generate_ca(self) -> Tuple[str, str]:
        """Generate a new root CA certificate and private key.

        Returns:
            (cert_path, key_path) tuple
        """
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError(
                "The 'cryptography' package is required for auto-cert generation. "
                "Install with: pip install cryptography"
            )

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Parley-MCP Proxy"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Parley-MCP Root CA"),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        with open(self.ca_key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))

        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        self._ca_cert = cert
        self._ca_key = key
        self._host_cache.clear()

        return self.ca_cert_path, self.ca_key_path

    def _load_ca(self):
        """Load the CA cert/key from disk if not already loaded."""
        if self._ca_cert is not None:
            return

        if not self.has_ca:
            raise RuntimeError("No CA certificate. Call generate_ca() first.")

        with open(self.ca_cert_path, "rb") as f:
            self._ca_cert = x509.load_pem_x509_certificate(f.read())

        with open(self.ca_key_path, "rb") as f:
            self._ca_key = serialization.load_pem_private_key(f.read(), password=None)

    def generate_host_cert(self, hostname: str) -> Tuple[str, str]:
        """Generate a TLS certificate for a specific hostname, signed by the CA.

        Returns:
            (cert_path, key_path) tuple
        """
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography package required")

        self._load_ca()

        safe_name = hostname.replace("*", "wildcard").replace(":", "_")
        cert_path = os.path.join(self.certs_dir, f"{safe_name}.pem")
        key_path = os.path.join(self.certs_dir, f"{safe_name}-key.pem")

        with self._lock:
            if hostname in self._host_cache:
                return self._host_cache[hostname]

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])

            san_entries = []
            try:
                ipaddress.ip_address(hostname)
                san_entries.append(x509.IPAddress(ipaddress.ip_address(hostname)))
            except ValueError:
                san_entries.append(x509.DNSName(hostname))
                if not hostname.startswith("*."):
                    san_entries.append(x509.DNSName(f"*.{hostname}"))

            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self._ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(
                    x509.SubjectAlternativeName(san_entries), critical=False
                )
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None), critical=True
                )
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                    critical=False,
                )
                .sign(self._ca_key, hashes.SHA256())
            )

            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))

            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
                f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))

            self._host_cache[hostname] = (cert_path, key_path)
            return cert_path, key_path

    def get_or_generate(self, hostname: str) -> Tuple[str, str]:
        """Get existing or generate new host certificate.

        If no CA exists, generates one first.
        """
        if not self.has_ca:
            self.generate_ca()
        return self.generate_host_cert(hostname)
