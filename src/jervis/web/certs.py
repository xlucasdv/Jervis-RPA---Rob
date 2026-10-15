"""Certificado HTTPS da interface na rede interna.

Cria uma autoridade certificadora própria (instalada uma vez nos computadores da equipe, ou por política de
grupo) e o certificado do servidor assinado por ela. Renovar o do servidor não exige reinstalar nada.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_NAME = "Jervis3000 CA interna"
SERVER_DAYS = 397  # navegadores recusam certificados de servidor mais longos
CA_DAYS = 3650


def local_names(extra: list[str] | None = None) -> tuple[list[str], list[str]]:
    """Nomes e IPs desta máquina na rede, para o certificado valer em qualquer um deles."""
    host = socket.gethostname()
    names = [n for n in dict.fromkeys([*(extra or []), host.lower(), socket.getfqdn().lower(), "localhost"]) if n]
    ips = {"127.0.0.1"}
    try:
        ips |= {info[4][0] for info in socket.getaddrinfo(host, None, socket.AF_INET)}
    except OSError:
        pass
    hostnames = [n for n in names if not _is_ip(n)]
    return hostnames, sorted(ips | {n for n in names if _is_ip(n)})


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if sys.platform == "win32":  # só o usuário atual lê a chave
        user = os.environ.get("USERNAME")
        if user:
            subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"], capture_output=True)
    else:
        os.chmod(path, 0o600)


def _key_bytes(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def ensure_ca(folder: Path) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey, bool]:
    """Autoridade certificadora interna (cria na primeira vez). Devolve (certificado, chave, criada agora)."""
    cert_path, key_path = folder / "jervis-ca.pem", folder / "jervis-ca.key"
    if cert_path.is_file() and key_path.is_file():
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        return cert, key, False
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Jervis3000")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    _write_private(key_path, _key_bytes(key))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / "jervis-ca.cer").write_bytes(cert.public_bytes(serialization.Encoding.DER))  # para instalar no Windows
    return cert, key, True


def make_server_certificate(cert_file: Path, key_file: Path, hostnames: list[str], ips: list[str]) -> tuple[Path, bool]:
    """Certificado do servidor assinado pela CA interna. Devolve (arquivo .cer da CA para a equipe, CA criada agora)."""
    folder = cert_file.parent
    ca_cert, ca_key, created = ensure_ca(folder)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    san = [x509.DNSName(h) for h in hostnames] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=SERVER_DAYS))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    _write_private(key_file, _key_bytes(key))
    # cadeia: servidor + CA (o navegador monta a confiança a partir da CA instalada)
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM))
    return folder / "jervis-ca.cer", created


def certificate_info(cert_file: Path) -> tuple[datetime, list[str]] | None:
    """(validade, nomes) do certificado do servidor, ou None se não existir."""
    if not cert_file.is_file():
        return None
    cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(v) for v in san.get_values_for_type(x509.DNSName)] + [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    return cert.not_valid_after_utc, names
