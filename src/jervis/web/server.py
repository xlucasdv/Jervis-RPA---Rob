"""Servidor HTTPS da interface (Cheroot, roda no Windows). Sempre com TLS 1.2 ou mais novo: sem HTTPS, o
login da Microsoft não volta e a sessão poderia ser lida na rede."""

from __future__ import annotations

import logging
import ssl
from pathlib import Path

from jervis.errors import ConfigError

log = logging.getLogger(__name__)


def serve(app, host: str, port: int, cert_file: str | Path, key_file: str | Path, threads: int = 12) -> None:
    from cheroot import wsgi
    from cheroot.ssl.builtin import BuiltinSSLAdapter

    cert_file, key_file = Path(cert_file), Path(key_file)
    if not cert_file.is_file() or not key_file.is_file():
        raise ConfigError(f"Certificado HTTPS não encontrado ({cert_file}). Crie com 'jervis web cert'.")
    adapter = BuiltinSSLAdapter(str(cert_file), str(key_file))
    adapter.context.minimum_version = ssl.TLSVersion.TLSv1_2
    server = wsgi.Server((host, port), app, numthreads=threads, server_name="jervis3000")
    server.ssl_adapter = adapter
    log.info("Interface web em https://%s:%s", host, port)
    try:
        server.start()  # bloqueia até Ctrl+C
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
