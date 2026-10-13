"""Credenciais de API de cada serviço, no cofre do sistema (ou em variáveis de ambiente).

Chaves no cofre: ``api:<slug>:<campo>``; variáveis: ``JERVIS_API_<SLUG>_<CAMPO>`` (têm prioridade).
Os campos dependem da classe do serviço.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Mapping

from jervis.credentials import CredentialStore
from jervis.errors import CredentialError
from jervis.security import SecretStr


@dataclass(frozen=True)
class Field:
    name: str
    label: str
    secret: bool = True


API_FIELDS: dict[str, tuple[Field, ...]] = {
    "acronis": (Field("client_id", "Client ID do cliente de API", secret=False), Field("client_secret", "Client secret")),
    "sophos": (Field("client_id", "Client ID da credencial de API do Sophos Central", secret=False), Field("client_secret", "Client secret")),
    "zabbix": (Field("token", "Token de API do Zabbix"),),
    "deskmanager": (Field("operator_key", "Chave de API do Operador"), Field("environment_key", "Chave de API do Ambiente")),
}
API_CLASSES = frozenset(API_FIELDS)


def _vault_key(slug: str, field: str) -> str:
    return f"api:{slug}:{field}"


def env_name(slug: str, field: str) -> str:
    return "JERVIS_API_" + re.sub(r"[^A-Z0-9]", "_", f"{slug}_{field}".upper())


def fields_for(class_identifier: str) -> tuple[Field, ...]:
    try:
        return API_FIELDS[class_identifier]
    except KeyError:
        raise CredentialError(f"A classe '{class_identifier}' não tem acesso por API. "
                              f"Classes com API: {', '.join(sorted(API_FIELDS))}.") from None


def save(store: CredentialStore, slug: str, class_identifier: str, values: dict[str, str]) -> None:
    for field in fields_for(class_identifier):
        store.set_secret(_vault_key(slug, field.name), values[field.name])


def load(store: CredentialStore, slug: str, class_identifier: str,
         environ: Mapping[str, str] | None = None) -> dict[str, SecretStr]:
    environ = os.environ if environ is None else environ
    values, missing = {}, []
    for field in fields_for(class_identifier):
        value = environ.get(env_name(slug, field.name)) or store.get_secret(_vault_key(slug, field.name))
        if value:
            values[field.name] = SecretStr(value)
        else:
            missing.append(field.label)
    if missing:
        raise CredentialError(f"Credenciais de API de '{slug}' incompletas (falta: {', '.join(missing)}). "
                              f"Use 'jervis services set-api-credentials {slug}'.")
    return values


def configured(store: CredentialStore, slug: str, class_identifier: str, environ: Mapping[str, str] | None = None) -> bool:
    try:
        load(store, slug, class_identifier, environ)
        return True
    except CredentialError:
        return False


def delete(store: CredentialStore, slug: str, class_identifier: str) -> None:
    for field in fields_for(class_identifier):
        store.delete_secret(_vault_key(slug, field.name))
