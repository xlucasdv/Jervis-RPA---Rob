"""Monta o cliente de API certo para um serviço cadastrado no banco."""

from __future__ import annotations

from jervis.api import credentials as api_credentials
from jervis.api.acronis import AcronisApi
from jervis.api.deskmanager import DeskManagerApi
from jervis.api.sophos import SophosApi
from jervis.api.zabbix import ZabbixApi
from jervis.credentials import CredentialStore
from jervis.db.repository import Service


def build(service: Service, store: CredentialStore):
    creds = api_credentials.load(store, service.slug, service.class_identifier)
    if service.class_identifier == "acronis":
        return AcronisApi(service.url, creds["client_id"], creds["client_secret"])
    if service.class_identifier == "sophos":
        return SophosApi(service.url, creds["client_id"], creds["client_secret"])
    if service.class_identifier == "zabbix":
        return ZabbixApi(service.url, creds["token"])
    if service.class_identifier == "deskmanager":
        return DeskManagerApi(service.url, creds["operator_key"], creds["environment_key"])
    raise AssertionError(service.class_identifier)  # fields_for já recusou classes sem API
