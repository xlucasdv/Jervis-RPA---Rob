"""Coletores de dados por tipo de plataforma."""

from __future__ import annotations

from jervis.collectors.acronis import AcronisCollector
from jervis.collectors.base import Collector
from jervis.collectors.sophos import SophosCollector
from jervis.collectors.zabbix import ZabbixCollector
from jervis.config import PlatformConfig, Settings
from jervis.errors import ConfigError

COLLECTORS: dict[str, type[Collector]] = {
    SophosCollector.kind: SophosCollector,
    AcronisCollector.kind: AcronisCollector,
    ZabbixCollector.kind: ZabbixCollector,
}


def build_collector(platform: PlatformConfig, settings: Settings) -> Collector:
    try:
        collector_cls = COLLECTORS[platform.kind]
    except KeyError:
        raise ConfigError(f"Coleta ainda não disponível para plataformas do tipo '{platform.kind}'.") from None
    return collector_cls(platform, settings)
