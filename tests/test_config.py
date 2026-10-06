import pytest

from jervis.config import (
    AppConfig,
    PlatformConfig,
    Settings,
    init_config,
    load_config,
    parse_config,
    save_config,
)
from jervis.errors import ConfigError


def test_template_is_valid_and_all_platforms_start_disabled(tmp_path):
    path = init_config(tmp_path / "platforms.yaml")
    config = load_config(path)
    assert set(config.platforms) == {"sophos", "acronis", "zabbix"}
    assert config.enabled_platforms() == []
    assert config.platforms["sophos"].mfa == "totp"


def test_init_refuses_to_overwrite(tmp_path):
    path = init_config(tmp_path / "platforms.yaml")
    with pytest.raises(ConfigError, match="--force"):
        init_config(path)
    init_config(path, force=True)


def test_save_and_reload_roundtrip(tmp_path):
    config = AppConfig(
        settings=Settings(browser="chrome", headless=False),
        platforms={
            "zabbix_hml": PlatformConfig(
                name="zabbix_hml", kind="zabbix", url="https://zabbix-hml.local/index.php",
                enabled=True, environment="homologacao", login_timeout=45,
                selectors={"error": ["div.red"]}, params={"grupos": ["Servidores"]},
            )
        },
    )
    path = save_config(config, tmp_path / "out.yaml")
    loaded = load_config(path)
    assert loaded.settings.browser == "chrome"
    assert loaded.platforms["zabbix_hml"] == config.platforms["zabbix_hml"]


def test_kind_defaults_to_platform_name():
    config = parse_config({"platforms": {"zabbix": {"url": "https://z.local"}}})
    assert config.platforms["zabbix"].kind == "zabbix"


@pytest.mark.parametrize("key", ["password", "senha", "username", "token"])
def test_rejects_credentials_in_config(key):
    with pytest.raises(ConfigError, match="Credenciais não podem"):
        parse_config({"platforms": {"zabbix": {"url": "https://z.local", key: "x"}}})


@pytest.mark.parametrize(
    "platform, message",
    [
        ({"url": "zabbix.local"}, "URL inválida"),
        ({"url": "ftp://zabbix.local"}, "URL inválida"),
        ({"enabled": True}, "não tem URL"),
        ({"kind": "nagios", "url": "https://n.local"}, "não suportado"),
        ({"url": "https://z.local", "mfa": "sms"}, "mfa"),
        ({"url": "https://z.local", "selectors": {"botao": "#x"}}, "Seletor"),
        ({"url": "https://z.local", "urll": "x"}, "desconhecida"),
    ],
)
def test_validation_errors(platform, message):
    with pytest.raises(ConfigError, match=message):
        parse_config({"platforms": {"zabbix": platform}})


def test_missing_file_suggests_init(tmp_path):
    with pytest.raises(ConfigError, match="jervis init"):
        load_config(tmp_path / "nao-existe.yaml")


def test_unknown_platform_lists_available():
    config = parse_config({"platforms": {"zabbix": {"url": "https://z.local"}}})
    with pytest.raises(ConfigError, match="Cadastradas: zabbix"):
        config.get("sophos")
