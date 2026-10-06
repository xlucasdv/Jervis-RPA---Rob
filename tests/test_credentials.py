import pytest

from jervis.credentials import CredentialStore, env_prefix
from jervis.errors import CredentialError, CredentialsNotFoundError


def test_set_get_delete_keyring(memory_keyring):
    store = CredentialStore(environ={})
    store.set("zabbix", "operador", "S3nh@", totp_secret="JBSWY3DPEHPK3PXP")

    creds = store.get("zabbix")
    assert creds.username == "operador"
    assert creds.password.reveal() == "S3nh@"
    assert creds.totp_secret.reveal() == "JBSWY3DPEHPK3PXP"
    assert store.status("zabbix").source == "keyring"
    # Gravado no cofre, nunca em texto aberto em outro lugar.
    assert ("jervis3000", "zabbix:password") in memory_keyring.data

    assert store.delete("zabbix") is True
    assert store.delete("zabbix") is False
    assert not store.status("zabbix").configured


def test_updating_without_totp_removes_old_secret():
    store = CredentialStore(environ={})
    store.set("sophos", "op", "a", totp_secret="JBSWY3DPEHPK3PXP")
    store.set("sophos", "op", "b")
    assert store.get("sophos").totp_secret is None


def test_environment_takes_priority_over_keyring():
    env = {"JERVIS_ZABBIX_HML_USERNAME": "env-user", "JERVIS_ZABBIX_HML_PASSWORD": "env-pass"}
    store = CredentialStore(environ=env)
    store.set("zabbix_hml", "cofre-user", "cofre-pass")
    assert store.get("zabbix_hml").username == "env-user"
    assert store.status("zabbix_hml").source == "env"


def test_partial_environment_is_an_error():
    store = CredentialStore(environ={"JERVIS_ZABBIX_USERNAME": "u"})
    with pytest.raises(CredentialError, match="juntas"):
        store.get("zabbix")


def test_missing_credentials_explains_how_to_fix():
    with pytest.raises(CredentialsNotFoundError, match="jervis credentials set acronis"):
        CredentialStore(environ={}).get("acronis")


def test_env_prefix_normalizes_names():
    assert env_prefix("zabbix-hml.sp") == "JERVIS_ZABBIX_HML_SP_"
