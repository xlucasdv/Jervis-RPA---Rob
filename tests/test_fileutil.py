import os

import pytest

from jervis import fileutil


@pytest.mark.skipif(os.name != "nt", reason="tratamento específico do Windows")
def test_replace_retries_transient_access_denied(tmp_path, monkeypatch):
    src, dst = tmp_path / "novo.json", tmp_path / "atual.json"
    src.write_text("novo")
    real_replace, failures, sleeps = os.replace, [PermissionError(13, "Acesso negado")] * 2, []

    def flaky(a, b):
        if failures:
            raise failures.pop()
        real_replace(a, b)

    monkeypatch.setattr(fileutil.os, "replace", flaky)
    fileutil.replace(src, dst, sleep=sleeps.append)
    assert dst.read_text() == "novo" and len(sleeps) == 2


def test_replace_gives_up_on_persistent_lock(tmp_path, monkeypatch):
    def locked(a, b):
        raise PermissionError(13, "Acesso negado")

    monkeypatch.setattr(fileutil.os, "replace", locked)
    with pytest.raises(PermissionError):
        fileutil.replace(tmp_path / "a", tmp_path / "b", sleep=lambda s: None)
