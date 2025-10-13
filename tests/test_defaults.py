import importlib
from pathlib import Path


def test_defaults_disabled():
    cfg = importlib.import_module("config")
    assert cfg.ENABLE_COVER_TRAFFIC is False
    assert cfg.ENABLE_HTTP_MIMICRY is False
    assert cfg.ENABLE_ZW_STEGANO is False
    assert cfg.ENABLE_RATCHET is True
    assert not Path("data/local_config.cfg").exists()
