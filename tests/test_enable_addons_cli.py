import importlib
import json
from pathlib import Path


def _patch_paths(module, base: Path, monkeypatch):
    monkeypatch.setattr(module, "LOCAL_CFG", base / "data" / "local_config.cfg")
    monkeypatch.setattr(module, "AUDIT", base / "data" / "audit.log")


def test_enable_addons_creates_config_and_audit(monkeypatch, tmp_path):
    enable_addons = importlib.import_module("tools.enable_addons")
    _patch_paths(enable_addons, tmp_path, monkeypatch)
    monkeypatch.setattr("builtins.input", lambda prompt="": "I understand and accept responsibility")
    rc = enable_addons.main()
    assert rc == 0
    local_cfg = enable_addons.LOCAL_CFG
    audit_log = enable_addons.AUDIT
    data = json.loads(local_cfg.read_text(encoding="utf-8"))
    assert data == {
        "ENABLE_COVER_TRAFFIC": True,
        "ENABLE_HTTP_MIMICRY": True,
        "ENABLE_ZW_STEGANO": False,
    }
    entries = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert entries
    assert entries[-1]["action"] == "enable_addons"


def test_enable_stegano_requires_addons(monkeypatch, tmp_path, capsys):
    enable_addons = importlib.import_module("tools.enable_addons")
    enable_stegano = importlib.import_module("tools.enable_stegano")
    _patch_paths(enable_addons, tmp_path, monkeypatch)
    _patch_paths(enable_stegano, tmp_path, monkeypatch)

    # Without enabling addons first
    monkeypatch.setattr("builtins.input", lambda prompt="": "ENABLE STEGANO")
    rc = enable_stegano.main()
    captured = capsys.readouterr()
    assert rc == 2
    assert "Run tools/enable_addons.py first" in captured.out

    # Enable addons then enable stegano with confirmation typo
    monkeypatch.setattr("builtins.input", lambda prompt="": "I understand and accept responsibility")
    assert enable_addons.main() == 0

    monkeypatch.setattr("builtins.input", lambda prompt="": "WRONG")
    rc = enable_stegano.main()
    assert rc == 1

    # Proper confirmation enables steganography
    monkeypatch.setattr("builtins.input", lambda prompt="": "ENABLE STEGANO")
    rc = enable_stegano.main()
    assert rc == 0
    cfg = json.loads(enable_stegano.LOCAL_CFG.read_text(encoding="utf-8"))
    assert cfg["ENABLE_ZW_STEGANO"] is True
    entries = [json.loads(line) for line in enable_stegano.AUDIT.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert entries[-1]["action"] == "enable_stegano"
