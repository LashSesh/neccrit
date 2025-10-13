#!/usr/bin/env python3
import getpass
import json
import subprocess
import time
from pathlib import Path

LOCAL_CFG = Path("data/local_config.cfg")
AUDIT = Path("data/audit.log")


def get_git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def append_audit(action: str, details: dict) -> None:
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": int(time.time()),
        "user": getpass.getuser(),
        "commit": get_git_commit(),
        "action": action,
        "details": details,
    }
    with AUDIT.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main() -> int:
    if not LOCAL_CFG.exists():
        print("Add-ons not enabled. Run tools/enable_addons.py first.")
        return 2
    cfg = json.loads(LOCAL_CFG.read_text(encoding="utf-8"))
    if not cfg.get("ENABLE_COVER_TRAFFIC"):
        print("Cover traffic not enabled. Run tools/enable_addons.py first.")
        return 2
    print("Enabling ZERO-WIDTH steganography requires explicit consent.")
    print("Type exactly: ENABLE STEGANO")
    ans = input("> ").strip()
    if ans != "ENABLE STEGANO":
        print("Confirmation failed.")
        return 1
    cfg["ENABLE_ZW_STEGANO"] = True
    LOCAL_CFG.write_text(json.dumps(cfg), encoding="utf-8")
    append_audit("enable_stegano", {"ENABLE_ZW_STEGANO": True})
    print("Steganography enabled locally.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
