#!/usr/bin/env python3
import getpass
import json
import subprocess
import time
from pathlib import Path

LOCAL_CFG = Path("data/local_config.cfg")
AUDIT = Path("data/audit.log")


def write_local_config(flags: dict) -> None:
    LOCAL_CFG.parent.mkdir(parents=True, exist_ok=True)
    with LOCAL_CFG.open("w", encoding="utf-8") as fh:
        json.dump(flags, fh)


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
    print("You are about to ENABLE optional addons for neccrit (cover traffic, mimicry, steganography).")
    print("These features are dual-use and MAY enable covert channels.")
    print("Type exactly: I understand and accept responsibility")
    ans = input("> ").strip()
    if ans != "I understand and accept responsibility":
        print("Confirmation failed. No changes made.")
        return 1
    flags = {
        "ENABLE_COVER_TRAFFIC": True,
        "ENABLE_HTTP_MIMICRY": True,
        "ENABLE_ZW_STEGANO": False,
    }
    write_local_config(flags)
    append_audit("enable_addons", flags)
    print("Add-ons enabled locally. See data/audit.log for an audit entry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
