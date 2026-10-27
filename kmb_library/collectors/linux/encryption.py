"""Collecte Linux : chiffrement LUKS des volumes montés (/ et /home), via lsblk."""

from __future__ import annotations

import json

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, run_cmd

NAME = "encryption"
LABEL = "Chiffrement"
WATCHED = ("/", "/home")


def _mounts(node: dict) -> list[str]:
    mp = node.get("mountpoints") or ([node["mountpoint"]] if node.get("mountpoint") else [])
    return [m for m in mp if m]


def parse_lsblk(doc: dict) -> list[dict]:
    """Un volume est chiffré si un de ses ancêtres est de type 'crypt' ou de format 'crypto_LUKS'."""
    found: dict[str, dict] = {}

    def walk(node: dict, encrypted: bool, chain: list[str]):
        enc = encrypted or node.get("type") == "crypt" or node.get("fstype") == "crypto_LUKS"
        here = chain + [node.get("name", "?")]
        for m in _mounts(node):
            if m in WATCHED:
                found[m] = {"drive": m, "state": "on" if enc else "off", "label": "LUKS" if enc else "Non chiffré",
                            "method": "lsblk", "device": " > ".join(here)}
        for child in node.get("children") or []:
            walk(child, enc, here)

    for dev in doc.get("blockdevices", []):
        walk(dev, False, [])
    return [found[m] for m in WATCHED if m in found]


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    doc = attempt(errors, "lsblk", lambda: json.loads(run_cmd(["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"])))
    return {"volumes": parse_lsblk(doc) if doc else None, "system_drive": "/", "_errors": errors}
