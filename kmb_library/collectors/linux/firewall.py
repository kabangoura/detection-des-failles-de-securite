"""Collecte Linux : pare-feu actif (ufw, firewalld, nftables) et politique par défaut."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import CommandError, attempt, is_admin, run_cmd

NAME = "firewall"
LABEL = "Pare-feu"


def parse_ufw_conf(conf: str, defaults: str) -> dict:
    enabled = bool(re.search(r"^\s*ENABLED\s*=\s*yes", conf, re.M | re.I))
    m = re.search(r'^\s*DEFAULT_INPUT_POLICY\s*=\s*"?(\w+)"?', defaults, re.M)
    policy = (m.group(1).upper() if m else "DROP")
    return {"name": "ufw", "enabled": enabled, "default_inbound": "Allow" if policy == "ACCEPT" else "Block"}


def parse_ufw_status(text: str) -> dict:
    """`ufw status verbose` (root) : 'Status: active' / 'Default: deny (incoming), allow (outgoing)'."""
    enabled = "status: active" in text.lower()
    m = re.search(r"Default:\s*(\w+)\s*\(incoming\)", text, re.I)
    inbound = "Allow" if m and m.group(1).lower() == "allow" else "Block"
    return {"name": "ufw", "enabled": enabled, "default_inbound": inbound}


def _systemd_active(unit: str) -> bool:
    return run_cmd(["systemctl", "is-active", unit], ok_codes=(0, 3, 4)).strip() == "active"


def detect() -> list[dict] | None:
    profiles = []
    if shutil.which("ufw") or Path("/etc/ufw/ufw.conf").exists():
        try:
            profiles.append(parse_ufw_status(run_cmd(["ufw", "status", "verbose"])) if is_admin() else
                            parse_ufw_conf(Path("/etc/ufw/ufw.conf").read_text(), Path("/etc/default/ufw").read_text()
                                           if Path("/etc/default/ufw").exists() else ""))
        except (CommandError, OSError):
            pass
    if shutil.which("firewall-cmd"):
        state = run_cmd(["firewall-cmd", "--state"], ok_codes=(0, 252)).strip()
        profiles.append({"name": "firewalld", "enabled": state == "running", "default_inbound": "Block"})
    if not any(p["enabled"] for p in profiles) and shutil.which("systemctl"):
        if _systemd_active("nftables"):
            profiles.append({"name": "nftables", "enabled": True, "default_inbound": None})
        elif is_admin() and shutil.which("nft"):
            rules = run_cmd(["nft", "list", "ruleset"])
            profiles.append({"name": "nftables", "enabled": "hook input" in rules, "default_inbound": "Block" if "policy drop" in rules else None})
    if not profiles:
        if not is_admin():
            return None  # des règles iptables/nft peuvent exister mais ne sont lisibles qu'en root
        profiles.append({"name": "Aucun pare-feu détecté", "enabled": False, "default_inbound": None})
    return profiles


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    profiles = attempt(errors, "profiles", detect)
    if profiles is None and "profiles" not in errors:
        errors["profiles"] = "Accès refusé : aucun outil de pare-feu lisible sans droits root (ufw/firewalld absents)"
    return {"profiles": profiles, "sensitive_inbound_rules": None, "_errors": errors}
