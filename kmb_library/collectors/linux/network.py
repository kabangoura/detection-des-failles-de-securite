"""Collecte Linux : ports en écoute, serveur SSH, partages NFS et Samba, serveurs DNS."""

from __future__ import annotations

import re
from pathlib import Path

from kmb_library.collectors.common import interfaces, listening_ports
from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt

NAME = "network"
LABEL = "Réseau"


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def parse_sshd_config(texts: list[str]) -> dict:
    """Première valeur rencontrée = valeur effective (règle d'OpenSSH). Les blocs Match sont ignorés."""
    found: dict[str, str] = {}
    for text in texts:
        in_match = False
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            key, _, value = line.partition(" ")
            key = key.lower()
            if key == "match":
                in_match = True
            if in_match:
                continue
            found.setdefault(key, value.strip().split()[0] if value.strip() else "")
    return {
        "permit_root_login": found.get("permitrootlogin", "prohibit-password"),  # défaut OpenSSH >= 7.0
        "password_authentication": found.get("passwordauthentication", "yes").lower() == "yes",
        "port": int(found["port"]) if found.get("port", "").isdigit() else 22,
    }


def parse_exports(text: str) -> list[dict]:
    shares = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            path, *clients = line.split()
            shares.append({"name": path, "path": path, "type": "nfs", "clients": " ".join(clients) or "*",
                           "administrative": False})
    return shares


def parse_smb_conf(text: str) -> list[dict]:
    shares, current = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        m = re.match(r"\[(.+)\]", line)
        if m:
            name = m.group(1).strip()
            current = None if name.lower() in ("global", "printers", "print$") else {"name": name, "path": None, "type": "smb",
                                                                                     "administrative": False, "guest_ok": False}
            if current:
                shares.append(current)
            continue
        if current and "=" in line:
            k, v = (x.strip().lower() for x in line.split("=", 1))
            if k == "path":
                current["path"] = line.split("=", 1)[1].strip()
            if k in ("guest ok", "public") and v in ("yes", "true", "1"):
                current["guest_ok"] = True
    return shares


def parse_resolv_conf(text: str) -> list[str]:
    return [line.split()[1] for line in text.splitlines() if line.strip().startswith("nameserver") and len(line.split()) > 1]


def _ssh_files() -> list[str]:
    files = sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf")) if Path("/etc/ssh/sshd_config.d").is_dir() else []
    return [_read(str(f)) for f in files] + [_read("/etc/ssh/sshd_config")]


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    listening = attempt(errors, "listening_ports", listening_ports)
    ssh = None
    if Path("/etc/ssh/sshd_config").exists():
        ssh = attempt(errors, "sshd_config", lambda: parse_sshd_config(_ssh_files()))
        if ssh is not None:
            ssh["installed"] = True
            ssh["running"] = any(p["port"] == ssh["port"] for p in listening or []) if listening is not None else None
    shares: list[dict] = []
    if Path("/etc/exports").exists():
        shares += attempt(errors, "nfs_exports", lambda: parse_exports(_read("/etc/exports")), []) or []
    if Path("/etc/samba/smb.conf").exists():
        shares += attempt(errors, "samba", lambda: parse_smb_conf(_read("/etc/samba/smb.conf")), []) or []
    dns = attempt(errors, "dns", lambda: parse_resolv_conf(_read("/etc/resolv.conf")), [])
    return {
        "listening": listening,
        "interfaces": attempt(errors, "interfaces", interfaces),
        "dns_servers": [{"interface": "resolv.conf", "servers": dns or []}],
        "ssh": ssh or {"installed": False, "running": False},
        "smb_shares": shares,
        "_errors": errors,
    }
