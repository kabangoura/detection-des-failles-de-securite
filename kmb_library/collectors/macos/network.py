"""Collecte macOS : ports en écoute, session à distance (SSH), partage d'écran et de fichiers, DNS."""

from __future__ import annotations

import re

from kmb_library.collectors.common import interfaces, listening_ports
from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, run_cmd

NAME = "network"
LABEL = "Réseau"


def parse_scutil_dns(text: str) -> list[str]:
    servers = []
    for m in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", text):
        if m.group(1) not in servers:
            servers.append(m.group(1))
    return servers


def _remote_login() -> bool:
    out = run_cmd(["launchctl", "print-disabled", "system"], ok_codes=(0, 1))
    m = re.search(r'"com\.openssh\.sshd"\s*=>\s*(\w+)', out)
    # Session à distance active si le service n'est pas marqué désactivé
    return bool(m) and m.group(1) in ("enabled", "false")


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    listening = attempt(errors, "listening_ports", listening_ports)
    ports = {p["port"] for p in listening or [] if p["exposed"]}
    ssh_on = attempt(errors, "remote_login", _remote_login)
    dns = attempt(errors, "dns", lambda: parse_scutil_dns(run_cmd(["scutil", "--dns"])), [])
    return {
        "listening": listening,
        "interfaces": attempt(errors, "interfaces", interfaces),
        "dns_servers": [{"interface": "scutil", "servers": dns or []}],
        "ssh": {"installed": True, "running": bool(ssh_on) or 22 in ports, "permit_root_login": None,
                "password_authentication": None, "port": 22},
        "sharing": {"screen_sharing": 5900 in ports, "file_sharing": 445 in ports},
        "smb_shares": None,  # la liste des partages (`sharing -l`) exige les droits administrateur
        "_errors": errors,
    }
