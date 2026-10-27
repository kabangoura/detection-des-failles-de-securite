"""Collecte : ports en écoute, interfaces, DNS, SMBv1, partages SMB, Bureau à distance (RDP)."""

from __future__ import annotations

from kmb_library.collectors.common import interfaces, listening_ports
from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, ps_json, read_reg

NAME = "network"
LABEL = "Réseau"

_TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"


def _smb1(errors: dict) -> bool | None:
    cfg = attempt(errors, "smb_config", lambda: ps_json(
        "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol"
    )[0])
    if cfg is not None:
        return bool(cfg.get("EnableSMB1Protocol"))
    # Repli : clé de registre explicite (absente = protocole non configuré)
    reg = attempt(errors, "smb1_registry", lambda: read_reg("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1"))
    return None if reg is None else bool(reg)


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    shares = attempt(errors, "smb_shares", lambda: ps_json(
        "Get-SmbShare | Select-Object Name,Path,Description,@{n='Special';e={$_.Special}}"
    ))
    dns = attempt(errors, "dns", lambda: ps_json(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses} | "
        "Select-Object InterfaceAlias,ServerAddresses"
    ))
    rdp_deny = attempt(errors, "rdp", lambda: read_reg("HKLM", _TS, "fDenyTSConnections"))
    rdp_tcp = attempt(errors, "rdp_nla", lambda: read_reg("HKLM", _TS + r"\WinStations\RDP-Tcp"), {}) or {}
    return {
        "listening": attempt(errors, "listening_ports", listening_ports),
        "interfaces": attempt(errors, "interfaces", interfaces),
        "dns_servers": [
            {"interface": d.get("InterfaceAlias"), "servers": d.get("ServerAddresses") or []} for d in dns
        ] if dns is not None else None,
        "smb1_enabled": _smb1(errors),
        "smb_shares": [
            {"name": s.get("Name"), "path": s.get("Path"), "description": s.get("Description"),
             "administrative": str(s.get("Name", "")).endswith("$")}
            for s in shares
        ] if shares is not None else None,
        "rdp": None if rdp_deny is None else {
            "enabled": rdp_deny == 0,
            "nla": rdp_tcp.get("UserAuthentication") == 1,
            "port": rdp_tcp.get("PortNumber"),
        },
        "_errors": errors,
    }
