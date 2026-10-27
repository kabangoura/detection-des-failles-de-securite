"""Collecte : profils du pare-feu Windows et règles entrantes sensibles."""

from __future__ import annotations

import re

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, ps_json, run_cmd

NAME = "firewall"
LABEL = "Pare-feu"

# Ports dont l'ouverture entrante sur le profil Public mérite une alerte
SENSITIVE_PORTS = ["21", "23", "135", "139", "445", "3389", "5900", "5985", "5986", "1433", "3306", "5432"]

_RULES = (
    "$ports=@('" + "','".join(SENSITIVE_PORTS) + "'); "
    "$rules=Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | "
    "Where-Object { $_.Profile -match 'Public|Any' }; "
    "$idx=@{}; foreach($r in $rules){ $idx[$r.Name]=$r }; "
    "$rules | Get-NetFirewallPortFilter | Where-Object { $_.Protocol -eq 'TCP' -and "
    "(@($_.LocalPort) | Where-Object { $ports -contains $_ }) } | ForEach-Object { "
    "$r=$idx[$_.InstanceID]; [pscustomobject]@{ Name=$r.DisplayName; Profile=[string]$r.Profile; "
    "Ports=(@($_.LocalPort) -join ',') } }"
)


def _profiles_netsh() -> list[dict]:
    """Repli si Get-NetFirewallProfile échoue : sortie de netsh (FR ou EN)."""
    out = run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
    names = ["Domain", "Private", "Public"]
    states = re.findall(r"(?:État|Etat|State)\s+(\S+)", out, flags=re.IGNORECASE)
    return [
        {"name": n, "enabled": s.upper() in ("ON", "ACTIVÉ", "ACTIVE", "ACTIVER"), "default_inbound": None}
        for n, s in zip(names, states)
    ]


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    raw = attempt(errors, "profiles", lambda: ps_json(
        "Get-NetFirewallProfile | Select-Object Name,@{n='Enabled';e={[string]$_.Enabled}},"
        "@{n='DefaultInboundAction';e={[string]$_.DefaultInboundAction}}"
    ))
    if raw is not None:
        profiles = [
            {
                "name": p.get("Name"),
                # NotConfigured = valeur par défaut de Windows, soit activé
                "enabled": p.get("Enabled") in ("True", "NotConfigured"),
                "default_inbound": p.get("DefaultInboundAction"),
            }
            for p in raw
        ]
    else:
        profiles = attempt(errors, "profiles_netsh", _profiles_netsh)

    rules = attempt(errors, "sensitive_rules", lambda: ps_json(_RULES, timeout=120))
    return {
        "profiles": profiles,
        "sensitive_inbound_rules": [
            {"name": r.get("Name"), "profile": r.get("Profile"), "ports": r.get("Ports")} for r in rules
        ] if rules is not None else None,
        "_errors": errors,
    }
