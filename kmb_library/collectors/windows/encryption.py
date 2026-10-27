"""Collecte : chiffrement BitLocker des volumes fixes."""

from __future__ import annotations

import psutil

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, ps_json, run_ps

NAME = "encryption"
LABEL = "Chiffrement"

# Valeurs de la propriété Shell System.Volume.BitLockerProtection (lisible sans droits admin)
SHELL_STATES = {
    1: ("on", "Activé"),
    2: ("off", "Désactivé"),
    3: ("in_progress", "Chiffrement en cours"),
    4: ("in_progress", "Déchiffrement en cours"),
    5: ("suspended", "Suspendu"),
    6: ("on", "Activé (verrouillé)"),
}


def _fixed_drives() -> list[str]:
    return [p.device.rstrip("\\") for p in psutil.disk_partitions(all=False) if "fixed" in p.opts]


def _via_shell(drive: str) -> dict:
    out = run_ps(
        f"(New-Object -ComObject Shell.Application).NameSpace('{drive}\\').Self.ExtendedProperty('System.Volume.BitLockerProtection')"
    ).strip()
    code = int(out) if out.isdigit() else None
    state, label = SHELL_STATES.get(code, ("unsupported", "Non compatible ou inconnu"))
    return {"drive": drive, "state": state, "label": label, "method": "shell"}


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    volumes = attempt(errors, "bitlocker_admin", lambda: ps_json(
        "Get-BitLockerVolume | Select-Object MountPoint,@{n='Protection';e={[string]$_.ProtectionStatus}},"
        "@{n='Status';e={[string]$_.VolumeStatus}},EncryptionPercentage"
    ))
    result: list[dict] = []
    if volumes is not None:
        for v in volumes:
            on = v.get("Protection") == "On"
            result.append({
                "drive": v.get("MountPoint"),
                "state": "on" if on else ("in_progress" if "Progress" in str(v.get("Status")) else "off"),
                "label": f"{v.get('Protection')} / {v.get('Status')}",
                "percent": v.get("EncryptionPercentage"),
                "method": "Get-BitLockerVolume",
            })
    else:
        # Sans droits admin : lecture via l'explorateur Windows
        errors.pop("bitlocker_admin", None)
        for drive in attempt(errors, "drives", _fixed_drives, []) or []:
            r = attempt(errors, f"bitlocker_{drive}", lambda d=drive: _via_shell(d))
            if r:
                result.append(r)
    return {"volumes": result, "system_drive": "C:", "_errors": errors}
