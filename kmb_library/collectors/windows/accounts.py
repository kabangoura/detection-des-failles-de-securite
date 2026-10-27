"""Collecte : comptes locaux et membres du groupe Administrateurs."""

from __future__ import annotations

import getpass

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, ps_json


def _v(value):
    """PowerShell 5.1 sérialise parfois une valeur nulle en {} : on la ramène à None."""
    return None if value in ({}, "", None) else value

NAME = "accounts"
LABEL = "Comptes utilisateurs"


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    users = attempt(errors, "local_users", lambda: ps_json(
        "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,@{n='SID';e={$_.SID.Value}},"
        "@{n='LastLogon';e={if($_.LastLogon){$_.LastLogon.ToString('o')}}},"
        "@{n='PasswordLastSet';e={if($_.PasswordLastSet){$_.PasswordLastSet.ToString('o')}}}"
    ))
    # S-1-5-32-544 = groupe Administrateurs, quel que soit la langue de Windows
    admins = attempt(errors, "admin_group", lambda: ps_json(
        "Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object Name,ObjectClass,"
        "@{n='SID';e={$_.SID.Value}},@{n='Source';e={[string]$_.PrincipalSource}}"
    ))
    current = getpass.getuser().lower()
    return {
        "current_user": getpass.getuser(),
        "local_users": [
            {
                "name": u.get("Name"),
                "enabled": bool(u.get("Enabled")),
                "password_required": bool(u.get("PasswordRequired")),
                "sid": u.get("SID"),
                "last_logon": _v(u.get("LastLogon")),
                "password_last_set": _v(u.get("PasswordLastSet")),
            }
            for u in users
        ] if users is not None else None,
        "administrators": [
            {
                "name": a.get("Name"),
                "type": a.get("ObjectClass"),
                "sid": a.get("SID"),
                "source": a.get("Source"),
                "is_current_user": str(a.get("Name", "")).lower().split("\\")[-1] == current,
            }
            for a in admins
        ] if admins is not None else None,
        "_errors": errors,
    }
