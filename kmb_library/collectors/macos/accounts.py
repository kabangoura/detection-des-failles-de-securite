"""Collecte macOS : comptes locaux, groupe admin, compte invité, ouverture de session automatique."""

from __future__ import annotations

import getpass
import plistlib
from pathlib import Path

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, run_cmd

NAME = "accounts"
LABEL = "Comptes utilisateurs"

LOGINWINDOW = Path("/Library/Preferences/com.apple.loginwindow.plist")


def parse_dscl_uids(text: str) -> list[dict]:
    users = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("-").isdigit():
            name, uid = parts[0], int(parts[1])
            if uid >= 500 and not name.startswith("_"):
                users.append({"name": name, "uid": uid})
    return users


def parse_group_membership(text: str) -> list[str]:
    for line in text.splitlines():
        if line.startswith("GroupMembership:"):
            return line.split(":", 1)[1].split()
    return []


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    current = getpass.getuser()
    users = attempt(errors, "users", lambda: parse_dscl_uids(run_cmd(["dscl", ".", "-list", "/Users", "UniqueID"])))
    admins = attempt(errors, "admin_group", lambda: parse_group_membership(run_cmd(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])))
    prefs = attempt(errors, "loginwindow", lambda: plistlib.loads(LOGINWINDOW.read_bytes()) if LOGINWINDOW.exists() else {}, {}) or {}
    return {
        "current_user": current,
        "local_users": [{"name": u["name"], "uid": u["uid"], "enabled": True, "password_required": None} for u in users]
        if users is not None else None,
        "administrators": [{"name": n, "is_current_user": n == current} for n in admins if n != "root"] if admins is not None else None,
        "guest_enabled": bool(prefs.get("GuestEnabled", False)),
        "autologin_user": prefs.get("autoLoginUser"),
        "_errors": errors,
    }
