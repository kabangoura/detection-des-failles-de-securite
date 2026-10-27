"""Collecte Linux : comptes (/etc/passwd), groupes d'administration (sudo, wheel), mots de passe vides (/etc/shadow si root)."""

from __future__ import annotations

import getpass
from pathlib import Path

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt

NAME = "accounts"
LABEL = "Comptes utilisateurs"

ADMIN_GROUPS = ("sudo", "wheel", "admin")
NOLOGIN = ("nologin", "false", "sync", "halt", "shutdown")


def parse_passwd(text: str) -> list[dict]:
    users = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 7 or line.startswith("#"):
            continue
        users.append({"name": parts[0], "uid": int(parts[2]), "gid": int(parts[3]), "home": parts[5], "shell": parts[6]})
    return users


def parse_group(text: str) -> dict[str, dict]:
    groups = {}
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            groups[parts[0]] = {"gid": int(parts[2]) if parts[2].isdigit() else None,
                                "members": [m for m in parts[3].split(",") if m]}
    return groups


def parse_shadow(text: str) -> dict[str, str]:
    return {p[0]: p[1] for p in (line.split(":") for line in text.splitlines()) if len(p) > 1}


def analyse(passwd: str, group: str, shadow: str | None, current: str) -> dict:
    users = parse_passwd(passwd)
    groups = parse_group(group)
    hashes = parse_shadow(shadow) if shadow is not None else None
    interactive = [u for u in users if not u["shell"].rsplit("/", 1)[-1] in NOLOGIN]
    human = [u for u in interactive if u["uid"] == 0 or 1000 <= u["uid"] < 65534]

    admin_names: set[str] = set()
    for g in ADMIN_GROUPS:
        if g in groups:
            admin_names.update(groups[g]["members"])
            admin_names.update(u["name"] for u in users if u["gid"] == groups[g]["gid"])

    def locked(name: str) -> bool | None:
        if hashes is None or name not in hashes:
            return None
        return hashes[name].startswith(("!", "*")) or hashes[name] == ""

    return {
        "current_user": current,
        "local_users": [
            {"name": u["name"], "uid": u["uid"], "shell": u["shell"],
             "enabled": not bool(locked(u["name"])) if hashes is not None else True,
             "password_required": None if hashes is None else hashes.get(u["name"], "x") != ""}
            for u in human
        ],
        "uid0_accounts": [u["name"] for u in users if u["uid"] == 0 and u["name"] != "root"],
        "root_password_locked": locked("root"),
        "shadow_readable": hashes is not None,
        "administrators": [{"name": n, "is_current_user": n == current} for n in sorted(admin_names)],
    }


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    passwd = attempt(errors, "passwd", lambda: Path("/etc/passwd").read_text(encoding="utf-8", errors="replace"), "")
    group = attempt(errors, "group", lambda: Path("/etc/group").read_text(encoding="utf-8", errors="replace"), "")
    shadow = attempt(errors, "shadow", lambda: Path("/etc/shadow").read_text(encoding="utf-8", errors="replace"))
    if shadow is None:
        errors["shadow"] = "Accès refusé à /etc/shadow (droits root requis)"
    data = analyse(passwd or "", group or "", shadow, getpass.getuser())
    data["_errors"] = errors
    return data
