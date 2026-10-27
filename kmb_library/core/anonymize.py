"""Anonymisation d'un rapport avant partage (remise du cours, envoi à l'IA).

Remplace : nom de la machine, noms des comptes locaux, identifiants SID, adresses IP
(on garde les deux premiers octets pour rester interprétable), chemins du profil utilisateur.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b")
_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+")
_KEEP_IPS = {"0.0.0.0", "127.0.0.1"}


def _ip(m: re.Match) -> str:
    return m.group(0) if m.group(0) in _KEEP_IPS else f"{m.group(1)}.{m.group(2)}.x.x"


def build_replacements(hostname: str | None, users: list[str], networks: list[str] | None = None) -> list[tuple[re.Pattern, str]]:
    reps: list[tuple[re.Pattern, str]] = []
    for i, ssid in enumerate(sorted({n for n in networks or [] if n and len(n) >= 2}, key=len, reverse=True), start=1):
        reps.append((re.compile(rf"(?<![\w]){re.escape(ssid)}(?![\w])"), f"reseau-wifi-{i}"))
    if hostname:
        alias = "PC-" + hashlib.sha256(hostname.encode()).hexdigest()[:6].upper()
        reps.append((re.compile(re.escape(hostname), re.I), alias))
    builtin = {"administrateur", "administrator", "invité", "guest", "defaultaccount", "wdagutilityaccount"}
    n = 0
    for u in sorted({u for u in users if u}, key=len, reverse=True):
        if u.lower() in builtin or len(u) < 3:
            continue
        n += 1
        reps.append((re.compile(rf"(?<![\w]){re.escape(u)}(?![\w])", re.I), f"utilisateur{n}"))
    return reps


def _walk(obj: Any, reps) -> Any:
    if isinstance(obj, str):
        s = _SID.sub("S-1-5-21-xxx", obj)
        s = _IPV4.sub(_ip, s)
        for pat, rep in reps:
            s = pat.sub(rep, s)
        return s
    if isinstance(obj, list):
        return [_walk(x, reps) for x in obj]
    if isinstance(obj, dict):
        return {k: _walk(v, reps) for k, v in obj.items()}
    return obj


def anonymize(data: dict, hostname: str | None, users: list[str], networks: list[str] | None = None) -> dict:
    return _walk(data, build_replacements(hostname, users, networks))


def identities_from_raw(raw: dict) -> tuple[str | None, list[str], list[str]]:
    """Retourne (nom de machine, noms de comptes, noms de réseaux Wi-Fi) à masquer."""
    coll = raw.get("collectors", {})
    sysd = (coll.get("system") or {}).get("data") or {}
    acc = (coll.get("accounts") or {}).get("data") or {}
    wifi = (coll.get("wifi") or {}).get("data") or {}
    users = [u.get("name") for u in acc.get("local_users") or []]
    users.append(sysd.get("user"))
    users += [str(a.get("name", "")).split("\\")[-1] for a in acc.get("administrators") or []]
    nets = [p.get("name") for p in wifi.get("profiles") or []] + [(wifi.get("current") or {}).get("ssid")]
    return sysd.get("hostname"), [u for u in users if u and u != "root"], [n for n in nets if n]
