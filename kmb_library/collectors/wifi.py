"""Collecte Wi-Fi (Windows, Linux, macOS) : sécurité du réseau connecté et des réseaux mémorisés.

Windows : netsh (sortie en français ou en anglais) ; Linux : nmcli ; macOS : system_profiler.
"""

from __future__ import annotations

import json
import re
import shutil
import sys

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, run_cmd

NAME = "wifi"
LABEL = "Wi-Fi"
MAX_PROFILES = 25


def classify(auth: str | None, cipher: str | None = None) -> str:
    """Ramène les libellés de chaque système à : ouvert, wep, wpa, wpa2, wpa3, entreprise, inconnu."""
    a = (auth or "").lower().replace(" ", "").replace("-", "").replace("_", "")
    c = (cipher or "").lower()
    if not a:
        return "inconnu"
    if a in ("open", "ouvert", "ouverte", "ouvrir", "aucune", "none", "--"):
        return "ouvert"
    if "wpa3" in a or "sae" in a or "owe" in a:
        return "wpa3"
    if "eap" in a or "entreprise" in a or "enterprise" in a or "8021x" in a:
        return "entreprise"
    if "wpa2" in a or "rsna" in a:
        return "wpa" if "tkip" in c else "wpa2"
    if "wep" in a:
        return "wep"
    if "wpa" in a:
        return "wpa"
    return "inconnu"


# --------------------------------------------------------------------------- Windows

_KV = re.compile(r"^\s*([^:]+?)\s*:\s*(.*)$")


def parse_netsh_interfaces(text: str) -> dict | None:
    info: dict[str, str] = {}
    for line in text.splitlines():
        m = _KV.match(line)
        if not m:
            continue
        key, value = m.group(1).strip().lower(), m.group(2).replace("\u00a0", " ").strip()
        if key == "ssid":
            info["ssid"] = value
        elif key in ("authentification", "authentication"):
            info.setdefault("auth", value)
        elif key in ("chiffrement", "cipher"):
            info.setdefault("cipher", value)
        elif key in ("état", "etat", "state"):
            info["state"] = value.lower()
    if not info.get("ssid") or not info.get("state", "").startswith(("connect", "connecté")):
        return None
    return {"ssid": info["ssid"], "auth": info.get("auth"), "cipher": info.get("cipher"),
            "security": classify(info.get("auth"), info.get("cipher"))}


def parse_netsh_profiles(text: str) -> list[str]:
    names = []
    for line in text.splitlines():
        m = re.match(r"\s*(?:Profil Tous les utilisateurs|All User Profile|Profil utilisateur actuel|Current User Profile)\s*:\s*(.+)$", line)
        if m:
            names.append(m.group(1).strip())
    return names


def parse_netsh_profile(name: str, text: str) -> dict:
    auth = cipher = mode = None
    for line in text.splitlines():
        m = _KV.match(line)
        if not m:
            continue
        key, value = m.group(1).strip().lower(), m.group(2).replace("\u00a0", " ").strip()
        if key in ("authentification", "authentication") and auth is None:
            auth = value
        elif key in ("chiffrement", "cipher") and cipher is None:
            cipher = value
        elif key in ("mode de connexion", "connection mode") and mode is None:
            mode = value.lower()
    return {"name": name, "auth": auth, "security": classify(auth, cipher),
            "autoconnect": bool(mode and ("auto" in mode))}


def _windows() -> dict:
    try:
        ifaces = run_cmd(["netsh", "wlan", "show", "interfaces"])
    except Exception as exc:  # noqa: BLE001
        if "wlansvc" in str(exc).lower() or "n'est pas en cours" in str(exc).lower() or "not running" in str(exc).lower():
            return {"available": False}
        raise
    if not re.search(r"SSID|interface", ifaces, re.I) or re.search(r"(Il n'existe aucune|There is no) .*interface", ifaces, re.I):
        return {"available": False}
    profiles = []
    for name in parse_netsh_profiles(run_cmd(["netsh", "wlan", "show", "profiles"]))[:MAX_PROFILES]:
        try:
            profiles.append(parse_netsh_profile(name, run_cmd(["netsh", "wlan", "show", "profile", f"name={name}"])))
        except Exception:  # noqa: BLE001 - un profil illisible n'empêche pas les autres
            profiles.append({"name": name, "auth": None, "security": "inconnu", "autoconnect": None})
    return {"available": True, "current": parse_netsh_interfaces(ifaces), "profiles": profiles}


# --------------------------------------------------------------------------- Linux

def split_nmcli(line: str) -> list[str]:
    """nmcli -t échappe les ':' contenus dans les valeurs par '\\:'."""
    return [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]


def parse_nmcli_wifi(text: str) -> dict | None:
    for line in text.splitlines():
        parts = split_nmcli(line)
        if len(parts) >= 3 and parts[0] == "yes":
            sec = parts[2] or "open"
            return {"ssid": parts[1], "auth": sec, "cipher": None, "security": classify(sec)}
    return None


def nm_keymgmt_to_auth(key_mgmt: str) -> str:
    return {"": "open", "none": "WEP", "wpa-psk": "WPA2-PSK", "sae": "WPA3-SAE", "wpa-eap": "WPA-EAP",
            "owe": "OWE", "ieee8021x": "802.1X"}.get(key_mgmt.strip().lower(), key_mgmt)


def _linux() -> dict:
    if not shutil.which("nmcli"):
        return {"available": False, "reason": "NetworkManager (nmcli) absent"}
    current = parse_nmcli_wifi(run_cmd(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"], ok_codes=(0, 10)))
    profiles = []
    for line in run_cmd(["nmcli", "-t", "-f", "NAME,TYPE", "con", "show"]).splitlines()[:200]:
        parts = split_nmcli(line)
        if len(parts) >= 2 and parts[1] == "802-11-wireless" and len(profiles) < MAX_PROFILES:
            out = run_cmd(["nmcli", "-g", "802-11-wireless-security.key-mgmt,connection.autoconnect", "con", "show", parts[0]], ok_codes=(0, 10))
            vals = out.splitlines() + ["", ""]
            auth = nm_keymgmt_to_auth(vals[0])
            profiles.append({"name": parts[0], "auth": auth, "security": classify(auth), "autoconnect": vals[1].strip() == "yes"})
    has_wifi = "wifi" in run_cmd(["nmcli", "-t", "-f", "TYPE", "dev"]).lower()
    return {"available": has_wifi or bool(profiles), "current": current, "profiles": profiles}


# --------------------------------------------------------------------------- macOS

def parse_airport_json(doc: dict) -> dict | None:
    for entry in doc.get("SPAirPortDataType", []):
        for iface in entry.get("spairport_airport_interfaces", []):
            cur = iface.get("spairport_current_network_information")
            if cur:
                mode = str(cur.get("spairport_security_mode", ""))
                label = mode.replace("spairport_security_mode_", "").replace("_", " ").upper() or None
                return {"ssid": cur.get("_name"), "auth": label, "cipher": None, "security": classify(mode.replace("spairport_security_mode_", ""))}
    return None


def _macos() -> dict:
    doc = json.loads(run_cmd(["system_profiler", "SPAirPortDataType", "-json"], timeout=60))
    current = parse_airport_json(doc)
    names = []
    out = attempt({}, "preferred", lambda: run_cmd(["networksetup", "-listpreferredwirelessnetworks", "en0"]), "") or ""
    for line in out.splitlines()[1:MAX_PROFILES + 1]:
        if line.strip():
            names.append({"name": line.strip(), "auth": None, "security": "inconnu", "autoconnect": True})
    return {"available": bool(doc.get("SPAirPortDataType")), "current": current, "profiles": names}


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    fn = {"win32": _windows, "darwin": _macos}.get(sys.platform, _linux)
    data = attempt(errors, "wifi", fn) or {"available": None}
    data["_errors"] = errors
    return data
