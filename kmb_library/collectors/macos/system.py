"""Collecte macOS : version, mises à jour en attente, SIP, Gatekeeper, mises à jour automatiques."""

from __future__ import annotations

import getpass
import platform
import plistlib
import re
from datetime import datetime
from pathlib import Path

import psutil

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, is_admin, run_cmd

NAME = "system"
LABEL = "Système et mises à jour"

SU_PLIST = Path("/Library/Preferences/com.apple.SoftwareUpdate.plist")


def parse_sw_vers(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def parse_softwareupdate(text: str) -> list[dict]:
    """`softwareupdate -l` : '* Label: macOS Sonoma 14.6.1-23G93' puis 'Title: ..., Version: ..., Recommended: YES, Action: restart,'."""
    updates, current = [], None
    for line in text.splitlines():
        m = re.match(r"\s*\*\s*Label:\s*(.+)", line)
        if m:
            current = {"title": m.group(1).strip(), "severity": None, "security": None}
            updates.append(current)
            continue
        if current and "Title:" in line:
            t = re.search(r"Title:\s*([^,]+)", line)
            if t:
                current["title"] = t.group(1).strip()
            current["security"] = "security" in line.lower() or "macos" in current["title"].lower()
            if "Recommended: YES" in line:
                current["severity"] = "Important"
    return updates


def parse_auto_update(prefs: dict) -> dict:
    """Clés absentes = valeur par défaut d'Apple (activée)."""
    return {
        "automatic_check": bool(prefs.get("AutomaticCheckEnabled", True)),
        "automatic_download": bool(prefs.get("AutomaticDownload", True)),
        "critical_updates": bool(prefs.get("CriticalUpdateInstall", True)),
        "install_macos": bool(prefs.get("AutomaticallyInstallMacOSUpdates", False)),
    }


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    vers = attempt(errors, "sw_vers", lambda: parse_sw_vers(run_cmd(["sw_vers"])), {}) or {}
    version = vers.get("ProductVersion") or platform.mac_ver()[0]
    data: dict = {
        "hostname": platform.node(),
        "user": getpass.getuser(),
        "is_admin": is_admin(),
        "python_version": platform.python_version(),
        "os": {
            "family": "macos",
            "caption": f"{vers.get('ProductName', 'macOS')} {version}",
            "version": version,
            "build": vers.get("BuildVersion"),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "last_boot": datetime.fromtimestamp(psutil.boot_time()).astimezone().isoformat(timespec="seconds"),
        },
        "firmware": "Apple",
    }
    if ctx.check_updates:
        out = attempt(errors, "updates", lambda: run_cmd(["softwareupdate", "-l"], timeout=180))
        if out is not None:
            data["pending_updates"] = parse_softwareupdate(out)
    else:
        data["pending_updates_skipped"] = True
    data["auto_update"] = attempt(errors, "auto_update", lambda: parse_auto_update(plistlib.loads(SU_PLIST.read_bytes()) if SU_PLIST.exists() else {}))
    sip = attempt(errors, "sip", lambda: run_cmd(["csrutil", "status"]))
    data["sip"] = None if sip is None else "enabled" in sip.lower() and "disabled" not in sip.lower()
    gk = attempt(errors, "gatekeeper", lambda: run_cmd(["spctl", "--status"], ok_codes=(0, 1)))
    data["gatekeeper"] = None if gk is None else "assessments enabled" in gk.lower()
    data["hardware"] = {
        "manufacturer": "Apple",
        "model": attempt(errors, "model", lambda: run_cmd(["sysctl", "-n", "hw.model"]).strip()),
        "cpu": attempt(errors, "cpu_name", lambda: run_cmd(["sysctl", "-n", "machdep.cpu.brand_string"]).strip()),
    }
    data["_errors"] = errors
    return data
