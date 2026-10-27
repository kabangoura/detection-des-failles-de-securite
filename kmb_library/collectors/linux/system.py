"""Collecte Linux : distribution, noyau, mises à jour en attente, Secure Boot, SELinux / AppArmor."""

from __future__ import annotations

import getpass
import platform
import shutil
from datetime import datetime
from pathlib import Path

import psutil

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, is_admin, run_cmd

NAME = "system"
LABEL = "Système et mises à jour"

_SB_VAR = Path("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")


def read(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def parse_os_release(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def parse_apt_upgradable(text: str) -> list[dict]:
    """`apt list --upgradable` : 'openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: ...]'."""
    updates = []
    for line in text.splitlines():
        if "/" not in line or "upgradable" not in line:
            continue
        pkg, rest = line.split("/", 1)
        parts = rest.split()
        repos = parts[0] if parts else ""
        updates.append({"title": f"{pkg} {parts[1] if len(parts) > 1 else ''}".strip(),
                        "security": "security" in repos, "severity": "Important" if "security" in repos else None})
    return updates


def parse_dnf_check_update(text: str) -> list[dict]:
    """`dnf -q check-update` : 'openssl.x86_64   1:3.0.7-27.el9   baseos'."""
    updates = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) == 3 and "." in cols[0] and not line.startswith(" "):
            updates.append({"title": f"{cols[0].rsplit('.', 1)[0]} {cols[1]}", "security": None, "severity": None})
    return updates


def _pending_updates() -> tuple[list[dict], str]:
    if shutil.which("apt"):
        return parse_apt_upgradable(run_cmd(["apt", "list", "--upgradable"], timeout=120)), "apt"
    if shutil.which("dnf"):
        return parse_dnf_check_update(run_cmd(["dnf", "-q", "check-update"], timeout=240, ok_codes=(0, 100))), "dnf"
    if shutil.which("checkupdates"):  # Arch (pacman-contrib)
        out = run_cmd(["checkupdates"], timeout=120, ok_codes=(0, 2))
        return [{"title": line.strip(), "security": None, "severity": None} for line in out.splitlines() if line.strip()], "pacman"
    if shutil.which("zypper"):
        out = run_cmd(["zypper", "-q", "lu"], timeout=120)
        return [{"title": c[2].strip(), "security": None, "severity": None}
                for c in (line.split("|") for line in out.splitlines()) if len(c) > 4 and c[0].strip() == "v"], "zypper"
    raise RuntimeError("Gestionnaire de paquets non reconnu")


def _last_update() -> str | None:
    for p in ("/var/log/apt/history.log", "/var/log/dnf.rpm.log", "/var/log/dnf.log", "/var/log/pacman.log", "/var/log/zypp/history"):
        if Path(p).exists():
            return datetime.fromtimestamp(Path(p).stat().st_mtime).date().isoformat()
    return None


def _secure_boot() -> bool | None:
    if shutil.which("mokutil"):
        out = run_cmd(["mokutil", "--sb-state"], ok_codes=(0, 1))
        if "enabled" in out.lower():
            return True
        if "disabled" in out.lower():
            return False
    if _SB_VAR.exists():
        data = _SB_VAR.read_bytes()
        return bool(data and data[-1] == 1)
    return None


def _mac_framework() -> dict:
    selinux = None
    if shutil.which("getenforce"):
        selinux = run_cmd(["getenforce"]).strip().lower()
    elif Path("/sys/fs/selinux/enforce").exists():
        selinux = "enforcing" if read("/sys/fs/selinux/enforce").strip() == "1" else "permissive"
    apparmor = None
    p = Path("/sys/module/apparmor/parameters/enabled")
    if p.exists():
        apparmor = read(p).strip().upper().startswith("Y")
    return {"selinux": selinux, "apparmor": apparmor}


def _cpu_model() -> str | None:
    for line in read("/proc/cpuinfo").splitlines():
        if line.lower().startswith(("model name", "hardware")):
            return line.split(":", 1)[1].strip()
    return None


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    rel = attempt(errors, "os_release", lambda: parse_os_release(read("/etc/os-release")), {}) or {}
    data: dict = {
        "hostname": platform.node(),
        "user": getpass.getuser(),
        "is_admin": is_admin(),
        "python_version": platform.python_version(),
        "os": {
            "family": "linux",
            "caption": rel.get("PRETTY_NAME") or f"Linux {platform.release()}",
            "id": rel.get("ID"),
            "id_like": rel.get("ID_LIKE"),
            "version": rel.get("VERSION_ID"),
            "codename": rel.get("VERSION_CODENAME"),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "last_boot": datetime.fromtimestamp(psutil.boot_time()).astimezone().isoformat(timespec="seconds"),
        },
        "firmware": "UEFI" if Path("/sys/firmware/efi").exists() else "BIOS",
    }
    if ctx.check_updates:
        res = attempt(errors, "updates", _pending_updates)
        if res:
            data["pending_updates"], data["package_manager"] = res
    else:
        data["pending_updates_skipped"] = True
    data["last_update_date"] = attempt(errors, "last_update", _last_update)
    data["secure_boot"] = attempt(errors, "secure_boot", _secure_boot)
    data["mac_framework"] = attempt(errors, "mac_framework", _mac_framework)
    data["hardware"] = {
        "manufacturer": attempt(errors, "dmi_vendor", lambda: read("/sys/class/dmi/id/sys_vendor").strip()),
        "model": attempt(errors, "dmi_product", lambda: read("/sys/class/dmi/id/product_name").strip()),
        "cpu": attempt(errors, "cpu_name", _cpu_model),
    }
    # Les informations DMI absentes (machine virtuelle, Raspberry Pi) ne sont pas des erreurs
    for k in ("dmi_vendor", "dmi_product"):
        errors.pop(k, None)
    data["_errors"] = errors
    return data
