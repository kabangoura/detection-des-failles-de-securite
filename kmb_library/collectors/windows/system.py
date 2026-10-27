"""Collecte : système d'exploitation, correctifs, UAC, Secure Boot, matériel."""

from __future__ import annotations

import ctypes
import getpass
import platform
from datetime import datetime

import psutil

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, is_admin, ps_json, read_reg

NAME = "system"
LABEL = "Système et correctifs"

_CV = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

_UPDATE_SEARCH = (
    "$s=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); "
    "$r=$s.Search(\"IsInstalled=0 and Type='Software' and IsHidden=0\"); "
    "$r.Updates | ForEach-Object { [pscustomobject]@{ Title=$_.Title; Severity=$_.MsrcSeverity; "
    "KB=($_.KBArticleIDs -join ','); Categories=(($_.Categories | ForEach-Object {$_.Name}) -join ', ') } }"
)


def _firmware_type() -> str | None:
    """GetFirmwareType (kernel32) : 1 = BIOS hérité, 2 = UEFI. Ne demande pas de droits admin."""
    ft = ctypes.c_uint(0)
    if ctypes.windll.kernel32.GetFirmwareType(ctypes.byref(ft)):
        return {1: "BIOS", 2: "UEFI"}.get(ft.value, "inconnu")
    return None


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    data: dict = {
        "hostname": platform.node(),
        "user": getpass.getuser(),
        "is_admin": is_admin(),
        "python_version": platform.python_version(),
    }

    os_cim = attempt(errors, "os", lambda: ps_json(
        "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,"
        "@{n='LastBootUpTime';e={$_.LastBootUpTime.ToString('o')}},@{n='InstallDate';e={$_.InstallDate.ToString('o')}}"
    )[0], {}) or {}
    cv = attempt(errors, "os_registry", lambda: read_reg("HKLM", _CV), {}) or {}
    data["os"] = {
        "caption": os_cim.get("Caption") or cv.get("ProductName") or platform.platform(),
        "version": os_cim.get("Version") or platform.version(),
        "build": str(os_cim.get("BuildNumber") or cv.get("CurrentBuild") or ""),
        "ubr": cv.get("UBR"),
        "display_version": cv.get("DisplayVersion") or cv.get("ReleaseId"),
        "edition": cv.get("EditionID"),
        "architecture": os_cim.get("OSArchitecture") or platform.machine(),
        "last_boot": os_cim.get("LastBootUpTime") or datetime.fromtimestamp(psutil.boot_time()).astimezone().isoformat(),
        "install_date": os_cim.get("InstallDate"),
    }

    hotfixes = attempt(errors, "hotfixes", lambda: ps_json(
        "Get-HotFix | Select-Object HotFixID,Description,"
        "@{n='InstalledOn';e={if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}}}"
    ), [])
    if hotfixes is not None:
        dated = sorted((h for h in hotfixes if h.get("InstalledOn")), key=lambda h: h["InstalledOn"], reverse=True)
        data["hotfixes"] = {
            "count": len(hotfixes),
            "latest_date": dated[0]["InstalledOn"] if dated else None,
            "recent": [{"id": h.get("HotFixID"), "type": h.get("Description"), "date": h.get("InstalledOn")} for h in dated[:8]],
        }

    if ctx.check_updates:
        pending = attempt(errors, "windows_update", lambda: ps_json(_UPDATE_SEARCH, timeout=240))
        if pending is not None:
            data["pending_updates"] = [
                {"title": u.get("Title"), "severity": u.get("Severity"), "kb": u.get("KB"), "categories": u.get("Categories")}
                for u in pending
            ]
    else:
        data["pending_updates_skipped"] = True

    uac = attempt(errors, "uac", lambda: read_reg("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"), {}) or {}
    data["uac"] = {
        "enable_lua": uac.get("EnableLUA"),
        "consent_prompt_admin": uac.get("ConsentPromptBehaviorAdmin"),
        "secure_desktop": uac.get("PromptOnSecureDesktop"),
    } if uac else None

    data["firmware"] = attempt(errors, "firmware", _firmware_type)
    sb = attempt(errors, "secure_boot", lambda: read_reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled"))
    data["secure_boot"] = None if sb is None else bool(sb)

    cs = attempt(errors, "hardware", lambda: ps_json(
        "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory"
    )[0], {}) or {}
    data["hardware"] = {
        "manufacturer": cs.get("Manufacturer"),
        "model": cs.get("Model"),
        "cpu": attempt(errors, "cpu_name", lambda: (read_reg("HKLM", r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString") or "").strip()),
    }
    data["_errors"] = errors
    return data
