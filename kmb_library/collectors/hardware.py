"""Collecte santé matérielle (Windows, Linux, macOS) : usure de la batterie et températures.

Windows : rapport `powercfg /batteryreport /xml` ; Linux : /sys/class/power_supply + psutil ;
macOS : `ioreg -rn AppleSmartBattery`.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, run_cmd

NAME = "hardware"
LABEL = "Santé matérielle"


def battery_health(design: float | None, full: float | None, cycles: int | None, unit: str) -> dict:
    health = round(100 * full / design, 1) if design and full and design > 0 else None
    return {"design_capacity": design, "full_capacity": full, "unit": unit, "cycles": cycles,
            "health_percent": min(health, 100.0) if health is not None else None}


def parse_powercfg_xml(text: str) -> dict | None:
    root = ET.fromstring(text)
    ns = {"b": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    prefix = "b:" if ns else ""
    batt = root.find(f".//{prefix}Batteries/{prefix}Battery", ns)
    if batt is None:
        return None

    def num(tag: str) -> float | None:
        el = batt.find(f"{prefix}{tag}", ns)
        try:
            return float(el.text) if el is not None and el.text else None
        except ValueError:
            return None

    cycles = num("CycleCount")
    return battery_health(num("DesignCapacity"), num("FullChargeCapacity"), int(cycles) if cycles else None, "mWh")


def _windows_battery() -> dict | None:
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    try:
        run_cmd(["powercfg", "/batteryreport", "/xml", "/output", path], timeout=60)
        return parse_powercfg_xml(Path(path).read_text(encoding="utf-8", errors="replace"))
    finally:
        Path(path).unlink(missing_ok=True)


def parse_sys_battery(values: dict[str, str]) -> dict:
    def f(k):
        v = values.get(k, "").strip()
        return float(v) if v.lstrip("-").isdigit() else None

    design, full, unit = f("energy_full_design"), f("energy_full"), "µWh"
    if design is None:
        design, full, unit = f("charge_full_design"), f("charge_full"), "µAh"
    cycles = f("cycle_count")
    return battery_health(design, full, int(cycles) if cycles else None, unit)


def _linux_battery() -> dict | None:
    for bat in sorted(Path("/sys/class/power_supply").glob("BAT*")):
        values = {}
        for name in ("energy_full_design", "energy_full", "charge_full_design", "charge_full", "cycle_count"):
            p = bat / name
            if p.exists():
                values[name] = p.read_text()
        return parse_sys_battery(values)
    return None


def parse_ioreg_battery(text: str) -> dict | None:
    def val(key: str) -> int | None:
        m = re.search(rf'"{key}"\s*=\s*(\d+)', text)
        return int(m.group(1)) if m else None

    design = val("DesignCapacity")
    if design is None:
        return None
    full = val("AppleRawMaxCapacity") or val("NominalChargeCapacity")
    if full is None:
        mx = val("MaxCapacity")
        full = mx if mx and mx > 100 else None  # sur Apple Silicon, MaxCapacity est un pourcentage
    return battery_health(design, full, val("CycleCount"), "mAh")


def _macos_battery() -> dict | None:
    return parse_ioreg_battery(run_cmd(["ioreg", "-rn", "AppleSmartBattery"]))


def _temperatures() -> list[dict]:
    import psutil

    temps = getattr(psutil, "sensors_temperatures", lambda: {})() or {}
    out = []
    for chip, entries in temps.items():
        for t in entries:
            if t.current:
                out.append({"sensor": f"{chip} {t.label}".strip(), "current": t.current, "high": t.high, "critical": t.critical})
    return out


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    import psutil

    has_battery = None
    try:
        has_battery = psutil.sensors_battery() is not None
    except (AttributeError, OSError, NotImplementedError):
        pass
    fn = {"win32": _windows_battery, "darwin": _macos_battery}.get(sys.platform, _linux_battery)
    battery = attempt(errors, "battery", fn) if has_battery is not False else None
    temps = attempt(errors, "temperatures", _temperatures, []) or []
    return {
        "battery_present": has_battery,
        "battery": battery,
        "temperatures": temps,
        "max_temperature_c": max((t["current"] for t in temps), default=None),
        "_errors": errors,
    }
