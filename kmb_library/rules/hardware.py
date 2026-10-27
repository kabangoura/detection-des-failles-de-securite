"""Règles de santé matérielle : usure de la batterie, température."""

from __future__ import annotations

from kmb_library.core.models import Finding
from kmb_library.rules.engine import RawView, make

BATTERY_WARN, BATTERY_BAD = 80, 60   # % de la capacité d'origine
TEMP_MAX = 90                          # °C


def evaluate(v: RawView, enr: dict) -> list[Finding]:
    out: list[Finding] = []
    hw = v.data("hardware")
    if hw.get("battery_present"):
        b = hw.get("battery") or {}
        h = b.get("health_percent")
        if h is None:
            out.append(make("HW-001", "non_verifiable", "Le système ne publie pas les capacités de la batterie"))
        else:
            cycles = f", {b['cycles']} cycles" if b.get("cycles") else ""
            evidence = f"Capacité actuelle {b.get('full_capacity'):.0f} / {b.get('design_capacity'):.0f} {b.get('unit')} : {h} % de l'origine{cycles}"
            if h < BATTERY_WARN:
                out.append(make("HW-001", "detecte", evidence, severity="moyen" if h < BATTERY_BAD else "faible", details=b))
            else:
                out.append(make("HW-001", "conforme", evidence, details=b))
    temp = hw.get("max_temperature_c") or (v.data("performance").get("cpu") or {}).get("temperature_c")
    if temp is not None:
        out.append(make("HW-002", "detecte" if temp > TEMP_MAX else "conforme", f"Température maximale mesurée : {temp:.0f} °C"))
    return out
