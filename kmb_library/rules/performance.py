"""Règles de performance : processeur, mémoire, démarrage, temps d'activité, type de disque."""

from __future__ import annotations

from kmb_library.core.models import Finding
from kmb_library.rules.engine import RawView, make

CPU_MAX = 85
RAM_MIN_GB = 7.5         # 8 Go physiques apparaissent comme ~7,8 Go utilisables
RAM_MAX_PERCENT = 85
STARTUP_WARN, STARTUP_HIGH = 8, 12
APP_MEM_SHARE = 0.20
UPTIME_MAX_DAYS = 14


def evaluate(v: RawView, enr: dict) -> list[Finding]:
    out: list[Finding] = []
    p = v.data("performance")
    cpu, mem = p.get("cpu") or {}, p.get("memory") or {}

    if cpu.get("usage_percent") is not None:
        top = ", ".join(f"{g['name']} ({g['cpu_percent']} %)" for g in p.get("top_cpu", [])[:3])
        out.append(make("PERF-001", "detecte" if cpu["usage_percent"] > CPU_MAX else "conforme",
                        f"Utilisation moyenne sur 3 s : {cpu['usage_percent']} % ({cpu.get('logical_cores')} cœurs logiques). Plus actifs : {top}"))
    if mem:
        out.append(make("PERF-002", "detecte" if mem["total_gb"] < RAM_MIN_GB else "conforme", f"{mem['total_gb']} Go de mémoire vive"))
        out.append(make("PERF-003", "detecte" if mem["percent"] > RAM_MAX_PERCENT else "conforme",
                        f"{mem['percent']} % utilisés ({mem['used_gb']} / {mem['total_gb']} Go)"))
        for g in p.get("top_memory", []):
            if mem["total_gb"] and g["memory_mb"] / 1024 > mem["total_gb"] * APP_MEM_SHARE:
                out.append(make("PERF-005", "detecte", f"{g['name']} : {g['memory_mb']} Mo sur {g['count']} processus",
                                suffix=g["name"], title=f"Application très gourmande en mémoire : {g['name']}"))

    startup = p.get("startup")
    if startup is not None:
        enabled = [s for s in startup if s.get("enabled")]
        sev = "moyen" if len(enabled) >= STARTUP_HIGH else "faible"
        out.append(make("PERF-004", "detecte" if len(enabled) >= STARTUP_WARN else "conforme",
                        f"{len(enabled)} programme(s) actif(s) au démarrage : " + ", ".join(s["name"] for s in enabled[:12]),
                        severity=sev))
    if p.get("uptime_days") is not None:
        out.append(make("PERF-006", "detecte" if p["uptime_days"] > UPTIME_MAX_DAYS else "conforme",
                        f"Dernier démarrage le {str(p.get('boot_time'))[:16]} ({p['uptime_days']} jours)"))

    disks = v.data("storage").get("physical_disks")
    if disks:
        hdd = [d for d in disks if str(d.get("media_type")).upper() == "HDD"]
        ssd = [d for d in disks if str(d.get("media_type")).upper() == "SSD"]
        if hdd and not ssd:
            out.append(make("PERF-007", "detecte", "Disque(s) mécanique(s) : " + ", ".join(d["name"] for d in hdd)))
        else:
            out.append(make("PERF-007", "conforme", "Disque(s) : " + ", ".join(f"{d['name']} ({d.get('media_type')})" for d in disks)))
    return out
