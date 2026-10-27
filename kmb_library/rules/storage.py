"""Règles de stockage : espace libre, doublons, gros fichiers, espace récupérable, Téléchargements, santé des disques."""

from __future__ import annotations

from pathlib import PurePath

from kmb_library.core.models import Finding
from kmb_library.core.utils import GB, MB, human_size
from kmb_library.rules.engine import RawView, make

FREE_WARN, FREE_CRIT = 20, 10   # % d'espace libre
DUP_MEDIUM, DUP_LOW = 1 * GB, 50 * MB
DOWNLOADS_MAX_GB = 5
RECOVERABLE_LOW, RECOVERABLE_MEDIUM = 1, 5   # Go récupérables sans risque


def _name(path: str) -> str:
    return PurePath(path.replace("\\", "/")).name


def evaluate(v: RawView, enr: dict) -> list[Finding]:
    out: list[Finding] = []
    st = v.data("storage")

    parts = st.get("partitions")
    if parts is None:
        out.append(make("STO-001", "non_verifiable", v.reason("storage", "partitions")))
    for part in parts or []:
        free_pct = round(100 - part["percent_used"], 1)
        mount = part["mount"].rstrip("\\")
        evidence = f"{mount} : {part['free_gb']} Go libres sur {part['total_gb']} Go ({free_pct} % libre)"
        if free_pct < FREE_WARN:
            out.append(make("STO-001", "detecte", evidence, suffix=mount, severity="eleve" if free_pct < FREE_CRIT else "moyen"))
        else:
            out.append(make("STO-001", "conforme", evidence, suffix=mount))

    dup = v.data("duplicates")
    if dup.get("skipped"):
        pass
    elif "wasted_bytes" in dup:
        wasted = dup["wasted_bytes"]
        if wasted > 0:
            sev = "moyen" if wasted >= DUP_MEDIUM else ("faible" if wasted >= DUP_LOW else "info")
            out.append(make("STO-002", "detecte",
                            f"{dup['duplicate_files']} fichier(s) personnel(s) en double dans {dup['group_count']} groupe(s) : "
                            f"{human_size(wasted)} récupérables ({dup['files_scanned']} fichiers analysés"
                            f"{', analyse partielle' if dup.get('truncated') else ''})",
                            severity=sev, details={"wasted_bytes": wasted}))
        else:
            out.append(make("STO-002", "conforme", f"Aucun doublon parmi {dup['files_scanned']} fichiers"))

    large = st.get("large_files") or []
    if large:
        personal = [f for f in large if f.get("category", "personnel") == "personnel"]
        shown = (personal or large)[:6]
        evidence = "; ".join(f"{_name(f['path'])} ({f['size_gb']} Go, {f.get('kind', 'fichier')})" for f in shown)
        if personal and len(personal) < len(large):
            evidence += f" — et {len(large) - len(personal)} gros fichier(s) d'applications (à gérer depuis l'application)"
        out.append(make("STO-003", "detecte", evidence, details={"personnels": len(personal), "total": len(large)}))

    rec = st.get("recoverable")
    if rec is not None:
        total = round(sum(r["size_gb"] for r in rec), 1)
        top = ", ".join(f"{r['name'].lower()} ({r['size_gb']} Go)" for r in rec[:4])
        if total >= RECOVERABLE_LOW:
            out.append(make("STO-006", "detecte", f"{total} Go récupérables sans risque : {top}",
                            severity="moyen" if total >= RECOVERABLE_MEDIUM else "faible", details={"total_gb": total}))
        else:
            out.append(make("STO-006", "conforme", f"Moins de 1 Go à récupérer ({total} Go)"))

    dl = next((f for f in st.get("folders", []) if f["name"] == "Téléchargements"), None)
    if dl:
        out.append(make("STO-004", "detecte" if dl["local_gb"] > DOWNLOADS_MAX_GB else "conforme",
                        f"Téléchargements : {dl['local_gb']} Go ({dl['files']} fichiers)"))

    for d in st.get("physical_disks") or []:
        if d.get("health") and d["health"] != "Healthy":
            out.append(make("STO-005", "detecte", f"{d['name']} : {d['health']} / {d.get('status')}", suffix=d["name"]))
    return out
