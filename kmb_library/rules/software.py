"""Règles logicielles : fin de support, mises à jour, versions multiples, applications volumineuses."""

from __future__ import annotations

import re
from collections import defaultdict

from kmb_library.core.models import Finding
from kmb_library.rules.engine import RawView, make

# Familles où plusieurs versions côte à côte sont normales (dépendances partagées)
_MULTI_OK = re.compile(r"Visual C\+\+|\.NET|Windows SDK|Runtime|Redistributable|Update|Driver|Pilote|Health Tools|Add-in|vs_", re.I)
LARGE_APP_MB = 2048
# Sous Linux, plusieurs versions de bibliothèques coexistent normalement : on ne suit que ces familles
_LINUX_FAMILIES = re.compile(r"^(python3|openjdk|php|postgresql|mysql-server|nodejs|ruby|gcc|dotnet-runtime)[.-]?(\d[\d.]*)")


def family(name: str) -> str:
    """'Python 3.11.4 (64-bit)' -> 'python' ; 'Unity 6000.3.22f1' -> 'unity'."""
    n = re.sub(r"\(.*?\)", " ", name.lower())
    n = re.sub(r"\b(x64|x86|64-bit|32-bit|amd64|update)\b", " ", n)
    n = re.sub(r"\bv?\d+([.\-_]\w+)*\b", " ", n)
    return re.sub(r"\s+", " ", n).strip(" -")


def evaluate(v: RawView, enr: dict) -> list[Finding]:
    out: list[Finding] = []
    sw = v.data("software")
    apps = sw.get("installed")
    if apps is None:
        return [make("APP-001", "non_verifiable", v.reason("software", "registry"))]

    problems = 0
    for s in enr.get("software_lifecycle", []):
        version = s.get("version") or ""
        label = s["name"] if version in s["name"] else f"{s['name']} {version}".strip()
        suffix = f"{s['product']}-{s.get('cycle') or s.get('version')}".replace(" ", "-").lower()
        distro_ok = s.get("distro_package") and (enr.get("os_lifecycle") or {}).get("status") in ("supporte", "maj_disponible")
        if s["status"] == "fin_de_support" and distro_ok:
            # Paquet d'une distribution encore supportée : elle rétroporte les correctifs au-delà de la date amont
            out.append(make("APP-001", "detecte", f"{label} : branche amont {s.get('cycle')} terminée le {s.get('eol')}, "
                            "mais le paquet reste maintenu par la distribution tant que celle-ci est supportée",
                            suffix=suffix, severity="info", title=f"Branche amont terminée (maintenue par la distribution) : {s['name']}",
                            details=s))
        elif s["status"] == "fin_de_support" and not s.get("rolling"):
            out.append(make("APP-001", "detecte", f"{label} : fin de support le {s.get('eol')} (source {s.get('source')})",
                            suffix=suffix, title=f"Logiciel en fin de support : {s['name']}", details=s))
            problems += 1
        elif s["status"] == "fin_de_support":
            latest = f", version actuelle de l'éditeur : {s['newest']}" if s.get("newest") else ""
            out.append(make("APP-002", "detecte", f"{label} : branche {s.get('cycle')} terminée le {s.get('eol')}{latest}",
                            suffix=suffix, severity="moyen", title=f"Version dépassée : {s['name']}", details=s))
            problems += 1
        elif s["status"] == "maj_disponible":
            out.append(make("APP-002", "detecte", f"{label} : version {s.get('latest')} disponible dans la branche {s.get('cycle')}",
                            suffix=suffix, title=f"Mise à jour disponible : {s['name']}", details=s))
            problems += 1
    if not problems:
        checked = len(enr.get("software_lifecycle", []))
        out.append(make("APP-001", "conforme", f"{checked} logiciel(s) vérifié(s) auprès d'endoflife.date, tous à jour"))

    groups: dict[str, list[dict]] = defaultdict(list)
    for a in apps:
        if v.os == "linux":
            m = _LINUX_FAMILIES.match(a["name"])
            if m and a.get("source") in ("dpkg", "rpm", "pacman"):
                groups[m.group(1)].append({**a, "_branch": m.group(2)})
        elif not _MULTI_OK.search(a["name"]):
            groups[family(a["name"])].append(a)
    multi = {k: g for k, g in groups.items() if k and len({x.get("_branch", x.get("version")) for x in g}) > 1}
    for fam, g in sorted(multi.items()):
        versions = ", ".join(f"{x['name']} ({x.get('version')})" for x in g)
        out.append(make("APP-003", "detecte", f"{len(g)} versions : {versions}", suffix=fam,
                        title=f"Plusieurs versions installées : {fam.title()}"))
    if not multi:
        out.append(make("APP-003", "conforme", "Aucune famille de logiciels installée en plusieurs versions"))

    # Taille réelle mesurée sur le disque (analyse du stockage) ; à défaut, taille déclarée par l'application
    measured = v.data("storage").get("apps")
    if measured:
        large = [a for a in measured if a["size_gb"] * 1024 >= LARGE_APP_MB]
        label = lambda a: f"{a['name']} ({a['size_gb']:.1f} Go{'' if a.get('measured') else ', déclaré'})"  # noqa: E731
    else:
        large = sorted((a for a in apps if (a.get("size_mb") or 0) >= LARGE_APP_MB), key=lambda a: a["size_mb"], reverse=True)
        label = lambda a: f"{a['name']} ({a['size_mb'] / 1024:.1f} Go)"  # noqa: E731
    if large:
        out.append(make("APP-004", "detecte", "; ".join(label(a) for a in large[:8]), details={"apps": large}))
    return out
