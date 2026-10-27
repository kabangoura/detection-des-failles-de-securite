"""Enrichissement : cycle de vie des logiciels et de l'OS via l'API publique endoflife.date.

Source : https://endoflife.date/api/{produit}.json (pas de clé, données ouvertes).
Les réponses sont mises en cache 7 jours dans data/cache/endoflife/ ; si l'API est
indisponible, on utilise le cache même périmé, sinon le logiciel reste « inconnu ».
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable

import httpx

from kmb_library.core.utils import now_iso, version_tuple

API = "https://endoflife.date/api/{product}.json"
CACHE_TTL_S = 7 * 24 * 3600


# --------------------------------------------------------------------------- correspondances

def _major(v: str) -> str | None:
    t = version_tuple(v)
    return str(t[0]) if t else None


def _major_minor(v: str) -> str | None:
    t = version_tuple(v)
    return f"{t[0]}.{t[1]}" if len(t) >= 2 else None


def _java(v: str) -> str | None:
    t = version_tuple(v)
    if not t:
        return None
    return str(t[1]) if t[0] == 1 and len(t) > 1 else str(t[0])  # 1.8.0 -> 8


@dataclass
class Matcher:
    pattern: str            # expression régulière appliquée au nom affiché
    product: str            # identifiant endoflife.date
    cycle: Callable[[str], str | None]
    rolling: bool = False   # True : nouvelles versions fréquentes (navigateurs, IDE) -> « mise à jour » plutôt que « fin de support »
    version_from_name: bool = False
    compare_latest: bool = True
    cycle_from_name: bool = False  # le cycle est le 1er groupe capturé dans le nom (ex. paquet « python3.11 »)


def _strip_epoch(v: str) -> str:
    """Versions Debian/RPM : '1:3.0.7-27.el9' -> '3.0.7'."""
    return re.sub(r"^\d+:", "", v or "")


# Paquets des distributions Linux : les correctifs sont rétroportés par la distribution, on ne compare
# donc PAS la version au « latest » de l'éditeur, seulement la fin de support de la branche.
LINUX_MATCHERS = [
    Matcher(r"^python(3\.\d+)$", "python", lambda v: None, cycle_from_name=True, compare_latest=False),
    Matcher(r"^nodejs$", "nodejs", lambda v: _major(_strip_epoch(v)), compare_latest=False),
    Matcher(r"^postgresql-(\d+)$", "postgresql", lambda v: None, cycle_from_name=True, compare_latest=False),
    Matcher(r"^php(\d\.\d)$", "php", lambda v: None, cycle_from_name=True, compare_latest=False),
    Matcher(r"^mysql-server-(\d+\.\d+)$", "mysql", lambda v: None, cycle_from_name=True, compare_latest=False),
    Matcher(r"^(?:google-chrome-stable|chromium)$", "chrome", lambda v: _major(_strip_epoch(v)), rolling=True, compare_latest=False),
    Matcher(r"^firefox$", "firefox", lambda v: _major(_strip_epoch(v)), rolling=True, compare_latest=False),
    Matcher(r"^docker-ce$", "docker-engine", lambda v: _major(_strip_epoch(v)), compare_latest=False),
    Matcher(r"^(?:virtualbox|virtualbox-\d\.\d)$", "virtualbox", lambda v: _major_minor(_strip_epoch(v)), compare_latest=False),
    Matcher(r"^libreoffice-core$", "libreoffice", lambda v: _major_minor(_strip_epoch(v)), compare_latest=False),
]

MATCHERS = [
    Matcher(r"^Python \d+\.\d+", "python", _major_minor),
    Matcher(r"^Node\.js", "nodejs", _major),
    Matcher(r"^Google Chrome$", "chrome", _major, rolling=True),
    Matcher(r"^Mozilla Firefox", "firefox", _major, rolling=True),
    Matcher(r"^PostgreSQL \d+", "postgresql", _major),
    Matcher(r"^MySQL Server", "mysql", _major_minor),
    Matcher(r"^Microsoft (\.NET|ASP\.NET Core|Windows Desktop Runtime).*\d+\.\d+\.\d+", "dotnet", _major,
            version_from_name=True, compare_latest=False),
    Matcher(r"^Visual Studio (Community|Professional|Enterprise|Build Tools) 20\d\d", "visual-studio", _major_minor, rolling=True),
    Matcher(r"^Unity \d{4}", "unity", _major_minor, rolling=True),
    Matcher(r"^Java(\(TM\))?( SE Development Kit| \d+)", "oracle-jdk", _java),
    Matcher(r"Eclipse Temurin|Adoptium", "eclipse-temurin", _java),
    Matcher(r"^Microsoft Build of OpenJDK", "microsoft-build-of-openjdk", _java),
    Matcher(r"Amazon Corretto", "amazon-corretto", _java),
    Matcher(r"^Microsoft Office .*(20\d\d)", "office", lambda v: None),  # cycle tiré du nom (voir match_software)
    Matcher(r"^LibreOffice", "libreoffice", _major_minor),
    Matcher(r"^Notepad\+\+", "notepad-plus-plus", _major_minor),
    Matcher(r"VirtualBox", "virtualbox", _major_minor),
    Matcher(r"^PowerShell 7", "powershell", _major_minor),
    Matcher(r"^PHP \d", "php", _major_minor),
    Matcher(r"^Go Programming Language", "go", _major_minor),
]

# Composants dont la fin de support est connue mais absents d'endoflife.date (source : Microsoft Lifecycle)
STATIC_EOL = [
    (r"Visual C\+\+ 2005 ", "Visual C++ 2005", "2016-04-12"),
    (r"Visual C\+\+ 2008 ", "Visual C++ 2008", "2018-04-10"),
    (r"Visual C\+\+ 2010 ", "Visual C++ 2010", "2020-07-14"),
    (r"Visual C\+\+ 2012 ", "Visual C++ 2012", "2023-01-10"),
    (r"Visual C\+\+ 2013 ", "Visual C++ 2013", "2024-04-09"),
    (r"Silverlight", "Microsoft Silverlight", "2021-10-12"),
    (r"Adobe Flash", "Adobe Flash Player", "2020-12-31"),
]


# --------------------------------------------------------------------------- client avec cache

class EndOfLifeClient:
    def __init__(self, cache_dir: Path | None, offline: bool = False, timeout: float = 10.0):
        self.cache_dir = cache_dir
        self.offline = offline
        self.timeout = timeout
        self.sources: dict[str, dict] = {}
        self._mem: dict[str, list | None] = {}

    def _cache_file(self, product: str) -> Path | None:
        return self.cache_dir / f"{product}.json" if self.cache_dir else None

    def cycles(self, product: str) -> list[dict] | None:
        if product in self._mem:
            return self._mem[product]
        cache = self._cache_file(product)
        cached = None
        if cache and cache.exists():
            try:
                cached = json.loads(cache.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                cached = None
        fresh = cached and time.time() - cached.get("fetched_ts", 0) < CACHE_TTL_S
        data, origin = None, None
        if fresh or (self.offline and cached):
            data, origin = cached["data"], "cache"
        elif not self.offline:
            try:
                r = httpx.get(API.format(product=product), timeout=self.timeout, follow_redirects=True)
                r.raise_for_status()
                data, origin = r.json(), "api"
                if cache:
                    cache.parent.mkdir(parents=True, exist_ok=True)
                    cache.write_text(json.dumps({"fetched_ts": time.time(), "fetched_at": now_iso(), "data": data}),
                                     encoding="utf-8")
            except (httpx.HTTPError, ValueError) as exc:
                if cached:
                    data, origin = cached["data"], "cache (API indisponible)"
                else:
                    origin = f"indisponible : {type(exc).__name__}"
        self.sources[product] = {
            "name": "endoflife.date", "product": product, "url": API.format(product=product), "origin": origin or "hors ligne",
            "fetched_at": (cached or {}).get("fetched_at") if origin and origin.startswith("cache") else now_iso(),
        }
        self._mem[product] = data
        return data


# --------------------------------------------------------------------------- évaluation

def _eol_passed(eol, today: date) -> bool | None:
    if isinstance(eol, bool):
        return eol
    if isinstance(eol, str):
        try:
            return date.fromisoformat(eol) <= today
        except ValueError:
            return None
    return None


def lifecycle_status(cycle: dict | None, version: str | None, today: date, compare_latest: bool = True) -> dict:
    if not cycle:
        return {"status": "inconnu"}
    eol = cycle.get("eol")
    passed = _eol_passed(eol, today)
    latest = cycle.get("latest")
    out = {"cycle": cycle.get("cycle"), "eol": eol, "latest": latest if compare_latest else None, "lts": cycle.get("lts")}
    if passed:
        out["status"] = "fin_de_support"
    elif compare_latest and latest and version and version_tuple(version) < version_tuple(latest):
        out["status"] = "maj_disponible"
    else:
        out["status"] = "supporte"
    if isinstance(eol, str) and not passed:
        out["days_to_eol"] = (date.fromisoformat(eol) - today).days
    return out


def match_software(app: dict, client: EndOfLifeClient, today: date, os_family: str = "windows") -> dict | None:
    name, version = app["name"], app.get("version") or ""
    if os_family == "windows":
        for pattern, label, eol in STATIC_EOL:
            if re.search(pattern, name, re.IGNORECASE):
                return {"name": name, "version": version, "product": label, "source": "Microsoft Lifecycle (liste locale)",
                        "status": "fin_de_support" if date.fromisoformat(eol) <= today else "supporte", "eol": eol, "rolling": False}
    # Sur Linux, les paquets de la distribution (dpkg/rpm) suivent LINUX_MATCHERS ; Flatpak/Snap suivent les noms d'applications
    matchers = LINUX_MATCHERS if os_family == "linux" and app.get("source") in ("dpkg", "rpm", "pacman") else MATCHERS
    for m in matchers:
        mt = re.search(m.pattern, name)
        if not mt:
            continue
        if m.version_from_name:
            vm = re.search(r"\d+\.\d+\.\d+", name)
            version = vm.group() if vm else version
        cycle_id = mt.group(1) if (m.product == "office" or m.cycle_from_name) else m.cycle(version)
        cycles = client.cycles(m.product)
        entry = {"name": name, "version": version, "product": m.product, "rolling": m.rolling, "source": "endoflife.date",
                 "distro_package": matchers is LINUX_MATCHERS}
        if cycles is None:
            return {**entry, "status": "inconnu", "reason": "source indisponible"}
        cycle = next((c for c in cycles if str(c.get("cycle")) == cycle_id), None)
        if cycle is None and cycle_id:
            cycle = next((c for c in cycles if str(c.get("cycle")).split("-")[0] == cycle_id), None)
        if cycle is None:
            return {**entry, "status": "inconnu", "reason": f"cycle {cycle_id} absent"}
        newest = cycles[0] if cycles else {}
        entry["newest"] = newest.get("latest") or newest.get("cycle")
        return {**entry, **lifecycle_status(cycle, version, today, m.compare_latest)}
    return None


def match_windows(os_info: dict, client: EndOfLifeClient, today: date) -> dict:
    """Associe le build Windows (ex. 10.0.19045) et l'édition au bon cycle endoflife.date."""
    build = str(os_info.get("build") or "")
    cycles = client.cycles("windows")
    base = {"product": "windows", "build": build, "display_version": os_info.get("display_version")}
    if not cycles or not build:
        return {**base, "status": "inconnu"}
    edition = str(os_info.get("edition") or "").lower()
    suffix = "-e" if ("enterprise" in edition or "education" in edition) else "-w"
    candidates = [c for c in cycles if str(c.get("latest", "")).endswith(f".{build}")
                  and "iot" not in c["cycle"] and "lts" not in c["cycle"]]
    if "ltsc" in edition or "ltsb" in edition:
        candidates = [c for c in cycles if str(c.get("latest", "")).endswith(f".{build}") and "lts" in c["cycle"]] or candidates
    chosen = next((c for c in candidates if c["cycle"].endswith(suffix)), None) or next(
        (c for c in candidates if not re.search(r"-[we]$", c["cycle"])), None) or (candidates[0] if candidates else None)
    status = lifecycle_status(chosen, None, today, compare_latest=False)
    if chosen:
        status["label"] = chosen.get("releaseLabel") or chosen["cycle"]
    return {**base, **status}


# Identifiant /etc/os-release -> produit endoflife.date
LINUX_PRODUCTS = {
    "ubuntu": "ubuntu", "debian": "debian", "fedora": "fedora", "rhel": "rhel", "centos": "centos",
    "rocky": "rocky-linux", "almalinux": "almalinux", "linuxmint": "linuxmint", "opensuse-leap": "opensuse",
    "ol": "oracle-linux", "amzn": "amazon-linux", "pop": "pop-os", "elementary": "elementary-os", "alpine": "alpine-linux",
}


def _find_cycle(cycles: list[dict], wanted: str | None) -> dict | None:
    if not wanted:
        return None
    exact = next((c for c in cycles if str(c.get("cycle")) == wanted), None)
    if exact:
        return exact
    major = wanted.split(".")[0]
    return next((c for c in cycles if str(c.get("cycle")) == major), None)


def match_linux(os_info: dict, client: EndOfLifeClient, today: date) -> dict:
    distro = str(os_info.get("id") or "").lower()
    product = LINUX_PRODUCTS.get(distro)
    base = {"product": product or distro, "version": os_info.get("version")}
    if not product:
        return {**base, "status": "inconnu", "reason": f"distribution « {distro} » non suivie par endoflife.date"}
    cycles = client.cycles(product)
    if not cycles:
        return {**base, "status": "inconnu"}
    cycle = _find_cycle(cycles, os_info.get("version"))
    status = lifecycle_status(cycle, None, today, compare_latest=False)
    if cycle:
        status["label"] = f"{os_info.get('caption') or distro} (cycle {cycle.get('cycle')})"
    return {**base, **status}


def match_macos(os_info: dict, client: EndOfLifeClient, today: date) -> dict:
    version = str(os_info.get("version") or "")
    t = version_tuple(version)
    wanted = f"{t[0]}.{t[1]}" if t and t[0] == 10 and len(t) > 1 else (str(t[0]) if t else None)
    cycles = client.cycles("macos")
    base = {"product": "macos", "version": version}
    if not cycles:
        return {**base, "status": "inconnu"}
    cycle = _find_cycle(cycles, wanted)
    status = lifecycle_status(cycle, version, today, compare_latest=True)
    if cycle:
        status["label"] = f"macOS {cycle.get('codename') or ''} {cycle.get('cycle')}".replace("  ", " ")
    return {**base, **status}


def match_os(os_info: dict, client: EndOfLifeClient, today: date, os_family: str) -> dict:
    if not os_info:
        return {"status": "inconnu"}
    if os_family == "linux":
        return match_linux(os_info, client, today)
    if os_family == "macos":
        return match_macos(os_info, client, today)
    return match_windows(os_info, client, today)


def enrich(raw: dict, cache_dir: Path | None, offline: bool = False, today: date | None = None) -> dict:
    today = today or date.today()
    client = EndOfLifeClient(cache_dir, offline)
    os_family = raw.get("os_family", "windows")
    coll = raw.get("collectors", {})
    os_info = (coll.get("system", {}).get("data") or {}).get("os") or {}
    apps = (coll.get("software", {}).get("data") or {}).get("installed") or []
    software = []
    for app in apps:
        m = match_software(app, client, today, os_family)
        if m:
            software.append(m)
    return {
        "os_lifecycle": match_os(os_info, client, today, os_family),
        "software_lifecycle": software,
        "sources": list(client.sources.values()),
    }
