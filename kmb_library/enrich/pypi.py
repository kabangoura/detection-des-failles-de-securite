"""Signale une version plus récente de KMB Library publiée sur PyPI.

- Une seule requête par jour au maximum : la réponse est gardée 24 h dans le dossier .cache des rapports.
- 2 secondes au plus, et rien de personnel n'est envoyé (simple lecture de la page publique du paquet).
- Hors ligne (option --hors-ligne), sans Internet ou si PyPI ne répond pas : on ne signale rien, le scan continue.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import httpx

URL = "https://pypi.org/pypi/kmb-library/json"
CACHE_TTL_S = 24 * 3600


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version)[:3])


def latest_version(cache_file: Path | None, timeout: float = 2.0) -> str | None:
    """Dernière version publiée sur PyPI (cache d'un jour), ou None si elle est inconnue."""
    cached = None
    if cache_file and cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cached = None
    if cached and time.time() - cached.get("fetched_ts", 0) < CACHE_TTL_S:
        return cached.get("version")
    try:
        r = httpx.get(URL, timeout=timeout, follow_redirects=True)
        r.raise_for_status()
        version = r.json()["info"]["version"]
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return cached.get("version") if cached else None
    if cache_file:
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps({"fetched_ts": time.time(), "version": version}), encoding="utf-8")
        except OSError:
            pass
    return version


def newer_version(current: str, cache_file: Path | None, offline: bool = False) -> str | None:
    """Numéro de la version plus récente que `current`, sinon None."""
    if offline:
        return None
    latest = latest_version(cache_file)
    return latest if latest and _key(latest) > _key(current) else None
