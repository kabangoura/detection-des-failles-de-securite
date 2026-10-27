"""Collecte : fichiers en double (même taille -> même empreinte partielle -> même SHA-256).

Par défaut, les candidats viennent de l'analyse du disque (collecteur « storage ») : tous les types de
fichiers personnels d'au moins 1 Mo, dans tout ce qui appartient à l'utilisateur. Les dossiers du
système et des applications ne sont jamais proposés. Les fichiers « en ligne uniquement » (OneDrive)
sont ignorés pour ne pas les télécharger.
Avec `--dossiers`, la recherche se limite aux dossiers indiqués.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections import defaultdict
from pathlib import Path

from kmb_library.core.context import ScanContext
from kmb_library.core.fswalk import WalkState, user_folders, walk_files

NAME = "duplicates"
LABEL = "Doublons"

CATEGORIES = {
    "documents": {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".txt", ".csv"},
    "musique": {".mp3", ".wav", ".flac", ".m4a", ".aac", ".ogg"},
    "videos": {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm"},
    "images": {".jpg", ".jpeg", ".png", ".webp", ".gif", ".heic", ".bmp"},
    "archives": {".zip", ".rar", ".7z", ".iso", ".msi", ".exe"},
}
EXT_CATEGORY = {ext: cat for cat, exts in CATEGORIES.items() for ext in exts}
MIN_SIZE = 1024
_CHUNK = 64 * 1024
SAMPLED_ABOVE = 512 * 1024 * 1024   # au-delà : empreinte sur 3 échantillons de 4 Mo (début, milieu, fin)
MAX_GROUPS_REPORTED = 100

# « Film (1).mp4 », « Film - copie.mp4 », « photo_copy.jpg », « Copie de rapport.docx », « rapport-final-v2.docx »
_COPY_PATTERNS = [
    r"^(copie de|copy of)\s+",
    r"\s*[-_ ]\s*(copie|copy)(\s*\(\d+\))?$",
    r"\s*\(\d+\)$",
    r"[-_ ]?(final|finale|def|definitif)$",
    r"[-_ ]?v\d+$",
]


def normalize_name(filename: str) -> str:
    stem = Path(filename).stem.lower().strip()
    previous = None
    while previous != stem:
        previous = stem
        for pat in _COPY_PATTERNS:
            stem = re.sub(pat, "", stem).strip()
    return stem + Path(filename).suffix.lower()


def category_of_file(path: str) -> str:
    from kmb_library.collectors.analyse_disque import kind_of

    ext = Path(path).suffix.lower()
    return EXT_CATEGORY.get(ext) or kind_of(path)


def _hash(path: str, mode: str) -> str | None:
    """mode : partial (début + fin), full (tout le fichier), sampled (3 échantillons de 4 Mo)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            if mode == "partial":
                h.update(fh.read(_CHUNK))
                if size > 2 * _CHUNK:
                    fh.seek(-_CHUNK, os.SEEK_END)
                    h.update(fh.read(_CHUNK))
            elif mode == "sampled":
                block = 4 * 1024 * 1024
                for offset in (0, max(size // 2 - block // 2, 0), max(size - block, 0)):
                    fh.seek(offset)
                    h.update(fh.read(block))
            else:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def group_by_content(by_size: dict[int, list[tuple[str, float]]], deadline: float) -> tuple[list[dict], int, bool]:
    """Regroupe les fichiers identiques. Retourne (groupes, fichiers hachés, analyse interrompue)."""
    groups, hashed, truncated = [], 0, False
    # les plus gros d'abord : ce sont eux qui libèrent le plus d'espace
    for size in sorted((s for s, f in by_size.items() if len(f) > 1), reverse=True):
        if time.monotonic() > deadline:
            truncated = True
            break
        files = by_size[size]
        partial: dict[str, list] = defaultdict(list)
        for path, mtime in files:
            ph = _hash(path, "partial")
            if ph:
                partial[ph].append((path, mtime))
        for candidates in partial.values():
            if len(candidates) < 2:
                continue
            mode = "sampled" if size > SAMPLED_ABOVE else "full"
            full: dict[str, list] = defaultdict(list)
            for path, mtime in candidates:
                fh = _hash(path, mode)
                hashed += 1
                if fh:
                    full[fh].append((path, mtime))
            for digest, same in full.items():
                if len(same) > 1:
                    ordered = sorted(same, key=lambda f: f[1])  # le plus ancien = original présumé
                    groups.append({
                        "sha256": digest, "size_bytes": size, "category": category_of_file(ordered[0][0]),
                        "count": len(same), "wasted_bytes": size * (len(same) - 1),
                        "files": [p for p, _ in ordered], "method": "échantillons" if mode == "sampled" else "contenu complet",
                    })
    groups.sort(key=lambda g: g["wasted_bytes"], reverse=True)
    return groups, hashed, truncated


def _summary(groups: list[dict], files_scanned: int, hashed: int, truncated: bool, roots: list[str],
             cloud: int = 0, similar: list | None = None) -> dict:
    by_cat: dict[str, dict] = {}
    for g in groups:
        c = by_cat.setdefault(g["category"], {"groups": 0, "wasted_bytes": 0})
        c["groups"] += 1
        c["wasted_bytes"] += g["wasted_bytes"]
    return {
        "roots": roots, "files_scanned": files_scanned, "cloud_only_skipped": cloud, "files_hashed": hashed,
        "truncated": truncated, "group_count": len(groups),
        "duplicate_files": sum(g["count"] - 1 for g in groups),
        "wasted_bytes": sum(g["wasted_bytes"] for g in groups),
        "by_category": by_cat, "groups": groups[:MAX_GROUPS_REPORTED], "similar_names": similar or [],
    }


def find_duplicates(roots: list[Path], budget_s: float) -> dict:
    """Recherche limitée à des dossiers précis (option --dossiers) : documents, médias, images, archives."""
    deadline = time.monotonic() + budget_s
    state = WalkState()
    by_size: dict[int, list] = defaultdict(list)
    by_name: dict[str, list] = defaultdict(list)
    skipped_cloud = 0
    for f in walk_files(roots, deadline, state):
        ext = Path(f.path).suffix.lower()
        if ext not in EXT_CATEGORY or f.size < MIN_SIZE:
            continue
        if f.cloud_only:
            skipped_cloud += 1
            continue
        by_size[f.size].append((f.path, f.mtime))
        by_name[normalize_name(Path(f.path).name)].append(f.path)
    groups, hashed, truncated = group_by_content(by_size, deadline + budget_s)
    dup_paths = {p for g in groups for p in g["files"]}
    similar = [{"normalized_name": n, "count": len(fs), "files": fs[:10]}
               for n, fs in by_name.items() if len(fs) > 1 and len([p for p in fs if p not in dup_paths]) > 1]
    similar.sort(key=lambda s: s["count"], reverse=True)
    return _summary(groups, state.files, hashed, state.truncated or truncated, [str(r) for r in roots],
                    skipped_cloud, similar[:50])


def collect(ctx: ScanContext) -> dict:
    if not ctx.duplicates:
        return {"skipped": True}
    if ctx.duplicate_dirs:
        return find_duplicates(ctx.duplicate_dirs, ctx.storage_time_budget_s / 4)
    candidates = ctx.shared.get("dup_candidates")
    if candidates is None:  # analyse du disque indisponible : repli sur les dossiers personnels
        return find_duplicates(list(user_folders().values()), ctx.storage_time_budget_s / 4)
    groups, hashed, truncated = group_by_content(candidates, time.monotonic() + ctx.storage_time_budget_s * 0.25)
    return _summary(groups, ctx.shared.get("files_scanned", 0), hashed, truncated or ctx.shared.get("walk_truncated", False),
                    ctx.shared.get("zones", []), ctx.shared.get("cloud_only", 0))
