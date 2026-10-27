"""Analyse approfondie de l'espace disque (lecture seule).

Zones analysées : tout le profil de l'utilisateur, les autres disques de données et les dossiers
créés à la racine du disque système. Les dossiers du système (Windows, Program Files, /usr, /System…)
ne sont jamais parcourus : leur taille est seulement estimée.

Chaque élément reçoit une catégorie :
    personnel   : vos fichiers, vous pouvez décider (supprimer, déplacer)
    application : données d'une application, passer par l'application ou la désinstaller
    systeme     : ne pas toucher
"""

from __future__ import annotations

import heapq
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from kmb_library.core.fswalk import is_cloud_only

GB, MB = 1024 ** 3, 1024 ** 2
LARGE_FILE_MIN = 200 * MB      # seuil « gros fichier »
DUP_MIN = 1 * MB               # taille minimale pour chercher des doublons (tous types de fichiers)
TOP_FOLDERS, TOP_FILES = 25, 40

# Dossiers du système : jamais parcourus
WINDOWS_SYSTEM_ROOT = {"windows", "program files", "program files (x86)", "programdata", "$recycle.bin",
                       "system volume information", "recovery", "perflogs", "$winreagent", "config.msi",
                       "msocache", "documents and settings", "users", "$windows.~bt", "$windows.~ws", "$sysreset",
                       "onedrivetemp", "boot", "efi"}
SYSTEM_FILES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp", "dumpstack.log"}
DATA_DRIVE_SKIP = {"$recycle.bin", "system volume information", "recovery", "config.msi"}
# Dans le profil : dossiers qui appartiennent à des applications (taille comptée, pas de doublons proposés)
APP_PARTS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "site-packages", ".gradle", ".m2", ".npm",
             ".nuget", ".cargo", ".rustup", ".vscode", ".cache", "packagecache", "library", ".android", ".conda",
             "anaconda3", "miniconda3", "go", "snap", ".local", ".var", ".docker", "virtualbox vms"}

KINDS = [
    ({".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".m4v", ".mpg"}, "vidéo"),
    ({".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".unitypackage"}, "archive"),
    ({".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".appimage", ".msix"}, "installateur"),
    ({".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".vdi", ".qcow2", ".ova"}, "image disque / machine virtuelle"),
    ({".sql", ".db", ".sqlite", ".mdf", ".ldf", ".bak", ".dump"}, "base de données / sauvegarde"),
    ({".jpg", ".jpeg", ".png", ".heic", ".raw", ".cr2", ".nef", ".psd", ".tif", ".tiff"}, "image"),
    ({".mp3", ".wav", ".flac", ".m4a", ".aac"}, "musique"),
    ({".pdf", ".docx", ".doc", ".xlsx", ".pptx", ".pst", ".ost"}, "document"),
]
EXT_KIND = {ext: kind for exts, kind in KINDS for ext in exts}


def kind_of(path: str) -> str:
    return EXT_KIND.get(Path(path).suffix.lower(), "autre")


@dataclass
class Zone:
    root: Path
    label: str
    kind: str          # profil | disque | racine


@dataclass
class DiskAnalysis:
    files: int = 0
    bytes_total: int = 0
    truncated: bool = False
    folder_sizes: dict = field(default_factory=lambda: defaultdict(int))
    folder_files: dict = field(default_factory=lambda: defaultdict(int))
    folder_category: dict = field(default_factory=dict)
    largest: list = field(default_factory=list)
    dup_by_size: dict = field(default_factory=lambda: defaultdict(list))
    cloud_only: int = 0
    measured_by_drive: dict = field(default_factory=lambda: defaultdict(int))
    zone_roots: dict = field(default_factory=dict)   # chemin -> libellé


# --------------------------------------------------------------------------- zones et catégories

def _drive_of(path: Path) -> str:
    return (path.drive or path.anchor or "/").upper()


def zones() -> list[Zone]:
    """Ce qui appartient à l'utilisateur : profil, autres disques, dossiers créés à la racine du disque système."""
    home = Path.home()
    out = [Zone(home, "Votre profil", "profil")]
    if sys.platform == "win32":
        system_drive = os.environ.get("SystemDrive", "C:").upper() + "\\"
        try:
            for child in Path(system_drive).iterdir():
                if child.is_dir() and child.name.lower() not in WINDOWS_SYSTEM_ROOT and not child.is_symlink():
                    out.append(Zone(child, f"{system_drive}{child.name}", "racine"))
        except OSError:
            pass
        for p in psutil.disk_partitions(all=False):
            if "fixed" in p.opts and p.mountpoint.upper() != system_drive:
                out.append(Zone(Path(p.mountpoint), f"Disque {p.mountpoint.rstrip(chr(92))}", "disque"))
    else:
        for base in ([Path("/mnt"), Path("/media"), Path("/media") / home.name] if sys.platform.startswith("linux")
                     else [Path("/Volumes")]):
            if base.is_dir():
                for child in base.iterdir():
                    try:
                        if child.is_dir() and not child.is_symlink() and os.path.ismount(child) and child != Path("/"):
                            out.append(Zone(child, str(child), "disque"))
                    except OSError:
                        continue
    return out


def _has_programs(folder: Path) -> bool:
    try:
        return any(e.name.lower().endswith((".exe", ".dll", ".sys")) for e in os.scandir(folder))
    except OSError:
        return False


def category_of(rel_parts: tuple[str, ...], zone: Zone) -> str:
    """Catégorie d'un fichier selon son chemin relatif à sa zone."""
    lower = [p.lower() for p in rel_parts]
    if zone.kind == "profil":
        if lower and (lower[0] == "appdata" or (lower[0] == "library" and sys.platform == "darwin") or lower[0].startswith(".")):
            return "application"
        if any(p in APP_PARTS for p in lower[:-1]):
            return "application"
        return "personnel"
    if lower and lower[0] in ("program files", "program files (x86)", "programdata", "applications"):
        return "application"
    if any(p in APP_PARTS for p in lower[:-1]):
        return "application"
    return "personnel"


# --------------------------------------------------------------------------- parcours

def analyse(deadline: float, zone_list: list[Zone] | None = None) -> DiskAnalysis:
    """Un seul parcours : tailles par dossier (2 niveaux), gros fichiers, candidats aux doublons."""
    res = DiskAnalysis()
    for zone in zone_list or zones():
        root_cat = "application" if zone.kind == "racine" and _has_programs(zone.root) else None
        res.zone_roots[str(zone.root)] = zone.label
        stack: list[tuple[str, tuple[str, ...]]] = [(str(zone.root), ())]
        while stack:
            current, rel = stack.pop()
            try:
                it = os.scandir(current)
            except OSError:
                continue
            with it:
                for entry in it:
                    if time.monotonic() > deadline:
                        res.truncated = True
                        return res
                    try:
                        if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
                            continue
                        name_l = entry.name.lower()
                        if entry.is_dir(follow_symlinks=False):
                            if not rel and zone.kind == "disque" and name_l in DATA_DRIVE_SKIP:
                                continue
                            stack.append((entry.path, rel + (entry.name,)))
                            continue
                        if not rel and name_l in SYSTEM_FILES:
                            continue
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    res.files += 1
                    parts = rel + (entry.name,)
                    cat = root_cat or category_of(parts, zone)
                    if is_cloud_only(st):
                        res.cloud_only += 1
                        continue  # fichier OneDrive « en ligne uniquement » : n'occupe pas le disque, jamais ouvert
                    size = st.st_size
                    res.bytes_total += size
                    res.measured_by_drive[_drive_of(zone.root)] += size
                    # tailles cumulées : zone, puis 1er et 2e niveau de dossiers
                    for depth in range(0, min(len(rel), 2) + 1):
                        key = str(zone.root.joinpath(*rel[:depth])) if depth else str(zone.root)
                        res.folder_sizes[key] += size
                        res.folder_files[key] += 1
                        if depth:
                            prev = res.folder_category.get(key)
                            folder_cat = root_cat or category_of(rel[:depth] + ("x",), zone)
                            res.folder_category[key] = folder_cat if prev in (None, folder_cat) else "mixte"
                    if size >= LARGE_FILE_MIN:
                        heapq.heappush(res.largest, (size, entry.path, cat))
                        if len(res.largest) > TOP_FILES:
                            heapq.heappop(res.largest)
                    if cat == "personnel" and size >= DUP_MIN:
                        res.dup_by_size[size].append((entry.path, st.st_mtime))
    return res


def folder_size(path: Path, deadline: float) -> int | None:
    total = 0
    stack = [str(path)]
    while stack:
        if time.monotonic() > deadline:
            return None
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            st = e.stat(follow_symlinks=False)
                            if not is_cloud_only(st):
                                total += st.st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


# --------------------------------------------------------------------------- espace récupérable sans risque

def _glob_dirs(base: Path, pattern: str) -> list[Path]:
    try:
        return [p for p in base.glob(pattern) if p.is_dir()]
    except OSError:
        return []


def recoverable_locations() -> list[tuple[str, list[Path], str]]:
    """(nom, dossiers, comment le libérer sans risque)."""
    home = Path.home()
    if sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        roaming = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        browsers = []
        for vendor in ("Google/Chrome", "Microsoft/Edge", "BraveSoftware/Brave-Browser"):
            for prof in _glob_dirs(local / vendor / "User Data", "*"):
                browsers += [d for d in (prof / "Cache", prof / "Code Cache", prof / "GPUCache") if d.is_dir()]
        browsers += _glob_dirs(local / "Mozilla" / "Firefox" / "Profiles", "*/cache2")
        return [
            ("Fichiers temporaires de votre compte", [Path(os.environ.get("TEMP", local / "Temp"))],
             "Paramètres > Système > Stockage > Fichiers temporaires, ou Nettoyage de disque (cleanmgr)"),
            ("Caches des navigateurs", browsers,
             "Dans le navigateur : Paramètres > Confidentialité > Effacer les données de navigation > Images et fichiers en cache"),
            ("Rapports de plantage", [local / "CrashDumps", local / "Microsoft" / "Windows" / "WER"],
             "Nettoyage de disque (cleanmgr) > Rapports d'erreurs Windows"),
            ("Miniatures et caches Windows", [local / "Microsoft" / "Windows" / "Explorer"],
             "Nettoyage de disque (cleanmgr) > Miniatures"),
            ("Mises à jour Windows déjà installées", [Path(os.environ.get("SystemRoot", "C:/Windows")) / "SoftwareDistribution" / "Download"],
             "Nettoyage de disque (cleanmgr) > Nettoyer les fichiers système > Nettoyage de Windows Update"),
        ] + ([("Cache de Microsoft Teams (classique)", [roaming / "Microsoft" / "Teams" / "Cache"],
               "Quitter Teams puis supprimer ce dossier, ou utiliser la réparation de Teams")] if (roaming / "Microsoft" / "Teams" / "Cache").is_dir() else [])
    if sys.platform == "darwin":
        return [
            ("Caches des applications", [home / "Library" / "Caches"], "Quitter les applications, puis vider ~/Library/Caches"),
            ("Corbeille", [home / ".Trash"], "Finder > Vider la corbeille"),
            ("Journaux", [home / "Library" / "Logs"], "Supprimer les anciens journaux de ~/Library/Logs"),
        ]
    return [
        ("Caches des applications", [home / ".cache"], "Supprimer le contenu de ~/.cache (les applications le recréent)"),
        ("Corbeille", [home / ".local" / "share" / "Trash"], "Gestionnaire de fichiers > Corbeille > Vider"),
        ("Paquets téléchargés (apt)", [Path("/var/cache/apt/archives")], "sudo apt clean"),
        ("Journaux système", [Path("/var/log/journal")], "sudo journalctl --vacuum-size=200M"),
    ]


def recycle_bin_bytes() -> int | None:
    if sys.platform != "win32":
        return None
    from kmb_library.core.utils import run_ps

    out = run_ps("$s=0; (New-Object -ComObject Shell.Application).NameSpace(10).Items() | ForEach-Object { $s += $_.Size }; $s", timeout=60)
    digits = re.sub(r"\D", "", out)
    return int(digits) if digits else 0


def old_installers(downloads: Path, days: int = 30) -> tuple[int, int]:
    limit = time.time() - days * 86400
    total = count = 0
    try:
        for e in os.scandir(downloads):
            if e.is_file() and e.name.lower().endswith((".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".iso")):
                st = e.stat()
                if st.st_mtime < limit and not is_cloud_only(st):
                    total += st.st_size
                    count += 1
    except OSError:
        pass
    return total, count


def recoverable(deadline: float) -> list[dict]:
    items = []
    for name, folders, how in recoverable_locations():
        size = 0
        for f in folders:
            if f.is_dir():
                s = folder_size(f, deadline)
                size += s or 0
        if size:
            items.append({"name": name, "size_gb": round(size / GB, 2), "how": how,
                          "paths": [str(f) for f in folders if f.is_dir()][:5]})
    try:
        rb = recycle_bin_bytes()
    except Exception:  # noqa: BLE001 - la Corbeille est facultative
        rb = None
    if rb:
        items.append({"name": "Corbeille", "size_gb": round(rb / GB, 2), "how": "Clic droit sur la Corbeille > Vider la Corbeille", "paths": []})
    from kmb_library.core.fswalk import user_folders

    dl = user_folders().get("Téléchargements")
    if dl:
        size, count = old_installers(dl)
        if size:
            items.append({"name": f"Anciens installateurs dans Téléchargements ({count})", "size_gb": round(size / GB, 2),
                          "how": "Supprimer les fichiers .exe/.msi de plus d'un mois déjà installés", "paths": [str(dl)]})
    return sorted(items, key=lambda i: i["size_gb"], reverse=True)


# --------------------------------------------------------------------------- synthèse

def summarize(res: DiskAnalysis, partitions: list[dict] | None) -> dict:
    """Mise en forme pour le rapport (tailles en Go, catégories, estimation de la part système)."""
    def depth(path: str) -> int:
        for root in res.zone_roots:
            if path == root or path.startswith(root.rstrip("\\/") + os.sep):
                return len(Path(path).relative_to(root).parts)
        return 0

    folders = [
        {"path": path, "name": Path(path).name or path, "size_gb": round(size / GB, 2), "files": res.folder_files[path],
         "category": res.folder_category.get(path, "personnel"), "depth": depth(path)}
        for path, size in res.folder_sizes.items()
    ]
    # dossiers de 1er/2e niveau (pas les racines de zones) : les plus gros
    depth_dirs = [f for f in folders if f["path"] in res.folder_category and f["path"] not in res.zone_roots and f["size_gb"] >= 0.05]
    space = sorted(depth_dirs, key=lambda f: f["size_gb"], reverse=True)[:TOP_FOLDERS]
    zones_out = [{**f, "label": res.zone_roots[f["path"]]} for f in folders if f["path"] in res.zone_roots]
    large = [{"path": p, "size_gb": round(s / GB, 2), "category": c, "kind": kind_of(p)}
             for s, p, c in sorted(res.largest, reverse=True)]
    system_estimate = None
    if partitions:
        system_drive = (os.environ.get("SystemDrive", "C:") + "\\").upper() if sys.platform == "win32" else "/"
        part = next((p for p in partitions if str(p["mount"]).upper() == system_drive or p["mount"] in ("/", "/System/Volumes/Data")), None)
        if part:
            measured = res.measured_by_drive.get(_drive_of(Path(part["mount"])), 0) / GB
            system_estimate = round(max(part["used_gb"] - measured, 0), 1)
    return {
        "space_by_folder": space,
        "zones": sorted(({"label": z["label"], "path": z["path"], "size_gb": z["size_gb"]} for z in zones_out),
                        key=lambda z: z["size_gb"], reverse=True),
        "large_files": large,
        "files_scanned": res.files,
        "measured_gb": round(res.bytes_total / GB, 1),
        "cloud_only_files": res.cloud_only,
        "system_estimate_gb": system_estimate,
        "truncated": res.truncated,
    }


# --------------------------------------------------------------------------- applications

APP_MIN = 100 * MB


def apps_sizes(apps: list[dict], deadline: float, top: int = 25) -> list[dict]:
    """Taille réelle du dossier d'installation de chaque application (sinon taille déclarée)."""
    out, seen = [], set()
    for app in apps or []:
        loc = app.get("install_location")
        measured = None
        if loc and time.monotonic() < deadline:
            path = Path(loc)
            key = os.path.normcase(str(path))
            # on ignore les emplacements trop généraux (C:\, C:\Program Files) et ceux déjà mesurés
            if len(path.parts) > 2 and path.name.lower() not in ("program files", "program files (x86)") and key not in seen and path.is_dir():
                seen.add(key)
                measured = folder_size(path, deadline)
        size = measured if measured is not None else int((app.get("size_mb") or 0) * MB)
        if size >= APP_MIN:
            out.append({"name": app["name"], "version": app.get("version"), "size_gb": round(size / GB, 2),
                        "measured": measured is not None, "path": loc if measured is not None else None,
                        "category": "application"})
    return sorted(out, key=lambda a: a["size_gb"], reverse=True)[:top]
