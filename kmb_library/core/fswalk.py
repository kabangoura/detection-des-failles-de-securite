"""Parcours de dossiers borné dans le temps, sans déclencher le téléchargement des fichiers cloud."""

from __future__ import annotations

import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# Attributs Windows d'un fichier « en ligne uniquement » (OneDrive, etc.)
_CLOUD_ATTRS = 0x00400000 | 0x00040000 | 0x00001000  # RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "$recycle.bin", "appdata", "packagecache",
              "temp", ".cache", ".trash", ".local"}


@dataclass
class FileEntry:
    path: str
    size: int
    mtime: float
    cloud_only: bool


@dataclass
class WalkState:
    files: int = 0
    truncated: bool = False


def is_cloud_only(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & _CLOUD_ATTRS)


def walk_files(roots: list[Path], deadline: float, state: WalkState) -> Iterator[FileEntry]:
    """Itère sur les fichiers des dossiers `roots` jusqu'à l'échéance `deadline` (time.monotonic)."""
    stack = [str(r) for r in roots if r and Path(r).is_dir()]
    visited: set[str] = set()
    while stack:
        current = stack.pop()
        key = os.path.normcase(current)
        if key in visited:
            continue
        visited.add(key)
        try:
            it = os.scandir(current)
        except OSError:
            continue
        with it:
            for entry in it:
                if time.monotonic() > deadline:
                    state.truncated = True
                    return
                try:
                    if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name.lower() not in _SKIP_DIRS:
                            stack.append(entry.path)
                        continue
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                state.files += 1
                yield FileEntry(entry.path, st.st_size, st.st_mtime, is_cloud_only(st))


_XDG = {"XDG_DESKTOP_DIR": "Bureau", "XDG_DOCUMENTS_DIR": "Documents", "XDG_DOWNLOAD_DIR": "Téléchargements",
        "XDG_PICTURES_DIR": "Images", "XDG_VIDEOS_DIR": "Vidéos", "XDG_MUSIC_DIR": "Musique"}


def parse_xdg_user_dirs(text: str, home: Path) -> dict[str, Path]:
    """Lit ~/.config/user-dirs.dirs (Linux), ex. XDG_DOWNLOAD_DIR="$HOME/Téléchargements"."""
    out = {}
    for line in text.splitlines():
        m = re.match(r'\s*(XDG_\w+_DIR)\s*=\s*"(.*)"', line)
        if m and m.group(1) in _XDG:
            out[_XDG[m.group(1)]] = Path(m.group(2).replace("$HOME", str(home)))
    return out


def user_folders() -> dict[str, Path]:
    """Dossiers personnels réels : registre (Windows, gère OneDrive), XDG (Linux), standards (macOS)."""
    home = Path.home()
    folders = {
        "Bureau": home / "Desktop",
        "Documents": home / "Documents",
        "Téléchargements": home / "Downloads",
        "Images": home / "Pictures",
        "Vidéos": home / ("Movies" if sys.platform == "darwin" else "Videos"),
        "Musique": home / "Music",
    }
    try:
        if sys.platform == "win32":
            from kmb_library.core.utils import read_reg

            reg = read_reg("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") or {}
            mapping = {
                "Bureau": "Desktop", "Documents": "Personal", "Images": "My Pictures", "Vidéos": "My Video",
                "Musique": "My Music", "Téléchargements": "{374DE290-123F-4565-9164-39C4925E467B}",
            }
            for label, value in mapping.items():
                if reg.get(value):
                    folders[label] = Path(os.path.expandvars(reg[value]))
        elif sys.platform.startswith("linux"):
            cfg = home / ".config" / "user-dirs.dirs"
            if cfg.exists():
                folders.update(parse_xdg_user_dirs(cfg.read_text(encoding="utf-8", errors="replace"), home))
    except Exception:  # noqa: BLE001 - repli sur les chemins par défaut
        pass
    return {k: v for k, v in folders.items() if v.is_dir()}
