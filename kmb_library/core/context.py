"""Options d'un scan, transmises à tous les collecteurs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanContext:
    check_updates: bool = True          # recherche des correctifs Windows manquants (API Windows Update)
    duplicates: bool = True             # recherche des fichiers en double
    duplicate_dirs: list[Path] = field(default_factory=list)  # vide = tout ce qui appartient à l'utilisateur
    storage_time_budget_s: int = 240    # temps maximal de l'analyse du disque (parcours + doublons), en secondes
    offline: bool = False               # pas d'appel à l'API endoflife.date (utilise le cache)
    cache_dir: Path | None = None
    verbose: bool = True
    display_name: str | None = None     # nom choisi pour ce PC dans le rapport (--nom)
    shared: dict = field(default_factory=dict)  # résultats intermédiaires partagés entre collecteurs
