"""Écriture et lecture des rapports, noms des fichiers et dossier de sortie.

Organisation par défaut (Documents\\KMB Library) :
    KMB-rapport_<PC>_<AAAA-MM-JJ>_<HHhMM>.json    LE rapport : seul fichier à téléverser, affiché par le site
    donnees-brutes/donnees-brutes_<PC>_<...>.json données collectées sans traitement (pour vérification)
    plans-ia/plan-ia_<id>.json                    plans de correction générés par l'IA (Groq ou xAI Grok)
    .cache/                                       réponses d'endoflife.date gardées 7 jours
Le scan ne produit volontairement aucun autre rapport (pas de HTML) : c'est le site qui présente le résultat.
Les anciens noms (rapport-traite_*, scan_*, raw_*) restent lisibles.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

from kmb_library.core.models import ScanReport

REPORT_PREFIX = "KMB-rapport_"
RAW_PREFIX = "donnees-brutes_"
AI_PREFIX = "plan-ia_"
RAW_DIR = "donnees-brutes"
AI_DIR = "plans-ia"
CACHE_DIR = ".cache"
LEGACY_REPORT_PREFIXES = ("rapport-traite_", "scan_")
LEGACY_AI_PREFIXES = ("plan_",)


def default_output_dir() -> Path:
    """Documents\\KMB Library (suit la redirection de Documents vers OneDrive sous Windows).

    La variable d'environnement KMB_SORTIE permet de choisir un autre dossier.
    """
    if os.environ.get("KMB_SORTIE"):
        return Path(os.environ["KMB_SORTIE"])
    docs = Path.home() / "Documents"
    if sys.platform == "win32":
        try:
            from kmb_library.core.utils import read_reg

            value = read_reg("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "Personal")
            if value:
                docs = Path(os.path.expandvars(value))
        except Exception:  # noqa: BLE001 - repli sur ~/Documents
            pass
    base = docs if docs.is_dir() else Path.home()
    return base / "KMB Library"


def _safe(text: str) -> str:
    """Nom de PC utilisable dans un nom de fichier (lettres, chiffres, tirets)."""
    cleaned = re.sub(r"[^\w\-]+", "-", text.strip(), flags=re.UNICODE).strip("-")
    return cleaned[:40] or "PC"


def file_stem(report: ScanReport) -> str:
    """Partie lisible commune aux fichiers d'un scan : <PC>_<AAAA-MM-JJ>_<HHhMM>."""
    try:
        when = datetime.fromisoformat(report.scan_date)
    except ValueError:
        when = datetime.now()
    return f"{_safe(report.display_name or report.machine_name)}_{when:%Y-%m-%d}_{when:%Hh%M}"


def _unique(path: Path) -> Path:
    """Évite d'écraser un fichier : ajoute _2, _3… si deux scans tombent dans la même minute."""
    if not path.exists():
        return path
    n = 2
    while (candidate := path.with_name(f"{path.stem}_{n}{path.suffix}")).exists():
        n += 1
    return candidate


def report_filename(report: ScanReport) -> str:
    return f"{REPORT_PREFIX}{file_stem(report)}.json"


def ai_plan_name(scan_id: str) -> str:
    return f"{AI_PREFIX}{scan_id}.json"


def save_scan(raw: dict, report: ScanReport, out_dir: Path) -> dict[str, Path]:
    """Enregistre les fichiers d'un scan et retourne leurs chemins."""
    out_dir = Path(out_dir)
    (out_dir / RAW_DIR).mkdir(parents=True, exist_ok=True)
    report_path = _unique(out_dir / report_filename(report))
    stem = report_path.stem.removeprefix(REPORT_PREFIX)
    report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    raw_path = out_dir / RAW_DIR / f"{RAW_PREFIX}{stem}.json"
    raw_path.write_text(json.dumps(raw, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return {"rapport": report_path, "brut": raw_path}


def load_report(path: Path) -> ScanReport:
    return ScanReport.model_validate_json(Path(path).read_text(encoding="utf-8"))
