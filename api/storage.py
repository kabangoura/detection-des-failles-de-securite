"""Stockage des rapports en fichiers JSON (pas de base de données) pour l'API locale.

<dossier de données>/KMB-rapport_<PC>_<date>.json : rapports (produits par `kmb scan --sortie data` ou reçus par POST /scans)
<dossier de données>/plans-ia/plan-ia_<id>.json     : plans de correction générés par l'IA (Groq ou xAI Grok)
Les rapports aux anciens emplacements et noms (processed/rapport-traite_*, processed/scan_*) sont toujours lus.
Les fichiers sont relus seulement s'ils ont changé (cache par date de modification).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from kmb_library.core.models import ScanReport
from kmb_library.reports.json_report import (AI_DIR, AI_PREFIX, LEGACY_AI_PREFIXES, LEGACY_REPORT_PREFIXES,
                                             REPORT_PREFIX, ai_plan_name, report_filename)

_SAFE_ID = re.compile(r"^[A-Za-z0-9_\-]{1,80}$")


class ScanStore:
    def __init__(self, data_dir: Path):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ai_dir = self.dir / AI_DIR
        self._legacy_ai_dir = self.dir / "processed" / "ai"
        self._cache: dict[Path, tuple[float, ScanReport]] = {}

    @staticmethod
    def valid_id(scan_id: str) -> bool:
        return bool(_SAFE_ID.match(scan_id))

    def _candidates(self) -> list[Path]:
        files = []
        for prefix in LEGACY_REPORT_PREFIXES:
            files += self.dir.joinpath("processed").glob(f"{prefix}*.json")
        files += self.dir.glob(f"{REPORT_PREFIX}*.json")  # en dernier : le nom actuel l'emporte
        return files

    def _load(self, path: Path) -> ScanReport | None:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        cached = self._cache.get(path)
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            report = ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None  # fichier corrompu ou d'un autre format : ignoré
        self._cache[path] = (mtime, report)
        return report

    def _index(self) -> dict[str, tuple[Path, ScanReport]]:
        found: dict[str, tuple[Path, ScanReport]] = {}
        for p in self._candidates():
            if r := self._load(p):
                found[r.scan_id] = (p, r)
        return found

    def all(self) -> list[ScanReport]:
        return sorted((r for _, r in self._index().values()), key=lambda r: r.scan_date, reverse=True)

    def get(self, scan_id: str) -> ScanReport | None:
        if scan_id == "dernier":
            reports = self.all()
            return reports[0] if reports else None
        if not self.valid_id(scan_id):
            return None
        hit = self._index().get(scan_id)
        return hit[1] if hit else None

    def exists(self, scan_id: str) -> bool:
        return scan_id in self._index()

    def save(self, report: ScanReport) -> Path:
        path = self.dir / report_filename(report)
        n = 2
        while path.exists():
            path = self.dir / report_filename(report).replace(".json", f"_{n}.json")
            n += 1
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        return path

    def delete(self, scan_id: str) -> bool:
        hit = self._index().get(scan_id) if self.valid_id(scan_id) else None
        if not hit:
            return False
        hit[0].unlink(missing_ok=True)
        hit[0].with_suffix(".html").unlink(missing_ok=True)
        self._cache.pop(hit[0], None)
        for d, prefixes in ((self.ai_dir, (AI_PREFIX,)), (self._legacy_ai_dir, (AI_PREFIX,) + LEGACY_AI_PREFIXES)):
            for prefix in prefixes:
                (d / f"{prefix}{scan_id}.json").unlink(missing_ok=True)
        return True

    def get_ai_plan(self, scan_id: str) -> dict | None:
        if not self.valid_id(scan_id):
            return None
        for d, prefixes in ((self.ai_dir, (AI_PREFIX,)), (self._legacy_ai_dir, (AI_PREFIX,) + LEGACY_AI_PREFIXES)):
            for prefix in prefixes:
                path = d / f"{prefix}{scan_id}.json"
                if path.exists():
                    return json.loads(path.read_text(encoding="utf-8"))
        return None

    def save_ai_plan(self, scan_id: str, plan: dict) -> None:
        self.ai_dir.mkdir(parents=True, exist_ok=True)
        (self.ai_dir / ai_plan_name(scan_id)).write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
