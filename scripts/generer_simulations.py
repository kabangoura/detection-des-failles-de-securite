"""Produit des rapports Linux et macOS SIMULÉS à partir des données brutes de tests/fixtures/.

Ces rapports ne proviennent pas de vraies machines : ils servent à montrer la vue et l'API
multiplateformes. Le traitement (règles, enrichissement endoflife.date, scores) est le vrai.
Usage : python scripts/generer_simulations.py   -> exemples/simulations/KMB-rapport_*.json
"""

from __future__ import annotations

import json
from pathlib import Path

from kmb_library.core.context import ScanContext
from kmb_library.core.runner import process
from kmb_library.reports.json_report import report_filename

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "exemples" / "simulations"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    ctx = ScanContext(cache_dir=ROOT / "data" / "cache" / "endoflife")
    for name, label in (("raw_linux.json", "SIMULATION-LINUX"), ("raw_macos.json", "SIMULATION-MACOS")):
        raw = json.loads((ROOT / "tests" / "fixtures" / name).read_text(encoding="utf-8"))
        raw["collectors"]["system"]["data"]["hostname"] = label
        report = process(raw, ctx)
        path = OUT / report_filename(report)
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        print(f"{label}: score {report.scores['global']}/100, {report.summary['total']} problèmes -> {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
