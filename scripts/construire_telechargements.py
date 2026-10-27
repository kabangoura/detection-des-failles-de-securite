"""Prépare les fichiers téléchargeables du site (web/telechargements/).

Usage :
    python scripts/construire_telechargements.py          # kmb-library.zip (installation avec Python, voir le guide)
    python scripts/construire_telechargements.py --exe    # + KMB-Scanner.exe (Windows, nécessite : pip install pyinstaller)

Le ZIP contient le code directement à sa racine : « Extraire tout » sous Windows donne un dossier
kmb-library prêt pour `pip install .`.
Le programme .exe n'est pas proposé sur le site : non signé, il déclenche les avertissements de
SmartScreen. Il reste disponible pour une distribution future (signature de code ou Microsoft Store).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOWNLOADS = ROOT / "web" / "telechargements"
BUILD = Path(tempfile.gettempdir()) / "kmb-scanner-build"
ZIP_CONTENT = ["kmb_library", "api", "web", "tests", "scripts", "pyproject.toml", "requirements.txt", "README.md", "README-pypi.md", ".env.example"]
ZIP_EXCLUDE = ("__pycache__", ".pyc", "telechargements", "egg-info")


def build_zip() -> Path:
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    target = DOWNLOADS / "kmb-library.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for item in ZIP_CONTENT:
            path = ROOT / item
            if not path.exists():
                continue
            files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
            for f in files:
                rel = f.relative_to(ROOT)
                if not any(x in str(rel) for x in ZIP_EXCLUDE):
                    z.write(f, rel)
    return target


def build_exe() -> Path:
    entry = ROOT / "kmb_library" / "scanner_app.py"
    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--console",
        "--name", "KMB-Scanner",
        "--add-data", f"{ROOT / 'kmb_library' / 'rules' / 'knowledge_base.json'};kmb_library/rules",
        "--collect-submodules", "kmb_library",
        "--paths", str(ROOT),  # la librairie de CE livrable, pas une autre version installée
        # Fichiers temporaires hors du projet : OneDrive verrouille sinon le dossier de construction
        "--distpath", str(ROOT / "dist"), "--workpath", str(BUILD), "--specpath", str(BUILD),
        str(entry),
    ]
    subprocess.run(cmd, check=True, cwd=ROOT)
    return ROOT / "dist" / "KMB-Scanner.exe"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", action="store_true", help="Construire aussi dist/KMB-Scanner.exe (Windows)")
    args = ap.parse_args()
    print("Code (ZIP) :", build_zip())
    if args.exe:
        if sys.platform != "win32":
            print("Le programme .exe se construit sous Windows.")
        else:
            print("Programme :", build_exe(), "(non publié sur le site)")
