"""Captures d'écran du tableau de bord avec Microsoft Edge (ou Chrome) en mode headless.

Usage (API démarrée) : python scripts/capturer_ecrans.py [--api http://127.0.0.1:8000] [--prefixe windows]
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "exemples" / "captures"
BROWSERS = [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe", "google-chrome", "chromium"]
PAGES = [("vue_ensemble", "/#overview", 1250), ("problemes", "/#findings", 1250), ("plan", "/#plan", 1250),
         ("performance_materiel", "/#performance", 1300), ("stockage", "/#storage", 1250),
         ("comparaison", "/#compare", 1100), ("rapport_pdf", "/scans/dernier/rapport.html", 1400), ("swagger", "/docs", 1500)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--prefixe", default="windows")
    ap.add_argument("--pages", nargs="*", help="Sous-ensemble de pages (noms)")
    args = ap.parse_args()
    browser = next((b for b in BROWSERS if Path(b).exists() or shutil.which(b)), None)
    if not browser:
        print("Edge ou Chrome introuvable.")
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    for i, (name, path, height) in enumerate(PAGES, start=1):
        if args.pages and name not in args.pages:
            continue
        target = OUT / f"{args.prefixe}_{i:02d}_{name}.png"
        subprocess.run([browser, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--virtual-time-budget=9000",
                        f"--window-size=1300,{height}", f"--screenshot={target}", args.api.rstrip("/") + path],
                       capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
        print(("OK  " if target.exists() else "ÉCHEC ") + target.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
