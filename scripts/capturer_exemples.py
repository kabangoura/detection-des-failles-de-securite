"""Enregistre des appels représentatifs de l'API et leurs réponses dans exemples/appels_api/.

Usage (API démarrée) :  python scripts/capturer_exemples.py [--api http://127.0.0.1:8000]
Sert de preuve de fonctionnement des endpoints, de leurs paramètres et des cas limites.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import httpx

OUT = Path(__file__).resolve().parent.parent / "exemples" / "appels_api"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    api = args.api.rstrip("/")

    scans = httpx.get(f"{api}/scans?limit=200").json()["resultats"]
    if len(scans) < 2:
        print("Il faut au moins deux scans (avant / après) dans data/processed.")
        return 1
    new, old = scans[0]["scan_id"], scans[-1]["scan_id"]

    calls = [
        ("01_liste_scans", "GET", "/scans?limit=10"),
        ("02_liste_scans_filtre_sans_resultat", "GET", "/scans?machine=inexistant"),
        ("03_liste_scans_dates_invalides", "GET", "/scans?date_min=2026-12-01&date_max=2026-01-01"),
        ("04_detail_scan", "GET", f"/scans/{new}"),
        ("05_scan_introuvable", "GET", "/scans/abc123"),
        ("06_problemes_critiques_et_eleves", "GET", f"/scans/{new}/findings?severite=critique&severite=eleve"),
        ("07_problemes_domaine_logiciels", "GET", f"/scans/{new}/findings?domaine=logiciels"),
        ("08_controles_non_verifiables", "GET", f"/scans/{new}/findings?statut=non_verifiable"),
        ("09_gravite_invalide", "GET", f"/scans/{new}/findings?severite=enorme"),
        ("10_recherche_sans_resultat", "GET", f"/scans/{new}/findings?recherche=zzzz"),
        ("11_logiciels_fin_de_support", "GET", f"/scans/{new}/logiciels?cycle_de_vie=fin_de_support"),
        ("12_logiciels_recherche", "GET", f"/scans/{new}/logiciels?recherche=node"),
        ("13_comparaison_avant_apres", "GET", f"/comparaison?ancien={old}&nouveau={new}"),
        ("14_comparaison_meme_scan", "GET", f"/comparaison?ancien={new}&nouveau={new}"),
        ("15_statistiques", "GET", "/statistiques"),
        ("16_connaissance_smbv1", "GET", "/connaissances/NET-001"),
        ("17_plan_ia", "POST", f"/scans/{new}/plan-ia"),
        ("18_scans_par_systeme", "GET", "/scans?systeme=windows"),
        ("19_systeme_invalide", "GET", "/scans?systeme=bsd"),
        ("20_problemes_wifi", "GET", f"/scans/{new}/findings?categorie=Wi-Fi&statut=tous"),
        ("21_sante", "GET", "/sante"),
    ]
    OUT.mkdir(parents=True, exist_ok=True)
    for name, method, path in calls:
        r = httpx.request(method, api + path, timeout=180)
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text[:500]
        doc = {"requete": f"{method} {path}", "statut_http": r.status_code, "reponse": body}
        (OUT / f"{name}.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"{r.status_code}  {method} {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
