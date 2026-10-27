"""Interface en ligne de commande : kmb scan | comparer | envoyer | plan-ia | version."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from kmb_library import __version__


def _setup_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _load_env() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(Path.cwd() / ".env")
    except ImportError:
        pass


def open_folder(path: Path) -> None:
    """Ouvre le dossier des rapports dans l'explorateur (sans effet en intégration continue)."""
    import os
    import subprocess

    if os.environ.get("CI"):
        return
    try:
        if sys.platform == "win32":
            os.startfile(str(path))  # noqa: S606 - ouverture volontaire du dossier de l'utilisateur
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


def scan_and_save(sortie: str | None = None, nom: str | None = None, anonymiser: bool = False, dossiers=None,
                  sans_doublons: bool = False, sans_maj: bool = False, hors_ligne: bool = False, budget: int = 240):
    """Lance un scan complet et enregistre les fichiers. Utilisé par `kmb scan` et par KMB-Scanner.exe."""
    from kmb_library.core.context import ScanContext
    from kmb_library.core.runner import run_scan
    from kmb_library.reports.json_report import CACHE_DIR, default_output_dir, save_scan

    base = Path(sortie) if sortie else default_output_dir()
    ctx = ScanContext(
        check_updates=not sans_maj,
        duplicates=not sans_doublons,
        duplicate_dirs=[Path(d) for d in dossiers or []],
        storage_time_budget_s=budget,
        offline=hors_ligne,
        cache_dir=base / CACHE_DIR / "endoflife",
        display_name=nom,
    )
    from kmb_library.enrich.pypi import newer_version

    nouvelle = newer_version(__version__, base / CACHE_DIR / "pypi.json", offline=hors_ligne)
    maj = f"Nouvelle version {nouvelle} disponible : python -m pip install --upgrade kmb-library" if nouvelle else ""
    if maj:
        print(maj + "\n")
    print(f"KMB Library {__version__} - scan du poste en cours (3 à 5 minutes : tout votre espace disque est examiné)...")
    raw, report = run_scan(ctx, anonymized=anonymiser, progress=lambda m: print("  - " + m))
    paths = save_scan(raw, report, base)

    s, n = report.scores, report.summary
    print("\nRésultat")
    print(f"  Ordinateur : {report.display_name or report.machine_name}"
          + (f" ({report.device_model})" if report.device_model else ""))
    print(f"  Score global : {s['global']}/100  (sécurité {s['securite']}, performance {s['performance']}, "
          f"stockage {s['stockage']}, logiciels {s['logiciels']})")
    print(f"  Problèmes : {n['critique']} critique(s), {n['eleve']} élevé(s), {n['moyen']} moyen(s), "
          f"{n['faible']} faible(s), {n['info']} info - {n['non_verifiables']} contrôle(s) non vérifiable(s)")
    for p in report.plan[:5]:
        print(f"   {p.priority}. [{p.severity}] {p.title}  ({p.gain})")
    if not report.is_admin:
        tip = "lancer « en tant qu'administrateur »" if sys.platform == "win32" else "relancer avec sudo"
        print(f"  Astuce : {tip} pour vérifier tous les contrôles ({n['non_verifiables']} non vérifiables).")
    print(f"\nDossier des rapports : {base}")
    print(f"  Votre rapport (à téléverser sur le site KMB Library) : {paths['rapport'].name}")
    print(f"  Données de départ (vérification seulement)           : {paths['brut'].relative_to(base)}")
    if maj:
        print("\n" + maj)
    return report, paths, base


def cmd_scan(args: argparse.Namespace) -> int:
    from kmb_library.collectors import detect_os_family

    if detect_os_family() == "unsupported":
        print(f"Système non pris en charge : {sys.platform} (Windows, Linux et macOS seulement).")
        return 2
    _report, paths, base = scan_and_save(args.sortie, args.nom, args.anonymiser, args.dossiers, args.sans_doublons,
                                         args.sans_maj, args.hors_ligne, 60 if args.rapide else args.budget)
    if not args.sans_ouvrir:
        open_folder(base)
    if args.envoyer:
        return _send(paths["rapport"], args.envoyer)
    return 0


def _send(path: Path, api: str) -> int:
    import httpx

    body = json.loads(Path(path).read_text(encoding="utf-8"))
    try:
        r = httpx.post(api.rstrip("/") + "/scans", json=body, timeout=30)
    except httpx.HTTPError as exc:
        print(f"Envoi impossible : {exc}")
        return 1
    print(f"Envoi vers {api} : HTTP {r.status_code} - {r.json().get('detail', r.json().get('message', ''))}")
    return 0 if r.status_code in (200, 201, 409) else 1


def cmd_send(args: argparse.Namespace) -> int:
    return _send(Path(args.rapport), args.api)


def cmd_compare(args: argparse.Namespace) -> int:
    from kmb_library.core.compare import compare_reports
    from kmb_library.reports.json_report import load_report

    result = compare_reports(load_report(Path(args.ancien)), load_report(Path(args.nouveau)))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    r = result["resume"]
    print(f"Corrigés : {r['corriges']} | Restants : {r['restants']} | Nouveaux : {r['nouveaux']} | Non vérifiables : {r['non_verifiables']}")
    for label, key in (("CORRIGÉS", "corriges"), ("RESTANTS", "restants"), ("NOUVEAUX", "nouveaux")):
        print(f"\n{label}")
        for f in result[key]:
            print(f"  - {f['key']} [{f['severity']}] {f['title']}")
    print("\nÉvolution des scores : " + ", ".join(f"{k} {v:+d}" for k, v in result["evolution_scores"].items()))
    for w in result["avertissements"]:
        print("Attention : " + w)
    return 0


def cmd_ai(args: argparse.Namespace) -> int:
    from kmb_library.ai.assistant import AIError, generate_plan
    from kmb_library.reports.json_report import load_report

    try:
        plan = generate_plan(load_report(Path(args.rapport)), model=args.modele)
    except AIError as exc:
        print(f"Erreur : {exc}")
        return 1
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kmb", description="KMB Library - audit de poste de travail (Windows, Linux, macOS)")
    sub = p.add_subparsers(dest="commande", required=True)

    s = sub.add_parser("scan", help="Scanner ce poste et produire les rapports")
    s.add_argument("-o", "--sortie", default=None,
                   help="Dossier des rapports (défaut : Documents/KMB Library ; « data » pour l'API locale)")
    s.add_argument("--nom", help="Nom à afficher pour ce PC dans le rapport (ex. \"PC de Marie\")")
    s.add_argument("--sans-ouvrir", action="store_true", help="Ne pas ouvrir le dossier des rapports à la fin")
    s.add_argument("--dossiers", nargs="+", help="Dossiers à analyser pour les doublons (défaut : dossiers personnels)")
    s.add_argument("--sans-doublons", action="store_true", help="Ne pas chercher les doublons")
    s.add_argument("--sans-maj", action="store_true", help="Ne pas interroger Windows Update (plus rapide)")
    s.add_argument("--hors-ligne", action="store_true", help="Ne pas appeler endoflife.date (utilise le cache)")
    s.add_argument("--anonymiser", action="store_true", help="Masquer machine, comptes, IP et chemins personnels")
    s.add_argument("--budget", type=int, default=240, help="Secondes max. pour l'analyse du disque (défaut 240 = 4 min)")
    s.add_argument("--rapide", action="store_true", help="Analyse du disque limitée à 1 minute (résultats moins complets)")
    s.add_argument("--envoyer", metavar="URL_API", help="Envoyer le rapport à l'API (ex. http://127.0.0.1:8000)")
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("comparer", help="Comparer deux rapports JSON (avant / après correction)")
    c.add_argument("ancien")
    c.add_argument("nouveau")
    c.add_argument("--json", action="store_true", help="Sortie JSON complète")
    c.set_defaults(func=cmd_compare)

    e = sub.add_parser("envoyer", help="Téléverser un rapport JSON vers l'API")
    e.add_argument("rapport")
    e.add_argument("--api", default="http://127.0.0.1:8000")
    e.set_defaults(func=cmd_send)

    a = sub.add_parser("plan-ia", help="Générer un plan de correction avec l'IA (Groq, ou xAI Grok)")
    a.add_argument("rapport")
    a.add_argument("--modele", help="Modèle à utiliser (défaut : KMB_IA_MODELE, sinon les modèles du fournisseur dans l'ordre)")
    a.set_defaults(func=cmd_ai)

    v = sub.add_parser("version", help="Afficher la version")
    v.set_defaults(func=lambda a: print(f"KMB Library {__version__}") or 0)
    return p


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    _load_env()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
