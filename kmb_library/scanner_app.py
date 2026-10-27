"""Point d'entrée du programme KMB-Scanner (double-clic, sans ligne de commande).

Pose deux questions simples, lance le scan, enregistre le rapport dans Documents\\KMB Library,
ouvre ce dossier et explique quoi faire ensuite. Construit en .exe par
`python scripts/construire_telechargements.py --exe` (non publié sur le site tant qu'il n'est pas signé).
"""

from __future__ import annotations

import platform
import sys
import traceback

from kmb_library import __version__

SITE_URL = ""  # adresse du site public, à renseigner au moment de l'hébergement


def _ask(question: str) -> str:
    try:
        return input(question).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def main() -> int:
    from kmb_library.cli import _load_env, _setup_console, open_folder, scan_and_save

    _setup_console()
    _load_env()
    print("=" * 64)
    print(f"  KMB Library {__version__} - examen de votre ordinateur")
    print("  Le scanner LIT des informations : il ne modifie rien.")
    print("=" * 64)
    print()
    nom = _ask(f"1) Quel nom donner à cet ordinateur dans le rapport ?\n   (Entrée = garder « {platform.node()} ») : ")
    masquer = _ask("2) Masquer vos informations personnelles (nom du PC, comptes, Wi-Fi) ? [o/N] : ").lower().startswith("o")
    print()
    try:
        _report, paths, base = scan_and_save(nom=nom or None, anonymiser=masquer)
    except Exception:  # noqa: BLE001 - message lisible pour l'utilisateur, détail pour le support
        print("\nLe scan n'a pas pu se terminer. Détail technique :")
        traceback.print_exc()
        _ask("\nAppuyez sur Entrée pour fermer...")
        return 1
    print("\n" + "=" * 64)
    print("  TERMINÉ !")
    print(f"  Votre rapport : {paths['rapport'].name}")
    print(f"  Dossier       : {base}")
    print()
    print("  ÉTAPE SUIVANTE : ouvrez le site KMB Library" + (f" ({SITE_URL})" if SITE_URL else ""))
    print("  cliquez sur « Analyser mon rapport » et choisissez ce fichier.")
    print("=" * 64)
    open_folder(base)
    _ask("\nAppuyez sur Entrée pour fermer...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
