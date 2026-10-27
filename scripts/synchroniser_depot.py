"""Copie le Livrable 2 dans le dépôt GitHub public (copie locale du dépôt), sans rien de privé.

Usage : python scripts/synchroniser_depot.py CHEMIN_DU_DEPOT

- Seule la liste AUTORISE est copiée : code, tests, site, outils, description du paquet.
  Ne partent jamais : conversations, notes de cours, data/ (rapports réels), .env (clé de l'IA), dist/ (.exe, paquets).
- Le dépôt devient le miroir exact de cette liste (un fichier supprimé ici est supprimé là-bas) ;
  .git et le README du dépôt (README-depot.md) sont gérés à part.
- Avant de terminer, tous les fichiers texte copiés sont contrôlés : si une donnée personnelle est trouvée,
  le script s'arrête avec une erreur et rien ne doit être envoyé.
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTORISE = ["kmb_library", "api", "tests", "web", "scripts", ".github", "pyproject.toml", "README-pypi.md",
            "requirements.txt", ".env.example", ".gitignore"]
EXCLU = ("__pycache__", ".pyc", ".egg-info", ".pytest_cache", ".exe")
# Données personnelles à rechercher (nom du poste, compte, courriel, IP…) : une expression par ligne dans
# .donnees-personnelles, fichier qui reste sur le poste (il n'est pas dans AUTORISE, donc jamais publié).
LISTE_PERSO = ROOT / ".donnees-personnelles"
TEXTE = {".py", ".md", ".json", ".toml", ".txt", ".html", ".css", ".js", ".yml", ".yaml", ".xml", ".example", ".gitignore", ".svg"}


def supprimer(p: Path) -> None:
    """Supprime un fichier ou un dossier. OneDrive verrouille parfois un dossier vide : sans effet pour Git, on l'ignore."""
    if p.is_dir():
        shutil.rmtree(p, onexc=lambda fn, path, exc: None if fn.__name__ == "rmdir" else (_ for _ in ()).throw(exc))
        restants = [f for f in p.rglob("*") if f.is_file()] if p.exists() else []
        if restants:
            raise SystemExit(f"Impossible de vider {p} : {restants[0]}")
    elif p.exists():
        p.unlink()


def copier(dest: Path) -> list[Path]:
    copies = []
    for nom in AUTORISE:
        src, cible = ROOT / nom, dest / nom
        supprimer(cible)
        if src.is_file():
            shutil.copy2(src, cible)
            copies.append(cible)
            continue
        for f in src.rglob("*"):
            rel = f.relative_to(ROOT)
            if f.is_file() and not any(x in str(rel) for x in EXCLU):
                (dest / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest / rel)
                copies.append(dest / rel)
    shutil.copy2(ROOT / "README-depot.md", dest / "README.md")
    copies.append(dest / "README.md")
    return copies


def nettoyer(dest: Path) -> None:
    """Retire du dépôt ce qui n'est plus dans la liste (ancienne organisation : site à la racine)."""
    garder = set(AUTORISE) | {".git", "README.md"}
    for f in dest.iterdir():
        if f.name not in garder:
            supprimer(f)


def controler(fichiers: list[Path]) -> list[str]:
    motifs = [m.strip() for m in LISTE_PERSO.read_text(encoding="utf-8").splitlines() if m.strip() and not m.startswith("#")]
    perso = re.compile("|".join(motifs), re.I)
    alertes = []
    for f in fichiers:
        if f.suffix.lower() in TEXTE or f.name in {".gitignore", ".env.example"}:
            for n, ligne in enumerate(f.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if perso.search(ligne):
                    alertes.append(f"{f}:{n}: {ligne.strip()[:100]}")
    return alertes


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    dest = Path(sys.argv[1]).resolve()
    if not (dest / ".git").is_dir():
        raise SystemExit(f"{dest} n'est pas une copie locale d'un dépôt Git.")
    if not LISTE_PERSO.exists():
        raise SystemExit(f"Liste des données personnelles absente ({LISTE_PERSO}) : contrôle impossible, rien n'est copié.")
    nettoyer(dest)
    fichiers = copier(dest)
    alertes = controler(fichiers)
    if alertes:
        print("DONNÉES PERSONNELLES TROUVÉES : ne rien envoyer.")
        print("\n".join(alertes))
        raise SystemExit(1)
    print(f"{len(fichiers)} fichiers copiés vers {dest}, aucune donnée personnelle trouvée.")
