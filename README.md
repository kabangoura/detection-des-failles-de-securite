# KMB Library · détection des failles de sécurité

**KMB Library** vérifie gratuitement la sécurité, les logiciels, la performance et le stockage d'un ordinateur
(Windows 10/11, Linux, macOS), puis explique quoi corriger, étape par étape.

- **Site et guide :** https://kabangoura.github.io/detection-des-failles-de-securite/
- **Installation :** `python -m pip install kmb-library` ([PyPI](https://pypi.org/project/kmb-library/))
- **Scan :** `python -m kmb_library scan` ; le rapport `KMB-rapport_….json` s'ouvre sur le site avec « Analyser mon rapport »,
  qui le lit dans le navigateur sans l'envoyer.

## Contenu du dépôt

| Dossier / fichier | Rôle |
|---|---|
| `kmb_library/` | la librairie : collecte (Windows, Linux, macOS), règles, scores, rapport JSON |
| `api/` | API FastAPI (mode serveur du site) |
| `web/` | le site public, publié sur GitHub Pages |
| `tests/` | tests automatiques (`pytest`) |
| `scripts/` | outils du projet : catalogue des commandes de correction, ZIP du site, simulations |
| `pyproject.toml`, `README-pypi.md` | description du paquet publié sur PyPI |
| `.github/workflows/` | automatisations GitHub : publication du site |

## Développement

```
python -m venv .venv
.venv\Scripts\activate            (Linux / macOS : source .venv/bin/activate)
python -m pip install -e ".[dev]"
python -m pytest
```

Projet scolaire. Les rapports personnels, la clé de l'IA (`.env`) et les documents de cours ne sont pas dans ce dépôt.
