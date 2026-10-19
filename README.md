# Détection des failles de sécurité · KMB Library

Site public de **KMB Library** : vérifiez gratuitement la sécurité, les logiciels, la performance et le stockage de votre ordinateur (Windows, Linux, macOS).

**Site :** https://kabangoura.github.io/detection-des-failles-de-securite/

1. Suivez le **Guide d'installation** du site : installez Python, puis KMB avec `python -m pip install kmb-library` ([PyPI](https://pypi.org/project/kmb-library/)).
2. Lancez `python -m kmb_library scan`. Votre rapport `KMB-rapport_….json` est créé dans *Documents/KMB Library*.
3. Sur le site, cliquez sur **Analyser mon rapport** et choisissez ce fichier.

Le rapport est lu **dans votre navigateur** : il n'est ni envoyé ni conservé.

| Fichier | Rôle |
|---|---|
| `index.html`, `style.css`, `app.js` | le site (guide + analyse du rapport dans le navigateur) |
| `config.js` | réglages (adresse du code à installer, exemple) |
| `telechargements/kmb-library.zip` | code de KMB Library (l'installation se fait depuis PyPI : `python -m pip install kmb-library`) |
| `exemple/KMB-rapport_exemple.json` | rapport d'exemple anonymisé |
| `sitemap.xml`, `llms.txt` | référencement : liste des pages pour les moteurs de recherche, résumé pour les assistants IA |
| `og-image.png`, `icon-512.png`, `favicon.svg` | image d'aperçu de partage et icônes |
