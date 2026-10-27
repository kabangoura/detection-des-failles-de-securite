![KMB Library : audit gratuit de votre ordinateur](https://kabangoura.github.io/detection-des-failles-de-securite/og-image.png)

# KMB Library

**KMB Library vérifie gratuitement la sécurité, les logiciels, la performance et le stockage de votre ordinateur**
(Windows 10/11, Linux, macOS), puis explique **simplement** quoi corriger, étape par étape.

Le scan **ne modifie rien** sur l'ordinateur. Il produit un rapport que vous ouvrez sur le site
**[KMB Library](https://kabangoura.github.io/detection-des-failles-de-securite/)** : le rapport est lu par votre navigateur,
**rien n'est envoyé**.

## Installation

Il faut Python 3.10 ou plus récent ([python.org](https://www.python.org/downloads/) ; sous Windows, cochez « Add python.exe to PATH »).

```
python -m pip install kmb-library
```

Linux et macOS (dans un environnement à part, sans toucher au Python du système) :

```
python3 -m venv ~/.kmb
~/.kmb/bin/python -m pip install kmb-library
```

## Utilisation

```
python -m kmb_library scan
```

Le scan dure 3 à 5 minutes. À la fin, le dossier **Documents/KMB Library** s'ouvre : votre rapport s'appelle
`KMB-rapport_<ordinateur>_<date>_<heure>.json`. Ouvrez le site, cliquez sur **Analyser mon rapport** et choisissez ce fichier.

Pour un examen complet, lancez la même commande depuis une invite de commandes ouverte **en tant qu'administrateur**
(ou avec `sudo` sous Linux / macOS).

| Commande | Rôle |
|---|---|
| `python -m kmb_library scan` | scanner l'ordinateur et créer le rapport |
| `python -m kmb_library scan --rapide` | analyse du disque limitée à 1 minute |
| `python -m kmb_library comparer ANCIEN.json NOUVEAU.json` | comparer deux rapports (avant / après vos corrections) |
| `python -m kmb_library version` | afficher la version |
| `python -m pip install --upgrade kmb-library` | mettre KMB à jour |
| `python -m pip uninstall kmb-library` | désinstaller KMB |

## Ce que KMB vérifie

- **Système** : fin de support, mises à jour de sécurité en attente
- **Protection** : antivirus, pare-feu, chiffrement du disque (BitLocker, FileVault, LUKS), comptes
- **Réseau et Wi-Fi** : services exposés, Wi-Fi ouvert ou mal chiffré
- **Logiciels** : versions obsolètes ou sans support (données [endoflife.date](https://endoflife.date))
- **Performance** : mémoire, processeur, programmes au démarrage, batterie
- **Stockage** : gros dossiers et fichiers, doublons, taille réelle des applications, espace récupérable sans risque
  (les dossiers du système ne sont jamais touchés)

Chaque problème trouvé est accompagné d'un **guide de correction** en trois temps : 🔍 Vérifier, ⚙️ Ouvrir le réglage,
🛠️ Corriger, avec l'endroit où taper chaque commande, son effet, le résultat attendu et les précautions.
KMB ne corrige rien lui-même : c'est vous qui décidez.

## Confidentialité

- Le rapport reste sur votre ordinateur ; le site le lit dans votre navigateur sans l'envoyer.
- Le scanner contacte seulement endoflife.date pour connaître les dates de fin de support des logiciels.
- Option `--anonymiser` : masque le nom de l'ordinateur, les comptes, les adresses IP et les chemins personnels.

---

Projet scolaire en français · [Site et guide](https://kabangoura.github.io/detection-des-failles-de-securite/) ·
[Questions fréquentes](https://kabangoura.github.io/detection-des-failles-de-securite/#questions)
