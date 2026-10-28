"""Version anglaise : base de connaissances traduite en entier, fichiers du site à jour, interface traduite."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import construire_traductions as ct  # noqa: E402


def test_base_de_connaissances_traduite_en_entier():
    fr, en = ct.charger()
    assert ct.controler(fr, en) == []


def test_fichier_du_site_a_jour():
    """web/kb_en.json doit correspondre à la traduction (sinon : python scripts/construire_traductions.py)."""
    fr, en = ct.charger()
    assert json.loads((ROOT / "web" / "kb_en.json").read_text(encoding="utf-8")) == ct.pour_le_site(fr, en)


def test_page_anglaise_sans_francais():
    page = (ROOT / "web" / "en" / "index.html").read_text(encoding="utf-8")
    assert '<html lang="en">' in page and 'src="../i18n-en.js"' in page and 'hreflang="fr"' in page
    for mot in ("Analyser mon rapport", "Questions fréquentes", "Guide d'installation", "Commencer le guide"):
        assert mot not in page


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js absent")
def test_interface_traduite():
    """Chaque texte affiché par app.js a sa traduction dans web/i18n-en.js (contrôle en JavaScript)."""
    r = subprocess.run(["node", str(ROOT / "tests" / "i18n_check.mjs")], capture_output=True, text=True, encoding="utf-8")
    resultat = json.loads(r.stdout)
    assert r.returncode == 0 and resultat["erreurs"] == [], resultat
