"""« Nouvelle version disponible » : à jour, nouvelle version, hors ligne, PyPI injoignable, cache d'un jour."""

import json
import time

import httpx
import pytest

from kmb_library.enrich import pypi


class FakeResponse:
    def __init__(self, version):
        self.version = version

    def raise_for_status(self):
        pass

    def json(self):
        return {"info": {"version": self.version}}


@pytest.fixture
def calls(monkeypatch):
    """Remplace l'appel réseau par une réponse choisie et compte les appels."""
    state = {"n": 0, "version": "2.2.0", "error": False}

    def fake_get(*args, **kwargs):
        state["n"] += 1
        if state["error"]:
            raise httpx.ConnectError("pas d'Internet")
        return FakeResponse(state["version"])

    monkeypatch.setattr(pypi.httpx, "get", fake_get)
    return state


def test_nouvelle_version_signalee(calls, tmp_path):
    assert pypi.newer_version("2.1.0", tmp_path / "pypi.json") == "2.2.0"


def test_a_jour_rien_a_signaler(calls, tmp_path):
    assert pypi.newer_version("2.2.0", tmp_path / "pypi.json") is None
    calls["version"] = "2.1.9"
    assert pypi.newer_version("2.10.0", tmp_path / "autre.json") is None  # comparaison numérique, pas alphabétique


def test_hors_ligne_aucun_appel(calls, tmp_path):
    assert pypi.newer_version("2.1.0", tmp_path / "pypi.json", offline=True) is None
    assert calls["n"] == 0


def test_pypi_injoignable_silencieux(calls, tmp_path):
    calls["error"] = True
    assert pypi.newer_version("2.1.0", tmp_path / "pypi.json") is None


def test_cache_un_jour(calls, tmp_path):
    cache = tmp_path / "pypi.json"
    pypi.newer_version("2.1.0", cache)
    pypi.newer_version("2.1.0", cache)
    assert calls["n"] == 1  # deuxième scan du jour : pas de nouvelle requête
    cache.write_text(json.dumps({"fetched_ts": time.time() - 2 * 24 * 3600, "version": "2.2.0"}), encoding="utf-8")
    calls["version"] = "2.3.0"
    assert pypi.newer_version("2.1.0", cache) == "2.3.0"  # cache périmé : nouvelle requête
    assert calls["n"] == 2


def test_ligne_de_commande_se_charge():
    """Le module de la commande `scan` (qui affiche le message) doit au moins se charger sans erreur."""
    import importlib

    import kmb_library.cli

    importlib.reload(kmb_library.cli)
    assert callable(kmb_library.cli.scan_and_save)
