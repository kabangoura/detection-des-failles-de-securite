"""Tests des endpoints de l'API avec un dossier de données temporaire."""

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from kmb_library.core.context import ScanContext
from kmb_library.core.runner import process
from tests.conftest import data

JSON = {"Content-Type": "application/json"}


@pytest.fixture
def reports(raw):
    ctx = ScanContext(offline=True, cache_dir=None)
    data(raw, "network")["smb1_enabled"] = True
    first = process(raw, ctx)
    raw["scan_id"] = "20260102-120000-test02"
    raw["started_at"] = raw["finished_at"] = "2026-01-02T12:00:00-05:00"
    data(raw, "network")["smb1_enabled"] = False
    second = process(raw, ctx)
    return first, second


@pytest.fixture
def client(tmp_path, reports, monkeypatch):
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    monkeypatch.delenv("GROK_API_KEY", raising=False)
    c = TestClient(create_app(tmp_path))
    for r in reports:
        assert c.post("/scans", content=r.model_dump_json(), headers=JSON).status_code == 201
    return c


def test_upload_duplicate_and_invalid(client, reports):
    assert client.post("/scans", content=reports[0].model_dump_json(), headers=JSON).status_code == 409
    r = client.post("/scans", json={"scan_id": "x"})
    assert r.status_code == 422 and r.json()["erreurs"]


def test_list_and_filters(client):
    r = client.get("/scans").json()
    assert r["total"] == 2 and r["resultats"][0]["scan_id"] == "20260102-120000-test02"
    assert client.get("/scans?limit=1").json()["resultats"].__len__() == 1
    assert client.get("/scans?date_min=2026-01-02").json()["total"] == 1
    empty = client.get("/scans?machine=inexistant").json()
    assert empty["total"] == 0 and "message" in empty
    assert client.get("/scans?limit=0").status_code == 422
    assert client.get("/scans?date_min=2026-02-01&date_max=2026-01-01").status_code == 422


def test_get_scan_and_alias(client):
    assert client.get("/scans/dernier").json()["scan_id"] == "20260102-120000-test02"
    assert client.get("/scans/inconnu").status_code == 404
    assert client.get("/scans/..%2F..%2Fsecret").status_code == 404


def test_findings_filters(client):
    base = "/scans/20260101-120000-test01/findings"
    crit = client.get(f"{base}?severite=critique").json()
    assert [f["key"] for f in crit["resultats"]] == ["NET-001"]
    assert client.get(f"{base}?severite=inconnue").status_code == 422
    assert client.get(f"{base}?recherche=zzz").json()["total"] == 0
    tous = client.get(f"{base}?statut=tous&domaine=securite").json()
    assert all(f["domain"] == "securite" for f in tous["resultats"]) and tous["total"] > 5


def test_software_endpoint(client):
    r = client.get("/scans/dernier/logiciels?recherche=note").json()
    assert r["total"] == 1 and r["resultats"][0]["name"] == "Notepad"
    assert client.get("/scans/dernier/logiciels?cycle_de_vie=fin_de_support").json()["total"] == 0


def test_comparison_and_stats(client):
    c = client.get("/comparaison?ancien=20260101-120000-test01&nouveau=dernier").json()
    assert [f["key"] for f in c["corriges"]] == ["NET-001"]
    assert c["evolution_scores"]["securite"] == 15
    assert client.get("/comparaison?ancien=dernier").status_code == 422
    assert client.get("/comparaison?ancien=nope").status_code == 404
    s = client.get("/statistiques").json()
    assert s["nb_scans"] == 2 and len(s["evolution"]) == 2
    assert client.get("/statistiques?machine=zzz").json()["nb_scans"] == 0


def test_knowledge_and_ai(client):
    assert client.get("/connaissances/net-001").json()["severity"] == "critique"
    assert client.get("/connaissances/XYZ").status_code == 404
    assert client.get("/scans/dernier/plan-ia").status_code == 404
    assert client.post("/scans/dernier/plan-ia").status_code == 503


def test_delete(client):
    assert client.delete("/scans/20260101-120000-test01").status_code == 200
    assert client.get("/scans").json()["total"] == 1
