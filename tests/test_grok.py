"""L'assistant IA : vérification des réponses et anonymisation (sans appel réseau réel)."""

import json

import httpx

from kmb_library.ai import grok
from kmb_library.core.context import ScanContext
from kmb_library.core.runner import process
from tests.conftest import data


def _report(raw):
    data(raw, "network")["smb1_enabled"] = True
    return process(raw, ScanContext(offline=True, cache_dir=None))


def test_payload_is_anonymized(raw):
    payload = json.dumps(grok.build_payload(_report(raw)), ensure_ascii=False)
    assert "PC-ALICE" not in payload and "alice" not in payload.lower()


def test_verification_flags_invented_steps(raw):
    report = _report(raw)
    plan = {"priorites": [{"ordre": 1, "key": "NET-001", "titre": "SMBv1"},
                          {"ordre": 2, "key": "FAUX-999", "titre": "Inventé"}]}
    out = grok.verify(plan, report)
    assert out["priorites"][0]["verifie"] is True
    assert out["priorites"][1]["verifie"] is False
    assert out["verification"]["etapes_non_verifiees"] == 1 and out["verification"]["fiable"] is False


def test_generate_plan_with_mocked_api(raw, monkeypatch):
    report = _report(raw)
    answer = {"resume": "ok", "priorites": [{"ordre": 1, "key": "NET-001", "titre": "Désactiver SMBv1", "etapes": ["..."]}]}

    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        assert headers["Authorization"] == "Bearer test-key"
        return httpx.Response(200, json={"model": "grok-test", "choices": [{"message": {"content": "```json\n" + __import__("json").dumps(answer) + "\n```"}}]})

    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setattr(grok.httpx, "post", fake_post)
    plan = grok.generate_plan(report)
    assert plan["verification"]["fiable"] is True
    assert plan["meta"]["modele"] == "grok-test"
