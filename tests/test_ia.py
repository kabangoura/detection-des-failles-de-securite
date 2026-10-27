"""L'assistant IA : anonymisation, vérification des réponses, choix du fournisseur et bascule de modèle (sans appel réseau réel)."""

import json

import httpx

from kmb_library.ai import assistant
from kmb_library.core.context import ScanContext
from kmb_library.core.runner import process
from tests.conftest import data


def _report(raw):
    data(raw, "network")["smb1_enabled"] = True
    return process(raw, ScanContext(offline=True, cache_dir=None))


def _answer(model):
    plan = {"resume": "ok", "priorites": [{"ordre": 1, "key": "NET-001", "titre": "Désactiver SMBv1", "etapes": ["..."]}]}
    return httpx.Response(200, json={"model": model, "choices": [{"message": {"content": "<think>...</think>```json\n" + json.dumps(plan) + "\n```"}}]})


def _no_keys(monkeypatch):
    for var in ("GROQ_API_KEY", "XAI_API_KEY", "GROK_API_KEY", "KMB_IA", "KMB_IA_MODELE"):
        monkeypatch.delenv(var, raising=False)


def test_payload_is_anonymized(raw):
    payload = json.dumps(assistant.build_payload(_report(raw)), ensure_ascii=False)
    assert "PC-ALICE" not in payload and "alice" not in payload.lower()


def test_verification_flags_invented_steps(raw):
    report = _report(raw)
    plan = {"priorites": [{"ordre": 1, "key": "NET-001", "titre": "SMBv1"},
                          {"ordre": 2, "key": "FAUX-999", "titre": "Inventé"}]}
    out = assistant.verify(plan, report)
    assert out["priorites"][0]["verifie"] is True
    assert out["priorites"][1]["verifie"] is False
    assert out["verification"]["etapes_non_verifiees"] == 1 and out["verification"]["fiable"] is False


def test_groq_par_defaut_et_xai_en_option(monkeypatch):
    _no_keys(monkeypatch)
    assert assistant.provider() is None
    monkeypatch.setenv("XAI_API_KEY", "cle-xai")
    assert assistant.provider()[0] == "xai"
    monkeypatch.setenv("GROQ_API_KEY", "cle-groq")
    assert assistant.provider()[0] == "groq"  # Groq passe en premier
    monkeypatch.setenv("KMB_IA", "xai")
    assert assistant.provider()[0] == "xai"


def test_generate_plan_with_mocked_groq(raw, monkeypatch):
    _no_keys(monkeypatch)
    report = _report(raw)
    seen = []

    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        assert url.startswith("https://api.groq.com/") and headers["Authorization"] == "Bearer test-key"
        seen.append(json["model"])
        return _answer(json["model"])

    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setattr(assistant.httpx, "post", fake_post)
    plan = assistant.generate_plan(report)
    assert plan["verification"]["fiable"] is True
    assert plan["meta"]["fournisseur"] == "Groq" and plan["meta"]["modele"] == "openai/gpt-oss-120b"
    assert seen == ["openai/gpt-oss-120b"]


def test_limite_atteinte_modele_suivant(raw, monkeypatch):
    """Plan gratuit : si un modèle répond 429 (limite atteinte), le suivant prend le relais."""
    _no_keys(monkeypatch)
    report = _report(raw)
    seen = []

    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        seen.append(json["model"])
        if json["model"] == "openai/gpt-oss-120b":
            return httpx.Response(429, json={"error": {"message": "Rate limit reached"}})
        return _answer(json["model"])

    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setattr(assistant.httpx, "post", fake_post)
    plan = assistant.generate_plan(report)
    assert seen == ["openai/gpt-oss-120b", "qwen/qwen3.8-27b"]
    assert plan["meta"]["modele"] == "qwen/qwen3.8-27b"


def test_commandes_comparees_a_la_base(raw):
    """Une commande de l'IA identique à une commande vérifiée de KMB est « connue » ; une commande inventée ne l'est pas."""
    report = _report(raw)
    finding = next(f for f in report.detected() if f.key == "NET-001")
    known = [c.cmd if hasattr(c, "cmd") else c for cmds in finding.remediation.commands.values() for c in cmds]
    assert known, "NET-001 doit avoir des commandes vérifiées dans la base"
    plan = {"priorites": [{"ordre": 1, "key": "NET-001", "titre": "SMBv1",
                           "commandes": ["  " + known[0].upper() + " ", "format C: /q"]}]}
    out = assistant.verify(plan, report)
    cmds = out["priorites"][0]["commandes_verifiees"]
    assert cmds[0]["connue"] is True    # même commande (casse et espaces ignorés)
    assert cmds[1]["connue"] is False   # commande absente de la base
    assert out["verification"]["commandes"] == 2 and out["verification"]["commandes_non_verifiees"] == 1


def test_reponse_mal_formee_nettoyee():
    """Morceaux de JSON ou phrases glissés dans la liste des commandes par une réponse mal formée : retirés."""
    brut = ['winget uninstall --name \\"NOM_DU_LOGICIEL\\', "\n      ]", "gain_estime", ":",
            "Élimination d’un vecteur de vulnérabilité connu.", "5‑10 min (droits administrateur requis).", "msinfo32",
            'attaque liés aux bibliothèques désuètes"', "10-15 min", "start ms-settings:windowsupdate"]
    assert assistant._clean_commands(brut) == ['winget uninstall --name "NOM_DU_LOGICIEL', "msinfo32", "start ms-settings:windowsupdate"]
