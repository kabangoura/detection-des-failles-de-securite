"""Assistant IA : plan de correction personnalisé généré par l'API Grok (xAI).

- La clé est lue dans la variable d'environnement XAI_API_KEY (fichier .env), jamais dans le code.
- Seuls les problèmes détectés, les scores et l'OS sont envoyés, après anonymisation.
- La réponse est VÉRIFIÉE : chaque étape doit citer une clé de constat existante ;
  les étapes inventées sont marquées « non vérifiée » plutôt que présentées comme fiables.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime

import httpx

from kmb_library.core.anonymize import anonymize
from kmb_library.core.models import ScanReport

API_URL = os.getenv("XAI_API_URL", "https://api.x.ai/v1/chat/completions")
DEFAULT_MODEL = "grok-4.7"
PROMPT_VERSION = "1.0"

SYSTEM_PROMPT = """Tu es un expert en cybersécurité et en maintenance de postes Windows.
On te fournit le résultat d'un audit automatique (KMB Library). Rédige en français un plan de correction
priorisé, clair pour un utilisateur non spécialiste.
Règles strictes :
- N'utilise QUE les problèmes fournis ; cite pour chaque étape la clé exacte du problème (champ "key").
- N'invente ni problème, ni version, ni chiffre absent des données.
- Donne des étapes concrètes et des commandes Windows (PowerShell) sûres ; signale celles qui demandent les droits administrateur.
- Ne donne aucune instruction d'exploitation offensive.
Réponds UNIQUEMENT avec un objet JSON de la forme :
{"resume": "3 à 5 phrases sur l'état du poste",
 "priorites": [{"ordre": 1, "key": "CLE", "titre": "...", "pourquoi": "...", "etapes": ["..."],
                "commandes": ["..."], "gain_estime": "...", "duree": "..."}],
 "conseils_generaux": ["..."]}"""


class GrokError(RuntimeError):
    pass


def api_key() -> str | None:
    return os.getenv("XAI_API_KEY") or os.getenv("GROK_API_KEY")


def build_payload(report: ScanReport) -> dict:
    """Données envoyées à Grok : jamais le nom de la machine, et noms de comptes/chemins masqués."""
    payload = {
        "os": report.os,
        "scores": report.scores,
        "resume_gravite": report.summary,
        "problemes": [
            {"key": f.key, "titre": f.title, "gravite": f.severity, "domaine": f.domain,
             "constat": f.evidence, "correction_connue": f.remediation.steps[:4]}
            for f in report.detected()
        ],
    }
    text = json.dumps(payload, ensure_ascii=False)
    users = set(re.findall(r"Users\\\\([^\\\\\"]+)", text))
    users |= {m for f in report.detected() if f.domain == "securite" for m in re.findall(r"« ([^»]+) »", f.evidence or "")}
    return anonymize(payload, report.machine_name, sorted(users))


def _parse_json(text: str) -> dict:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise GrokError("La réponse de Grok ne contient pas de JSON.")
    return json.loads(text[start:end + 1])


def verify(plan: dict, report: ScanReport) -> dict:
    """Contrôle de la réponse de l'IA par rapport aux données réelles du scan."""
    known = {f.key: f for f in report.detected()}
    checked, unknown = [], 0
    for step in plan.get("priorites", []) or []:
        key = step.get("key")
        ok = key in known
        unknown += not ok
        step["verifie"] = ok
        if ok:
            step["gravite_reelle"] = known[key].severity
        checked.append(step)
    covered = {s.get("key") for s in checked}
    missing = [k for k, f in known.items() if f.severity in ("critique", "eleve") and k not in covered]
    plan["priorites"] = checked
    plan["verification"] = {
        "etapes": len(checked),
        "etapes_non_verifiees": unknown,
        "problemes_graves_oublies": missing,
        "fiable": unknown == 0 and not missing,
    }
    return plan


def generate_plan(report: ScanReport, model: str | None = None, timeout: float = 120.0) -> dict:
    key = api_key()
    if not key:
        raise GrokError("Clé API absente : définir XAI_API_KEY dans le fichier .env (voir .env.example).")
    model = model or os.getenv("XAI_MODEL", DEFAULT_MODEL)
    body = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(build_payload(report), ensure_ascii=False)},
        ],
        "response_format": {"type": "json_object"},
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        r = httpx.post(API_URL, json=body, headers=headers, timeout=timeout)
        if r.status_code == 400 and "response_format" in r.text:
            body.pop("response_format")
            r = httpx.post(API_URL, json=body, headers=headers, timeout=timeout)
    except httpx.HTTPError as exc:
        raise GrokError(f"API Grok injoignable : {exc}") from exc
    if r.status_code == 401:
        raise GrokError("Clé API Grok refusée (401). Vérifier XAI_API_KEY.")
    if r.status_code >= 400:
        raise GrokError(f"Erreur API Grok {r.status_code} : {r.text[:300]}")
    data = r.json()
    content = data["choices"][0]["message"]["content"]
    plan = verify(_parse_json(content), report)
    plan["meta"] = {
        "scan_id": report.scan_id, "modele": data.get("model", model), "fournisseur": "xAI Grok",
        "genere_le": datetime.now().astimezone().isoformat(timespec="seconds"), "prompt_version": PROMPT_VERSION,
        "tokens": data.get("usage"),
    }
    return plan
