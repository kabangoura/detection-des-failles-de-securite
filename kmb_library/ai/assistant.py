"""Assistant IA : plan de correction personnalisé, généré par un modèle de langage puis VÉRIFIÉ.

Fournisseurs (format de requête identique, « chat completions ») :
- Groq (par défaut) : plan gratuit, modèles ouverts ; clé GROQ_API_KEY (https://console.groq.com/keys).
- xAI Grok (option) : clé XAI_API_KEY.
Le fournisseur est celui dont la clé est présente (Groq d'abord) ; KMB_IA=groq|xai l'impose.

- Les clés sont lues dans les variables d'environnement (fichier .env), jamais dans le code.
- Seuls les problèmes détectés, les scores et le système sont envoyés, après anonymisation.
- Plusieurs modèles sont essayés dans l'ordre : si l'un atteint sa limite du plan gratuit (429), le suivant prend le relais.
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
from kmb_library.core.models import Command, ScanReport

PROMPT_VERSION = "2.1"
PROVIDERS = {
    "groq": {"label": "Groq", "url": "https://api.groq.com/openai/v1/chat/completions", "key_env": "GROQ_API_KEY",
             "models": ["openai/gpt-oss-120b", "qwen/qwen3.8-27b", "openai/gpt-oss-20b"]},
    "xai": {"label": "xAI Grok", "url": "https://api.x.ai/v1/chat/completions", "key_env": "XAI_API_KEY",
            "models": ["grok-4.7"]},
}
MAX_PROBLEMS = 15  # plan gratuit Groq : 8 000 jetons par minute, la demande doit rester courte

SYSTEM_PROMPT = """Tu es un expert en cybersécurité et en maintenance d'ordinateurs (Windows, Linux, macOS).
On te fournit le résultat d'un audit automatique (KMB Library). Rédige en français un plan de correction
priorisé, clair pour un utilisateur non spécialiste.
Règles strictes :
- N'utilise QUE les problèmes fournis ; cite pour chaque étape la clé exacte du problème (champ "key").
- N'invente ni problème, ni version, ni chiffre absent des données.
- Donne des étapes concrètes. Pour les commandes, reprends EN PRIORITÉ, mot pour mot, celles du champ
  "commandes_connues" (elles sont vérifiées) ; n'en propose une autre que si aucune ne convient, adaptée au
  système indiqué (champ "os"). Signale celles qui demandent les droits administrateur.
- Ne donne aucune instruction d'exploitation offensive.
Réponds UNIQUEMENT avec un objet JSON de la forme :
{"resume": "3 à 5 phrases sur l'état du poste",
 "priorites": [{"ordre": 1, "key": "CLE", "titre": "...", "pourquoi": "...", "etapes": ["..."],
                "commandes": ["..."], "gain_estime": "...", "duree": "..."}],
 "conseils_generaux": ["..."]}"""


class AIError(RuntimeError):
    pass


def provider() -> tuple[str, dict, str] | None:
    """(nom, configuration, clé) du fournisseur utilisable, ou None si aucune clé n'est configurée."""
    wanted = os.getenv("KMB_IA", "").strip().lower()
    for name, conf in PROVIDERS.items():
        if wanted and name != wanted:
            continue
        key = os.getenv(conf["key_env"]) or (os.getenv("GROK_API_KEY") if name == "xai" else None)
        if key:
            return name, conf, key
    return None


def api_key() -> str | None:
    found = provider()
    return found[2] if found else None


def _commands_for(finding, os_family: str | None, limit: int = 3) -> list[str]:
    """Commandes vérifiées de la base KMB pour ce problème et ce système (les « corriger » d'abord)."""
    cmds = finding.remediation.commands.get(os_family or "windows") or next(iter(finding.remediation.commands.values()), [])
    order = {"corriger": 0, "ouvrir": 1, "verifier": 2}
    cmds = sorted(cmds, key=lambda c: order.get(getattr(c, "type", ""), 3))
    return [c.cmd if isinstance(c, Command) else str(c) for c in cmds[:limit]]


def build_payload(report: ScanReport) -> dict:
    """Données envoyées à l'IA : jamais le nom de la machine, et noms de comptes/chemins masqués."""
    detected = report.detected()[:MAX_PROBLEMS]
    payload = {
        "os": report.os,
        "scores": report.scores,
        "resume_gravite": report.summary,
        "problemes": [
            {"key": f.key, "titre": f.title, "gravite": f.severity, "domaine": f.domain,
             "constat": (f.evidence or "")[:240], "correction_connue": f.remediation.steps[:3],
             "commandes_connues": _commands_for(f, report.os_family)}
            for f in detected
        ],
    }
    text = json.dumps(payload, ensure_ascii=False)
    users = set(re.findall(r"Users\\\\([^\\\\\"]+)", text))
    users |= {m for f in detected if f.domain == "securite" for m in re.findall(r"« ([^»]+) »", f.evidence or "")}
    return anonymize(payload, report.machine_name, sorted(users))


def _parse_json(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()  # raisonnement de certains modèles
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise AIError("La réponse de l'IA ne contient pas de JSON.")
    return json.loads(text[start:end + 1])


_PLAN_FIELDS = {"ordre", "key", "titre", "pourquoi", "etapes", "commandes", "gain_estime", "duree", "resume", "priorites"}


def _norm(text: str) -> str:
    return " ".join(str(text).replace('\\"', '"').strip().strip("`").lower().split())


def _clean_commands(raw) -> list[str]:
    """Garde les vraies commandes : une réponse mal formée de l'IA peut glisser des morceaux de JSON dans la liste."""
    out = []
    for c in raw if isinstance(raw, list) else []:
        c = str(c).replace('\\"', '"').strip().rstrip("\\").strip()
        if c.count('"') % 2:  # guillemet orphelin laissé par une réponse mal formée
            c = c.strip('"').strip()
        mots = c.split()
        prose = (c.endswith((".", "…")) and len(mots) >= 3) or (  # une phrase, pas une commande
            len(mots) >= 3 and re.search(r"[à-ÿ]", c) and not re.search(r"[-/\\:=|$<>]", c))
        duree = re.fullmatch(r"\d+\s*[-–‑à]?\s*\d*\s*(min|minutes?|h|heures?|s|secondes?)\.?", c, re.I)
        if duree or len(c) < 3 or c.strip(':,[]{}" ').lower() in _PLAN_FIELDS or not re.search(r"[A-Za-z]{2}", c) or prose:
            continue
        out.append(c)
    return out


def _pattern(command: Command | str) -> re.Pattern:
    """Commande vérifiée de la base KMB → motif : les mots à remplacer (<NOM>, remplacer) acceptent n'importe quelle valeur."""
    cmd, words = (command.cmd, command.remplacer or {}) if isinstance(command, Command) else (command, {})
    text = re.escape(_norm(cmd))
    for word in words:
        text = text.replace(re.escape(_norm(word)), ".+?")
    text = re.sub(r"<[^>]+>", ".+?", text).replace(r"\ ", r"\s+")
    return re.compile(text + r"\s*$")


def _known_commands(report: ScanReport) -> dict[str, list[re.Pattern]]:
    """Commandes vérifiées de la base KMB, par constat (tous systèmes confondus)."""
    return {f.key: [_pattern(c) for cmds in f.remediation.commands.values() for c in cmds] for f in report.findings}


def verify(plan: dict, report: ScanReport) -> dict:
    """Contrôle de la réponse de l'IA par rapport aux données réelles du scan.

    - chaque étape doit citer la clé d'un problème réellement détecté ;
    - chaque commande proposée est comparée aux commandes vérifiées de la base KMB (celles du problème
      d'abord, puis toutes les autres) : une commande inconnue est marquée « non vérifiée ».
    """
    known = {f.key: f for f in report.detected()}
    patterns = _known_commands(report)
    every = [pt for pts in patterns.values() for pt in pts]
    checked, unknown, n_cmds, unknown_cmds = [], 0, 0, 0
    for step in plan.get("priorites", []) or []:
        key = step.get("key")
        ok = key in known
        unknown += not ok
        step["verifie"] = ok
        if ok:
            step["gravite_reelle"] = known[key].severity
        cmds = []
        step["commandes"] = _clean_commands(step.get("commandes"))
        for c in step["commandes"]:
            own = any(pt.match(_norm(c)) for pt in patterns.get(key, []))
            cmds.append({"commande": c, "connue": own or any(pt.match(_norm(c)) for pt in every)})
        step["commandes_verifiees"] = cmds
        n_cmds += len(cmds)
        unknown_cmds += sum(not x["connue"] for x in cmds)
        checked.append(step)
    covered = {s.get("key") for s in checked}
    missing = [k for k, f in known.items() if f.severity in ("critique", "eleve") and k not in covered]
    plan["priorites"] = checked
    plan["verification"] = {
        "etapes": len(checked),
        "etapes_non_verifiees": unknown,
        "problemes_graves_oublies": missing,
        "commandes": n_cmds,
        "commandes_non_verifiees": unknown_cmds,
        "fiable": unknown == 0 and not missing,
    }
    return plan


def _call(url: str, key: str, body: dict, timeout: float) -> httpx.Response:
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    r = httpx.post(url, json=body, headers=headers, timeout=timeout)
    if r.status_code == 400 and "response_format" in r.text:  # modèle sans mode JSON : on s'en passe
        body = {k: v for k, v in body.items() if k != "response_format"}
        r = httpx.post(url, json=body, headers=headers, timeout=timeout)
    return r


def generate_plan(report: ScanReport, model: str | None = None, timeout: float = 120.0) -> dict:
    found = provider()
    if not found:
        raise AIError("Clé API absente : mettre GROQ_API_KEY (ou XAI_API_KEY) dans le fichier .env (voir .env.example).")
    name, conf, key = found
    models = [model or os.getenv("KMB_IA_MODELE")] if (model or os.getenv("KMB_IA_MODELE")) else conf["models"]
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(build_payload(report), ensure_ascii=False)}]
    errors = []
    for m in models:
        body = {"model": m, "temperature": 0.2, "max_tokens": 2500, "messages": messages,
                "response_format": {"type": "json_object"}}
        try:
            r = _call(conf["url"], key, body, timeout)
        except httpx.HTTPError as exc:
            raise AIError(f"API {conf['label']} injoignable : {exc}") from exc
        if r.status_code == 401:
            raise AIError(f"Clé API {conf['label']} refusée (401). Vérifier {conf['key_env']} dans le fichier .env.")
        if r.status_code == 429 or r.status_code >= 500 or (r.status_code in (400, 404) and "model" in r.text.lower()):
            errors.append(f"{m} : {r.status_code}")
            continue  # limite atteinte ou modèle indisponible : modèle suivant
        if r.status_code >= 400:
            raise AIError(f"Erreur API {conf['label']} {r.status_code} : {r.text[:300]}")
        data = r.json()
        try:
            plan = _parse_json(data["choices"][0]["message"]["content"])
        except (ValueError, KeyError, IndexError, AIError):
            errors.append(f"{m} : réponse illisible")
            continue
        plan = verify(plan, report)
        plan["meta"] = {
            "scan_id": report.scan_id, "modele": data.get("model", m), "fournisseur": conf["label"],
            "genere_le": datetime.now().astimezone().isoformat(timespec="seconds"), "prompt_version": PROMPT_VERSION,
            "tokens": data.get("usage"),
        }
        return plan
    raise AIError(f"Aucun modèle {conf['label']} disponible pour l'instant (limites du plan gratuit ?) : " + "; ".join(errors))
