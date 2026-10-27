"""Moteur de règles : transforme les données brutes + enrichies en constats (findings)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from kmb_library.core.models import Finding, Remediation
from kmb_library.core.utils import parse_date

KB_PATH = Path(__file__).with_name("knowledge_base.json")
RISK_SCORE = {"critique": 9.5, "eleve": 7.5, "moyen": 5.0, "faible": 2.5, "info": 0.0}


@lru_cache(maxsize=1)
def knowledge_base() -> dict[str, Any]:
    return json.loads(KB_PATH.read_text(encoding="utf-8"))


def penalties() -> dict[str, int]:
    return knowledge_base()["_meta"]["penalties"]


def make(rule_id: str, status: str, evidence: str | None = None, *, suffix: str | None = None,
         severity: str | None = None, title: str | None = None, location: str | None = None,
         details: dict | None = None) -> Finding:
    """Crée un constat à partir d'une entrée de la base de connaissances."""
    kb = knowledge_base()[rule_id]
    sev = severity or kb["severity"]
    return Finding(
        key=f"{rule_id}:{suffix}" if suffix else rule_id,
        id=rule_id,
        domain=kb["domain"],
        category=kb["category"],
        title=title or kb["title"],
        severity=sev,
        status=status,
        description=kb.get("description", ""),
        danger=kb.get("danger"),
        impact=kb.get("impact"),
        evidence=evidence,
        location=location or kb.get("location"),
        risk_score=RISK_SCORE[sev] if status == "detecte" else 0.0,
        penalty=penalties()[sev] if status == "detecte" else 0,
        remediation=Remediation(**kb.get("remediation", {})),
        references=kb.get("references", []),
        details=details,
    )


def localize(f: Finding, os_family: str) -> Finding:
    """Applique les variantes d'une entrée pour le système analysé (champs `xxx_linux`, `xxx_macos`)."""
    if os_family == "windows":
        return f
    kb = knowledge_base().get(f.id, {})
    if f"remediation_{os_family}" in kb:
        f.remediation = Remediation(**kb[f"remediation_{os_family}"])
    for field in ("location", "description", "danger", "impact"):
        if f"{field}_{os_family}" in kb and getattr(f, field) == kb.get(field):
            setattr(f, field, kb[f"{field}_{os_family}"])
    if f"title_{os_family}" in kb and f.title == kb.get("title"):
        f.title = kb[f"title_{os_family}"]
    return f


class RawView:
    """Accès simplifié aux données brutes d'un collecteur."""

    def __init__(self, raw: dict):
        self.raw = raw
        self.os = raw.get("os_family", "windows")
        # Date de référence = début du scan (un ancien rapport retraité garde des durées cohérentes)
        self.now = parse_date(raw.get("started_at"))

    def data(self, name: str) -> dict:
        return (self.raw.get("collectors", {}).get(name) or {}).get("data") or {}

    def error(self, name: str, key: str) -> str | None:
        return (self.data(name).get("_errors") or {}).get(key)

    def reason(self, name: str, key: str, default: str = "Information non disponible") -> str:
        err = self.error(name, key) or ""
        if "refus" in err.lower() or "denied" in err.lower() or "privil" in err.lower():
            return "Droits administrateur requis pour ce contrôle (relancer le scan en tant qu'administrateur)"
        return f"{default}{' : ' + err if err else ''}"


def evaluate(raw: dict, enrichment: dict) -> list[Finding]:
    from kmb_library.rules import hardware, performance, security, software, storage, wifi

    view = RawView(raw)
    findings: list[Finding] = []
    for module in (security, wifi, software, performance, hardware, storage):
        findings.extend(module.evaluate(view, enrichment))
    findings = [localize(f, view.os) for f in findings]
    # Clés uniques garanties (sécurité pour la comparaison entre scans)
    seen: dict[str, int] = {}
    for f in findings:
        if f.key in seen:
            seen[f.key] += 1
            f.key = f"{f.key}#{seen[f.key]}"
        else:
            seen[f.key] = 0
    return findings
