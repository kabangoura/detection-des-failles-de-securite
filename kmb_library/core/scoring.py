"""Calcul des scores /100 et du plan de correction priorisé.

Règle (cahier des charges) : chaque domaine part de 100 et perd des points par problème détecté :
critique -15, élevé -10, moyen -5, faible -1, info 0 (minimum 0).
Score global = moyenne pondérée : sécurité 40 %, performance 20 %, stockage 20 %, logiciels 20 %.
"""

from __future__ import annotations

from kmb_library.core.models import DOMAIN_LABELS, DOMAINS, SEVERITIES, Finding, PlanStep
from kmb_library.core.utils import human_size

WEIGHTS = {"securite": 0.4, "performance": 0.2, "stockage": 0.2, "logiciels": 0.2}
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def compute_scores(findings: list[Finding]) -> dict[str, int]:
    scores = {}
    for domain in DOMAINS:
        lost = sum(f.penalty for f in findings if f.domain == domain and f.status == "detecte")
        scores[domain] = max(0, 100 - lost)
    scores["global"] = round(sum(scores[d] * w for d, w in WEIGHTS.items()))
    return scores


def summarize(findings: list[Finding]) -> dict[str, int]:
    summary = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.status == "detecte":
            summary[f.severity] += 1
    summary["total"] = sum(summary[s] for s in SEVERITIES)
    summary["conformes"] = sum(1 for f in findings if f.status == "conforme")
    summary["non_verifiables"] = sum(1 for f in findings if f.status == "non_verifiable")
    return summary


def build_plan(findings: list[Finding]) -> list[PlanStep]:
    """Priorité : gravité décroissante, puis sécurité avant les autres domaines, puis gain."""
    todo = [f for f in findings if f.status == "detecte" and f.severity != "info"]
    todo.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.domain != "securite", -f.penalty))
    plan = []
    for i, f in enumerate(todo, start=1):
        gain = f"+{f.penalty} {DOMAIN_LABELS[f.domain].lower()}"
        if f.id == "STO-002" and f.details and f.details.get("wasted_bytes"):
            gain += f" / {human_size(f.details['wasted_bytes'])} libérés"
        plan.append(PlanStep(priority=i, key=f.key, title=f.title, severity=f.severity, domain=f.domain,
                             gain=gain, duration=f.remediation.duration))
    return plan
