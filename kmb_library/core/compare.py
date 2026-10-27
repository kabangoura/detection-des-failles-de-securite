"""Comparaison de deux scans : problèmes corrigés, restants, nouveaux."""

from __future__ import annotations

from kmb_library.core.models import ScanReport


def _brief(f) -> dict:
    return {"key": f.key, "id": f.id, "title": f.title, "severity": f.severity, "domain": f.domain, "evidence": f.evidence}


def compare_reports(old: ScanReport, new: ScanReport) -> dict:
    """Compare sur la clé stable `key` des constats.

    Un problème absent du nouveau scan n'est « corrigé » que si le contrôle a bien été
    effectué (statut conforme, ou clé d'instance disparue). S'il est devenu non vérifiable
    (ex. scan sans droits admin), il est classé à part pour ne pas annoncer une fausse correction.
    """
    old_det = {f.key: f for f in old.findings if f.status == "detecte"}
    new_det = {f.key: f for f in new.findings if f.status == "detecte"}
    new_all = {f.key: f for f in new.findings}
    new_unverified_rules = {f.id for f in new.findings if f.status == "non_verifiable"}

    fixed, unverified = [], []
    for key, f in old_det.items():
        if key in new_det:
            continue
        nf = new_all.get(key)
        if (nf and nf.status == "non_verifiable") or (nf is None and f.id in new_unverified_rules):
            unverified.append(_brief(f))
        else:
            fixed.append(_brief(f))
    remaining = [_brief(new_det[k]) for k in new_det if k in old_det]
    new_issues = [_brief(f) for k, f in new_det.items() if k not in old_det]

    delta = {k: new.scores.get(k, 0) - old.scores.get(k, 0) for k in new.scores}
    warnings = []
    if old.machine_name != new.machine_name:
        warnings.append(f"Les scans proviennent de deux machines différentes ({old.machine_name} / {new.machine_name}).")
    if old.scan_date > new.scan_date:
        warnings.append("Le scan « ancien » est plus récent que le scan « nouveau ».")
    if old.is_admin != new.is_admin:
        warnings.append("Les deux scans n'ont pas été lancés avec les mêmes droits (administrateur ou non) : certains contrôles diffèrent.")

    return {
        "ancien": {"scan_id": old.scan_id, "date": old.scan_date, "scores": old.scores},
        "nouveau": {"scan_id": new.scan_id, "date": new.scan_date, "scores": new.scores},
        "evolution_scores": delta,
        "resume": {"corriges": len(fixed), "restants": len(remaining), "nouveaux": len(new_issues),
                   "non_verifiables": len(unverified)},
        "corriges": fixed,
        "restants": remaining,
        "nouveaux": new_issues,
        "non_verifiables": unverified,
        "avertissements": warnings,
    }
