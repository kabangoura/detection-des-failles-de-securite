"""Règles Wi-Fi : réseau connecté ouvert ou faiblement chiffré, réseaux ouverts mémorisés."""

from __future__ import annotations

from kmb_library.core.models import Finding
from kmb_library.rules.engine import RawView, make


def evaluate(v: RawView, enr: dict) -> list[Finding]:
    w = v.data("wifi")
    if not w or w.get("available") is False:
        return []  # poste sans Wi-Fi : contrôle sans objet
    if w.get("available") is None:
        return [make("WIFI-001", "non_verifiable", v.reason("wifi", "wifi", "Interface Wi-Fi illisible"))]
    out: list[Finding] = []
    cur = w.get("current")
    if cur:
        sec, label = cur.get("security"), f"« {cur.get('ssid')} » ({cur.get('auth') or 'inconnu'}{', ' + cur['cipher'] if cur.get('cipher') else ''})"
        out.append(make("WIFI-001", "detecte" if sec == "ouvert" else "conforme", f"Réseau connecté {label}"))
        if sec in ("wep", "wpa"):
            out.append(make("WIFI-002", "detecte", f"Réseau connecté {label}", severity="critique" if sec == "wep" else "eleve"))
        elif sec in ("wpa2", "wpa3", "entreprise"):
            out.append(make("WIFI-002", "conforme", f"Chiffrement {sec.upper()}"))
    risky = [p for p in w.get("profiles") or [] if p.get("security") == "ouvert" and p.get("autoconnect")]
    for p in risky:
        out.append(make("WIFI-003", "detecte", f"Réseau ouvert « {p['name']} » mémorisé avec connexion automatique", suffix=p["name"]))
    if w.get("profiles") is not None and not risky:
        out.append(make("WIFI-003", "conforme", f"{len(w['profiles'])} réseau(x) mémorisé(s), aucun réseau ouvert en connexion automatique"))
    return out
