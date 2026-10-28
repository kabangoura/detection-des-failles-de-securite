"""Traduction anglaise de la base de connaissances : contrôle, puis fichier pour le site.

Usage : python scripts/construire_traductions.py

- Source : kmb_library/rules/knowledge_base_en.json, rangé comme la base française (mêmes champs, étapes et
  commandes dans le même ordre ; les commandes elles-mêmes ne sont pas recopiées : elles ne se traduisent pas).
- Contrôle : chaque fiche, chaque texte, chaque étape et chaque commande française a sa traduction
  (même nombre d'étapes, même nombre de commandes, mêmes mots à remplacer). Le script s'arrête sinon.
- Sortie : web/kb_en.json, lu par la version anglaise du site. Les commandes y sont indexées par leur texte exact,
  ce qui permet de traduire n'importe quel rapport, même produit par une version précédente de KMB.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KB_FR = ROOT / "kmb_library" / "rules" / "knowledge_base.json"
KB_EN = ROOT / "kmb_library" / "rules" / "knowledge_base_en.json"
SORTIE = ROOT / "web" / "kb_en.json"
TEXTES = ("category", "title", "description", "danger", "impact", "location")


def charger() -> tuple[dict, dict]:
    return json.loads(KB_FR.read_text(encoding="utf-8")), json.loads(KB_EN.read_text(encoding="utf-8"))


def controler(fr: dict, en: dict) -> list[str]:
    """Liste des écarts entre la base française et sa traduction (vide = traduction complète)."""
    ecarts = []
    for rid, f in fr.items():
        if rid.startswith("_"):
            continue
        e = en.get(rid)
        if e is None:
            ecarts.append(f"{rid} : fiche non traduite")
            continue
        for champ, valeur in f.items():
            if champ.split("_")[0] in TEXTES and isinstance(valeur, str) and not e.get(champ):
                ecarts.append(f"{rid}.{champ} : texte non traduit")
            if champ.startswith("remediation"):
                re_ = e.get(champ) or {}
                if len(re_.get("steps", [])) != len(valeur.get("steps", [])):
                    ecarts.append(f"{rid}.{champ} : {len(valeur.get('steps', []))} étapes en français, {len(re_.get('steps', []))} en anglais")
                if valeur.get("duration") and not re_.get("duration"):
                    ecarts.append(f"{rid}.{champ} : durée non traduite")
                for os_, cmds in (valeur.get("commands") or {}).items():
                    cmds_en = (re_.get("commands") or {}).get(os_, [])
                    if len(cmds_en) != len(cmds):
                        ecarts.append(f"{rid}.{champ}.{os_} : {len(cmds)} commandes en français, {len(cmds_en)} en anglais")
                        continue
                    for i, (c, t) in enumerate(zip(cmds, cmds_en)):
                        if isinstance(c, str):
                            continue
                        for cle in ("effet", "attendu", "attention"):
                            if c.get(cle) and not t.get(cle):
                                ecarts.append(f"{rid}.{champ}.{os_}[{i}] : « {cle} » non traduit ({c['cmd']})")
                        if set((c.get("remplacer") or {})) != set((t.get("remplacer") or {})):
                            ecarts.append(f"{rid}.{champ}.{os_}[{i}] : mots à remplacer différents ({c['cmd']})")
    for rid in en:
        if not rid.startswith("_") and rid not in fr:
            ecarts.append(f"{rid} : fiche anglaise sans équivalent français")
    return ecarts


def pour_le_site(fr: dict, en: dict) -> dict:
    out = {}
    for rid, f in fr.items():
        if rid.startswith("_"):
            continue
        e = en[rid]
        fiche = {k: v for k, v in e.items() if not k.startswith("remediation")}
        commandes = {}
        for champ, valeur in f.items():
            if not champ.startswith("remediation"):
                continue
            re_ = e[champ]
            fiche["steps" + champ[len("remediation"):]] = re_.get("steps", [])
            if re_.get("duration"):
                fiche["duration" + champ[len("remediation"):]] = re_["duration"]
            for os_, cmds in (valeur.get("commands") or {}).items():
                for c, t in zip(cmds, re_["commands"][os_]):
                    if not isinstance(c, str):
                        commandes[c["cmd"]] = {k: v for k, v in t.items() if v}
        fiche["commandes"] = commandes
        out[rid] = fiche
    return out


if __name__ == "__main__":
    fr, en = charger()
    ecarts = controler(fr, en)
    if ecarts:
        print("Traduction incomplète :")
        print("\n".join("  " + e for e in ecarts))
        raise SystemExit(1)
    site = pour_le_site(fr, en)
    SORTIE.write_text(json.dumps(site, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    n_cmd = sum(len(v["commandes"]) for v in site.values())
    print(f"Traduction complète : {len(site)} fiches, {n_cmd} commandes expliquées -> {SORTIE.relative_to(ROOT)}")
