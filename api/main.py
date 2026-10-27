"""API JSON de KMB Library (FastAPI) + service du tableau de bord.

Lancement (depuis le dossier livrable_1) :
    uvicorn api.main:app --reload
Documentation interactive : http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import os
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.storage import ScanStore
from kmb_library import __version__
from kmb_library.core.compare import compare_reports
from kmb_library.core.models import ScanReport, Severity
from kmb_library.rules.engine import knowledge_base

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"

DESCRIPTION = """
API de consultation des audits produits par **KMB Library** (`kmb scan`).

* Les rapports sont des fichiers JSON dans `data/processed/` (aucune base de données).
* `scan_id` accepte la valeur spéciale **`dernier`** pour viser le scan le plus récent.
* Les listes retournent toujours `{"total", "resultats"}` et un `message` lorsqu'aucun résultat ne correspond.
"""

TAGS = [
    {"name": "Scans", "description": "Téléverser, lister et consulter les rapports d'audit"},
    {"name": "Analyse", "description": "Filtrer les problèmes, les logiciels, comparer et obtenir des statistiques"},
    {"name": "IA", "description": "Plan de correction généré par l'IA (Groq, ou xAI Grok), vérifié par rapport au scan"},
    {"name": "Référence", "description": "Base de connaissances des contrôles"},
]


def _summary(r: ScanReport) -> dict:
    return {"scan_id": r.scan_id, "machine_name": r.machine_name, "os": r.os, "os_family": r.os_family, "scan_date": r.scan_date,
            "scores": r.scores, "summary": r.summary, "is_admin": r.is_admin, "anonymized": r.anonymized}


def _list(items: list, total: int | None = None, empty_msg: str = "Aucun résultat pour ces critères.") -> dict:
    out = {"total": len(items) if total is None else total, "resultats": items}
    if not items:
        out["message"] = empty_msg
    return out


def create_app(data_dir: Path | None = None) -> FastAPI:
    data_dir = Path(data_dir or os.getenv("KMB_DATA_DIR", ROOT / "data"))
    store = ScanStore(data_dir)
    app = FastAPI(title="KMB Library API", version=__version__, description=DESCRIPTION, openapi_tags=TAGS)
    app.state.store = store

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        errors = [{"champ": ".".join(str(x) for x in e.get("loc", [])), "message": e.get("msg")} for e in exc.errors()]
        return JSONResponse(status_code=422, content=jsonable_encoder({"detail": "Paramètre ou contenu invalide", "erreurs": errors}))

    def get_or_404(scan_id: str) -> ScanReport:
        report = store.get(scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Scan introuvable : {scan_id}")
        return report

    # ------------------------------------------------------------------ scans

    @app.post("/scans", status_code=status.HTTP_201_CREATED, tags=["Scans"],
              summary="Téléverser un rapport JSON produit par `kmb scan`")
    def upload_scan(report: ScanReport):
        if not store.valid_id(report.scan_id):
            raise HTTPException(status_code=422, detail="scan_id invalide (lettres, chiffres, - et _ uniquement)")
        if store.exists(report.scan_id):
            raise HTTPException(status_code=409, detail=f"Le scan {report.scan_id} existe déjà")
        store.save(report)
        return {"message": "Rapport enregistré", "scan_id": report.scan_id, "scores": report.scores}

    @app.get("/scans", tags=["Scans"], summary="Lister l'historique des scans")
    def list_scans(
        machine: str | None = Query(None, description="Filtre sur le nom de machine (contient, insensible à la casse)"),
        systeme: Literal["windows", "linux", "macos"] | None = Query(None, description="Système d'exploitation"),
        date_min: date | None = Query(None, description="Date minimale (AAAA-MM-JJ)"),
        date_max: date | None = Query(None, description="Date maximale (AAAA-MM-JJ)"),
        score_max: int | None = Query(None, ge=0, le=100, description="Seulement les scans dont le score global est ≤ à cette valeur"),
        limit: int = Query(20, ge=1, le=200, description="Nombre maximal de résultats"),
    ):
        if date_min and date_max and date_min > date_max:
            raise HTTPException(status_code=422, detail="date_min doit être antérieure ou égale à date_max")
        items = store.all()
        if machine:
            items = [r for r in items if machine.lower() in r.machine_name.lower()]
        if systeme:
            items = [r for r in items if r.os_family == systeme]
        if date_min:
            items = [r for r in items if r.scan_date[:10] >= date_min.isoformat()]
        if date_max:
            items = [r for r in items if r.scan_date[:10] <= date_max.isoformat()]
        if score_max is not None:
            items = [r for r in items if r.scores.get("global", 0) <= score_max]
        return _list([_summary(r) for r in items[:limit]], total=len(items), empty_msg="Aucun scan ne correspond à ces critères.")

    @app.get("/scans/{scan_id}", tags=["Scans"], summary="Consulter un rapport complet")
    def get_scan(scan_id: str):
        return get_or_404(scan_id)

    @app.get("/scans/{scan_id}/rapport.html", tags=["Scans"], summary="Rapport HTML imprimable (enregistrable en PDF)",
             response_class=HTMLResponse)
    def html_report(scan_id: str):
        from kmb_library.reports.html_report import render

        return HTMLResponse(render(get_or_404(scan_id)))

    @app.delete("/scans/{scan_id}", tags=["Scans"], summary="Supprimer un rapport")
    def delete_scan(scan_id: str):
        report = get_or_404(scan_id)
        store.delete(report.scan_id)
        return {"message": "Rapport supprimé", "scan_id": report.scan_id}

    # ------------------------------------------------------------------ analyse

    @app.get("/scans/{scan_id}/findings", tags=["Analyse"], summary="Filtrer les problèmes d'un scan")
    def list_findings(
        scan_id: str,
        severite: list[Severity] | None = Query(None, description="Une ou plusieurs gravités (répéter le paramètre)"),
        domaine: Literal["securite", "performance", "stockage", "logiciels"] | None = Query(None),
        categorie: str | None = Query(None, description="Ex. Réseau, Pare-feu, Wi-Fi, Batterie, Logiciels"),
        statut: Literal["detecte", "conforme", "non_verifiable", "tous"] = Query("detecte"),
        recherche: str | None = Query(None, min_length=2, description="Texte cherché dans le titre, le constat et la clé"),
        limit: int = Query(100, ge=1, le=500),
    ):
        report = get_or_404(scan_id)
        items = report.findings
        if statut != "tous":
            items = [f for f in items if f.status == statut]
        if severite:
            items = [f for f in items if f.severity in severite]
        if domaine:
            items = [f for f in items if f.domain == domaine]
        if categorie:
            items = [f for f in items if f.category.lower() == categorie.lower()]
        if recherche:
            q = recherche.lower()
            items = [f for f in items if q in f.title.lower() or q in (f.evidence or "").lower() or q in f.key.lower()]
        order = {"critique": 0, "eleve": 1, "moyen": 2, "faible": 3, "info": 4}
        items = sorted(items, key=lambda f: order[f.severity])
        return _list([f.model_dump() for f in items[:limit]], total=len(items), empty_msg="Aucun problème ne correspond à ces critères.")

    @app.get("/scans/{scan_id}/logiciels", tags=["Analyse"], summary="Inventaire des logiciels et leur cycle de vie")
    def list_software(
        scan_id: str,
        recherche: str | None = Query(None, min_length=2, description="Nom ou éditeur"),
        cycle_de_vie: Literal["fin_de_support", "maj_disponible", "supporte", "inconnu", "non_suivi"] | None = Query(None),
        taille_min_mo: float | None = Query(None, ge=0, description="Taille minimale déclarée (Mo)"),
        limit: int = Query(200, ge=1, le=1000),
    ):
        report = get_or_404(scan_id)
        items = report.inventory.get("software") or []
        if recherche:
            q = recherche.lower()
            items = [s for s in items if q in s["name"].lower() or q in str(s.get("publisher") or "").lower()]
        if cycle_de_vie:
            items = [s for s in items if s.get("lifecycle") == cycle_de_vie]
        if taille_min_mo is not None:
            items = [s for s in items if (s.get("size_mb") or 0) >= taille_min_mo]
        return _list(items[:limit], total=len(items), empty_msg="Aucun logiciel ne correspond à ces critères.")

    @app.get("/comparaison", tags=["Analyse"], summary="Comparer deux scans : corrigés, restants, nouveaux")
    def compare(
        ancien: str = Query(..., description="scan_id du scan de référence (avant correction)"),
        nouveau: str = Query("dernier", description="scan_id du scan après correction (défaut : le plus récent)"),
    ):
        old, new = get_or_404(ancien), get_or_404(nouveau)
        if old.scan_id == new.scan_id:
            raise HTTPException(status_code=422, detail="Les deux scans comparés sont identiques")
        return compare_reports(old, new)

    @app.get("/statistiques", tags=["Analyse"], summary="Indicateurs globaux et évolution des scores")
    def statistics(machine: str | None = Query(None, description="Limiter à une machine"),
                   systeme: Literal["windows", "linux", "macos"] | None = Query(None, description="Limiter à un système")):
        reports = store.all()
        if machine:
            reports = [r for r in reports if machine.lower() in r.machine_name.lower()]
        if systeme:
            reports = [r for r in reports if r.os_family == systeme]
        if not reports:
            return {"nb_scans": 0, "message": "Aucun scan disponible pour ces critères."}
        latest = reports[0]
        recurring = Counter(f.key for r in reports for f in r.detected())
        titles = {f.key: f.title for r in reports for f in r.detected()}
        dup = latest.inventory.get("duplicates") or {}
        return {
            "nb_scans": len(reports),
            "machines": sorted({r.machine_name for r in reports}),
            "systemes": dict(Counter(r.os_family for r in reports)),
            "dernier_scan": _summary(latest),
            "repartition_gravite": {k: latest.summary.get(k, 0) for k in ("critique", "eleve", "moyen", "faible", "info")},
            "repartition_domaine": dict(Counter(f.domain for f in latest.detected())),
            "evolution": [{"scan_id": r.scan_id, "date": r.scan_date, "scores": r.scores} for r in reversed(reports)],
            "problemes_recurrents": [{"key": k, "title": titles[k], "nb_scans": n} for k, n in recurring.most_common(10)],
            "espace_recuperable_octets": dup.get("wasted_bytes", 0),
        }

    # ------------------------------------------------------------------ IA

    def ia_configuree() -> bool:
        from kmb_library.ai.assistant import api_key

        return api_key() is not None

    @app.get("/scans/{scan_id}/plan-ia", tags=["IA"], summary="Lire le plan IA déjà généré")
    def get_ai_plan(scan_id: str):
        report = get_or_404(scan_id)
        plan = store.get_ai_plan(report.scan_id)
        if plan is None:
            raise HTTPException(status_code=404, detail="Aucun plan IA pour ce scan : utiliser POST pour le générer")
        return plan

    @app.post("/scans/{scan_id}/plan-ia", tags=["IA"], summary="Générer un plan de correction avec l'IA")
    def create_ai_plan(scan_id: str, regenerer: bool = Query(False, description="Ignorer le plan déjà enregistré")):
        from kmb_library.ai.assistant import AIError, api_key, generate_plan

        report = get_or_404(scan_id)
        if not regenerer and (plan := store.get_ai_plan(report.scan_id)):
            return plan
        if not api_key():
            raise HTTPException(status_code=503, detail="Assistant IA non configuré : mettre GROQ_API_KEY (ou XAI_API_KEY) dans le fichier .env")
        try:
            plan = generate_plan(report)
        except AIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        store.save_ai_plan(report.scan_id, plan)
        return plan

    # ------------------------------------------------------------------ référence

    @app.get("/connaissances", tags=["Référence"], summary="Lister les contrôles de la base de connaissances")
    def list_kb(domaine: Literal["securite", "performance", "stockage", "logiciels"] | None = None,
                recherche: str | None = Query(None, min_length=2)):
        items = [{"id": k, **{x: v[x] for x in ("domain", "category", "severity", "title")}}
                 for k, v in knowledge_base().items() if not k.startswith("_")]
        if domaine:
            items = [i for i in items if i["domain"] == domaine]
        if recherche:
            items = [i for i in items if recherche.lower() in i["title"].lower()]
        return _list(items)

    @app.get("/connaissances/{rule_id}", tags=["Référence"], summary="Explication complète d'un contrôle")
    def get_kb(rule_id: str):
        entry = knowledge_base().get(rule_id.upper())
        if entry is None or rule_id.startswith("_"):
            raise HTTPException(status_code=404, detail=f"Contrôle inconnu : {rule_id}")
        return {"id": rule_id.upper(), **entry}

    @app.get("/sante", tags=["Référence"], summary="État du service")
    def health():
        return {"statut": "ok", "version": __version__, "scans": len(store.all()), "ia_configuree": ia_configuree()}

    # ------------------------------------------------------------------ site web
    # Le dossier web/ est un site statique autonome (publiable tel quel sur GitHub Pages ou Hostinger).
    # Servi ici à la racine, après les routes de l'API (qui restent prioritaires) :
    #   /                       site public : guide + analyse d'un rapport dans le navigateur
    #   /?mode=serveur          tableau de bord alimenté par cette API (rapports du dossier de données)
    if WEB_DIR.is_dir():
        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="site")

    return app


try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except ImportError:
    pass

app = create_app()
