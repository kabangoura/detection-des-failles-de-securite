"""Structure des données traitées (rapport JSON standardisé de KMB Library)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critique", "eleve", "moyen", "faible", "info"]
Status = Literal["detecte", "conforme", "non_verifiable"]
Domain = Literal["securite", "performance", "stockage", "logiciels"]

SEVERITIES: tuple[str, ...] = ("critique", "eleve", "moyen", "faible", "info")
DOMAINS: tuple[str, ...] = ("securite", "performance", "stockage", "logiciels")
SEVERITY_LABELS = {"critique": "Critique", "eleve": "Élevé", "moyen": "Moyen", "faible": "Faible", "info": "Information"}
DOMAIN_LABELS = {"securite": "Sécurité", "performance": "Performance", "stockage": "Stockage", "logiciels": "Logiciels"}


class Command(BaseModel):
    """Une commande que l'utilisateur lance lui-même (KMB ne l'exécute jamais)."""

    type: Literal["verifier", "ouvrir", "corriger"] = Field(..., description="verifier : montre le problème ; ouvrir : ouvre le réglage ; corriger : corrige directement")
    cmd: str = Field(..., description="Commande exacte à copier")
    ou: Literal["cmd", "cmd_admin", "ps", "ps_admin", "terminal"] = Field(..., description="Où la taper")
    effet: str = Field(..., description="Ce que fait la commande")
    attendu: str | None = Field(None, description="Ce qu'on doit voir si tout va bien (vérification)")
    remplacer: dict[str, str] | None = Field(None, description="Mots à remplacer avant de lancer la commande")
    attention: str | None = Field(None, description="Avertissement")


class Remediation(BaseModel):
    steps: list[str] = Field(default_factory=list, description="Étapes manuelles détaillées")
    commands: dict[str, list[Command | str]] = Field(default_factory=dict, description="Commandes par système (windows, linux, macos)")
    duration: str | None = Field(None, description="Durée estimée de la correction")
    requires_admin: bool = False


class Finding(BaseModel):
    """Résultat d'un contrôle. `key` est unique dans un scan et stable d'un scan à l'autre."""

    key: str = Field(..., description="Identifiant unique et stable, ex. 'FW-001:Public'")
    id: str = Field(..., description="Identifiant de la règle, ex. 'FW-001'")
    domain: Domain
    category: str
    title: str
    severity: Severity
    status: Status
    description: str = ""
    danger: str | None = None
    impact: str | None = None
    evidence: str | None = None
    location: str | None = None
    risk_score: float = Field(0.0, ge=0, le=10, description="Score de risque indicatif 0-10 (inspiré de CVSS)")
    penalty: int = Field(0, description="Points retirés au score du domaine si le problème est détecté")
    remediation: Remediation = Field(default_factory=Remediation)
    references: list[str] = Field(default_factory=list)
    details: dict[str, Any] | None = None


class CollectorStatus(BaseModel):
    status: Literal["ok", "partiel", "erreur", "ignore"]
    duration_s: float = 0.0
    errors: dict[str, str] = Field(default_factory=dict)


class PlanStep(BaseModel):
    priority: int
    key: str
    title: str
    severity: Severity
    domain: Domain
    gain: str
    duration: str | None = None


class ScanReport(BaseModel):
    schema_version: str = "1.0"
    scan_id: str
    machine_name: str = Field(..., description="Nom réseau de l'ordinateur (ex. DESKTOP-ABC123)")
    display_name: str | None = Field(None, description="Nom choisi par l'utilisateur (option --nom)")
    device_model: str | None = Field(None, description="Fabricant et modèle (ex. HP EliteBook Folio 9480m)")
    os: str
    os_family: str = "windows"
    os_version: str | None = None
    scan_date: str
    kmb_version: str
    duration_s: float = 0.0
    is_admin: bool = False
    anonymized: bool = False
    scores: dict[str, int] = Field(default_factory=dict, description="securite, performance, stockage, logiciels, global")
    summary: dict[str, int] = Field(default_factory=dict, description="Nombre de problèmes détectés par gravité")
    findings: list[Finding] = Field(default_factory=list)
    plan: list[PlanStep] = Field(default_factory=list, description="Plan de correction priorisé")
    inventory: dict[str, Any] = Field(default_factory=dict)
    collectors: dict[str, CollectorStatus] = Field(default_factory=dict)
    sources: list[dict[str, Any]] = Field(default_factory=list)

    def detected(self) -> list[Finding]:
        return [f for f in self.findings if f.status == "detecte"]
