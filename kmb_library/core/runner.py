"""Orchestration d'un scan : collecte -> enrichissement -> règles -> scores -> rapport."""

from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Callable

from kmb_library import __version__
from kmb_library.collectors import collectors_for, detect_os_family
from kmb_library.core.anonymize import anonymize, identities_from_raw
from kmb_library.core.context import ScanContext
from kmb_library.core.models import CollectorStatus, ScanReport
from kmb_library.core.scoring import build_plan, compute_scores, summarize
from kmb_library.core.utils import is_admin, now_iso
from kmb_library.enrich.endoflife import enrich
from kmb_library.rules.engine import evaluate

Progress = Callable[[str], None]


def new_scan_id() -> str:
    return f"{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"


def collect_raw(ctx: ScanContext, progress: Progress | None = None) -> dict:
    """Étape A : exécute tous les collecteurs ; un collecteur en échec n'arrête jamais le scan."""
    os_family = detect_os_family()
    raw = {"scan_id": new_scan_id(), "started_at": now_iso(), "kmb_version": __version__,
           "os_family": os_family, "is_admin": is_admin(), "collectors": {}}
    for module in collectors_for(os_family):
        if progress:
            progress(f"Collecte : {module.LABEL}...")
        t0 = time.perf_counter()
        try:
            data = module.collect(ctx)
            errors = data.get("_errors") or {}
            status = "ignore" if data.get("skipped") else ("partiel" if errors else "ok")
            entry = {"status": status, "errors": errors, "data": data}
        except Exception as exc:  # noqa: BLE001
            entry = {"status": "erreur", "errors": {"collecteur": f"{type(exc).__name__}: {exc}"}, "data": {}}
        entry["duration_s"] = round(time.perf_counter() - t0, 2)
        raw["collectors"][module.NAME] = entry
    raw["finished_at"] = now_iso()
    return raw


def _inventory(raw: dict, enr: dict) -> dict:
    """Données de consultation (vue + API) extraites et organisées à partir du brut."""
    c = {k: (v.get("data") or {}) for k, v in raw["collectors"].items()}
    life = {s["name"]: s for s in enr.get("software_lifecycle", [])}
    software = []
    for app in c.get("software", {}).get("installed") or []:
        lc = life.get(app["name"], {})
        software.append({**app, "lifecycle": lc.get("status", "non_suivi"), "eol": lc.get("eol"),
                         "latest": lc.get("latest"), "product": lc.get("product")})
    sysd, perf, st, net = c.get("system", {}), c.get("performance", {}), c.get("storage", {}), c.get("network", {})
    wifi, hw = c.get("wifi", {}), c.get("hardware", {})
    return {
        "system": {"os": sysd.get("os"), "hardware": sysd.get("hardware"), "firmware": sysd.get("firmware"),
                   "hotfixes": sysd.get("hotfixes"), "last_update_date": sysd.get("last_update_date"),
                   "pending_updates": sysd.get("pending_updates"), "os_lifecycle": enr.get("os_lifecycle")},
        "wifi": {k: wifi.get(k) for k in ("available", "current", "profiles")},
        "hardware": {k: hw.get(k) for k in ("battery_present", "battery", "temperatures", "max_temperature_c")},
        "software": software,
        "software_cleaning": c.get("software", {}).get("cleaning"),
        "performance": {k: perf.get(k) for k in ("cpu", "memory", "top_memory", "top_cpu", "process_count",
                                                  "startup", "services_enabled", "boot_time", "uptime_days", "battery")},
        "storage": {k: st.get(k) for k in ("partitions", "physical_disks", "folders", "large_files", "truncated", "space_by_folder",
                                            "zones", "recoverable", "apps", "system_estimate_gb", "measured_gb",
                                            "files_scanned", "cloud_only_files")},
        "duplicates": c.get("duplicates", {}),
        "network": {"listening": net.get("listening"), "dns_servers": net.get("dns_servers"),
                    "interfaces": net.get("interfaces"), "smb_shares": net.get("smb_shares")},
    }


def process(raw: dict, ctx: ScanContext, anonymized: bool = False, progress: Progress | None = None) -> ScanReport:
    """Étape B : enrichit, applique les règles, calcule les scores et construit le rapport."""
    if progress:
        progress("Enrichissement : cycle de vie des logiciels (endoflife.date)...")
    enr = enrich(raw, ctx.cache_dir, offline=ctx.offline)
    if progress:
        progress("Analyse : application des règles...")
    findings = evaluate(raw, enr)
    sysd = raw["collectors"].get("system", {}).get("data") or {}
    os_info = sysd.get("os") or {}
    t0 = datetime.fromisoformat(raw["started_at"])
    t1 = datetime.fromisoformat(raw.get("finished_at") or raw["started_at"])
    report = ScanReport(
        scan_id=raw["scan_id"],
        machine_name=sysd.get("hostname") or "inconnu",
        display_name=(ctx.display_name or "").strip() or None,
        device_model=" ".join(x for x in ((sysd.get("hardware") or {}).get("manufacturer"),
                                          (sysd.get("hardware") or {}).get("model")) if x) or None,
        os=" ".join(x for x in (os_info.get("caption"), os_info.get("display_version")) if x) or raw.get("os_family", "?"),
        os_family=raw.get("os_family", "windows"),
        os_version=(f"{os_info.get('version')}.{os_info.get('ubr')}" if os_info.get("ubr")
                    else os_info.get("kernel") and f"{os_info.get('version') or ''} (noyau {os_info['kernel']})".strip()
                    or os_info.get("version")),
        scan_date=raw["started_at"],
        kmb_version=raw["kmb_version"],
        duration_s=round((t1 - t0).total_seconds(), 1),
        is_admin=raw.get("is_admin", False),
        scores=compute_scores(findings),
        summary=summarize(findings),
        findings=findings,
        plan=build_plan(findings),
        inventory=_inventory(raw, enr),
        collectors={k: CollectorStatus(status=v["status"], duration_s=v["duration_s"], errors=v["errors"])
                    for k, v in raw["collectors"].items()},
        sources=enr.get("sources", []),
    )
    if anonymized:
        host, users, nets = identities_from_raw(raw)
        data = anonymize(report.model_dump(), host, users, nets)
        data["anonymized"] = True
        report = ScanReport.model_validate(data)
    return report


def run_scan(ctx: ScanContext, anonymized: bool = False, progress: Progress | None = None) -> tuple[dict, ScanReport]:
    raw = collect_raw(ctx, progress)
    report = process(raw, ctx, anonymized, progress)
    if anonymized:
        host, users, nets = identities_from_raw(raw)
        raw = anonymize(raw, host, users, nets)
    return raw, report
