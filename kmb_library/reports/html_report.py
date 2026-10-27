"""Rapport HTML autonome (un seul fichier, consultable hors ligne, sans serveur)."""

from __future__ import annotations

from html import escape
from pathlib import Path

from kmb_library.core.models import DOMAIN_LABELS, SEVERITY_LABELS, ScanReport
from kmb_library.core.utils import human_size

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--muted:#5d6878;--line:#e2e6ec;--accent:#2357d9;
--critique:#b3261e;--eleve:#d4561c;--moyen:#b58200;--faible:#2f7d4f;--info:#5d6878}
@media (prefers-color-scheme:dark){:root{--bg:#12161d;--card:#1b212b;--fg:#e6e9ee;--muted:#9aa4b2;--line:#2b3340;--accent:#7aa2ff;
--critique:#ff6b62;--eleve:#ff9356;--moyen:#e7b632;--faible:#5fc48a;--info:#9aa4b2}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1100px;margin:auto;padding:24px 16px}h1{margin:0 0 4px}h2{margin:32px 0 12px;font-size:20px}
.muted{color:var(--muted)}.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(160px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.score{font-size:34px;font-weight:700}.score small{font-size:15px;color:var(--muted);font-weight:400}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;color:#fff}
.b-critique{background:var(--critique)}.b-eleve{background:var(--eleve)}.b-moyen{background:var(--moyen)}
.b-faible{background:var(--faible)}.b-info{background:var(--info)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:10px 14px}
summary{cursor:pointer;font-weight:600}code,pre{font-family:Consolas,monospace;font-size:13px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;overflow-x:auto;white-space:pre-wrap}
table{width:100%;border-collapse:collapse;background:var(--card)}td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
.table-wrap{overflow-x:auto}
"""


TYPE_LABEL = {"verifier": "Vérifier", "ouvrir": "Ouvrir le réglage", "corriger": "Corriger"}
WHERE_LABEL = {"cmd": "Invite de commandes", "cmd_admin": "Invite de commandes (administrateur)", "ps": "PowerShell",
               "ps_admin": "PowerShell (administrateur)", "terminal": "Terminal"}


def _badge(sev: str) -> str:
    return f'<span class="badge b-{sev}">{escape(SEVERITY_LABELS.get(sev, sev))}</span>'


def render(report: ScanReport) -> str:
    r = report
    e = escape
    cards = "".join(
        f'<div class="card"><div class="muted">{e(DOMAIN_LABELS.get(k, "Global"))}</div>'
        f'<div class="score">{v}<small>/100</small></div></div>'
        for k, v in r.scores.items()
    )
    summary = " ".join(f"{_badge(s)} {r.summary.get(s, 0)}" for s in ("critique", "eleve", "moyen", "faible", "info"))
    plan_rows = "".join(
        f"<tr><td>{p.priority}</td><td>{_badge(p.severity)}</td><td>{e(p.title)}</td><td>{e(p.gain)}</td><td>{e(p.duration or '')}</td></tr>"
        for p in r.plan
    )
    items = []
    for f in sorted(r.detected(), key=lambda f: ("critique", "eleve", "moyen", "faible", "info").index(f.severity)):
        steps = "".join(f"<li>{e(s)}</li>" for s in f.remediation.steps)
        own = f.remediation.commands.get(r.os_family) or [c for lst in f.remediation.commands.values() for c in lst]
        cmds = "\n".join(c if isinstance(c, str) else f"[{TYPE_LABEL[c.type]} · {WHERE_LABEL[c.ou]}] {c.cmd}" for c in own)
        items.append(
            f"<details><summary>{_badge(f.severity)} {e(f.title)} <span class='muted'>({e(f.key)})</span></summary>"
            f"<p><b>Constat :</b> {e(f.evidence or '')}</p><p><b>De quoi s'agit-il ?</b> {e(f.description)}</p>"
            f"<p><b>Pourquoi est-ce dangereux ?</b> {e(f.danger or '')}</p><p><b>Impact :</b> {e(f.impact or '')}</p>"
            f"<p><b>Emplacement :</b> {e(f.location or '')}</p><p><b>Correction :</b></p><ol>{steps}</ol>"
            + (f"<pre>{e(cmds)}</pre>" if cmds else "") + "</details>"
        )
    unverified = "".join(f"<li>{e(f.title)} : <span class='muted'>{e(f.evidence or '')}</span></li>"
                         for f in r.findings if f.status == "non_verifiable")
    ok = "".join(f"<li>{e(f.title)} : <span class='muted'>{e(f.evidence or '')}</span></li>"
                 for f in r.findings if f.status == "conforme")
    dup = r.inventory.get("duplicates") or {}
    dup_rows = "".join(
        f"<tr><td>{g['count']}</td><td>{human_size(g['size_bytes'])}</td><td>{'<br>'.join(e(p) for p in g['files'])}</td></tr>"
        for g in (dup.get("groups") or [])[:30]
    )
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Rapport KMB {e(r.scan_id)}</title><style>{_CSS}</style></head>
<body><main>
<h1>Rapport KMB Library</h1>
<p class="muted">{e(r.display_name or r.machine_name)}{" (" + e(r.machine_name) + ")" if r.display_name else ""}{" · " + e(r.device_model) if r.device_model else ""} · {e(r.os)} · scan du {e(r.scan_date[:16].replace('T', ' '))} · durée {r.duration_s} s ·
{'administrateur' if r.is_admin else 'sans droits administrateur'}{' · anonymisé' if r.anonymized else ''}</p>
<div class="grid">{cards}</div>
<p>{summary}</p>
<h2>Plan de correction priorisé</h2>
<div class="table-wrap"><table><tr><th>#</th><th>Gravité</th><th>Action</th><th>Gain</th><th>Durée</th></tr>{plan_rows}</table></div>
<h2>Problèmes détectés ({len(r.detected())})</h2>{''.join(items) or '<p>Aucun problème détecté.</p>'}
<h2>Doublons ({dup.get('group_count', 0)} groupes, {human_size(dup.get('wasted_bytes', 0))} récupérables)</h2>
<div class="table-wrap"><table><tr><th>Copies</th><th>Taille</th><th>Fichiers</th></tr>{dup_rows}</table></div>
<h2>Contrôles non vérifiables</h2><ul>{unverified or '<li>Aucun</li>'}</ul>
<h2>Contrôles conformes</h2><ul>{ok}</ul>
<p class="muted">Généré par KMB Library {e(r.kmb_version)}. Sources : {', '.join(sorted({e(s.get('name', '')) for s in r.sources})) or 'aucune'}.</p>
</main></body></html>"""


def save_html(report: ScanReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    from kmb_library.reports.json_report import report_filename

    path = out_dir / report_filename(report).replace(".json", ".html")
    path.write_text(render(report), encoding="utf-8")
    return path
