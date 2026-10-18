// Site KMB Library.
// Mode « local » (par défaut, site public) : le rapport est lu par le navigateur, rien n'est envoyé.
// Mode « serveur » (?mode=serveur) : tableau de bord alimenté par l'API FastAPI locale.
"use strict";

const MODE = new URLSearchParams(location.search).get("mode") === "serveur" ? "serveur" : "local";
const CONFIG = window.KMB_CONFIG || {};
const SEV = ["critique", "eleve", "moyen", "faible", "info"];
const SEV_LABEL = { critique: "Critique", eleve: "Élevé", moyen: "Moyen", faible: "Faible", info: "Information" };
const SEV_RANK = { critique: 0, eleve: 1, moyen: 2, faible: 3, info: 4 };
const DOMAIN_LABEL = { securite: "Sécurité", performance: "Performance", stockage: "Stockage", logiciels: "Logiciels", global: "Global" };
const LIFE_LABEL = { fin_de_support: "Fin de support", maj_disponible: "Mise à jour disponible", supporte: "Supporté", inconnu: "Inconnu", non_suivi: "Non suivi" };
const STATUS_LABEL = { detecte: "Détecté", conforme: "Conforme", non_verifiable: "Non vérifiable" };
const OS_LABEL = { windows: "Windows", linux: "Linux", macos: "macOS" };
const WIFI_LABEL = { ouvert: "ouvert (non chiffré)", wep: "WEP (obsolète)", wpa: "WPA (obsolète)", wpa2: "WPA2", wpa3: "WPA3", entreprise: "Entreprise (802.1X)", inconnu: "inconnu" };

const state = { scans: [], report: null, charts: {}, local: new Map() };
const $ = (sel) => document.querySelector(sel);

// ------------------------------------------------------------------ utilitaires
function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
function badge(sev) { return `<span class="badge b-${sev}">${SEV_LABEL[sev] || sev}</span>`; }
function fmtDate(iso) { return iso ? iso.slice(0, 16).replace("T", " ") : "—"; }
function size(bytes) {
  if (bytes == null) return "—";
  const u = ["o", "Ko", "Mo", "Go", "To"]; let i = 0; let n = bytes;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
function scoreColor(v) { return v >= 80 ? cssVar("--ok") : v >= 60 ? cssVar("--moyen") : cssVar("--critique"); }
function machineLabel(r) { return r.display_name || r.machine_name; }
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.hidden = true), 6000);
}
function qs(form) {
  const p = new URLSearchParams();
  for (const [k, v] of new FormData(form)) if (v !== "") p.append(k, v);
  return p.toString();
}
function chart(id, config) {
  if (!window.Chart) return;
  state.charts[id]?.destroy();
  state.charts[id] = new Chart(document.getElementById(id), config);
}
function debounce(fn, ms = 250) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
function apiError(status, message) { const e = new Error(message); e.status = status; return e; }

// ------------------------------------------------------------------ accès aux données
async function api(path, opts = {}) {
  if (MODE === "local") return localApi(path, opts);
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw apiError(res.status, body.detail || `Erreur HTTP ${res.status}`);
  return body;
}

function summaryOf(r) {
  return { scan_id: r.scan_id, machine_name: r.machine_name, display_name: r.display_name, device_model: r.device_model,
           os: r.os, os_family: r.os_family, scan_date: r.scan_date, scores: r.scores, summary: r.summary };
}
function sortedLocal() { return [...state.local.values()].sort((a, b) => (a.scan_date < b.scan_date ? 1 : -1)); }
function getLocal(id) {
  const r = id === "dernier" ? sortedLocal()[0] : state.local.get(id);
  if (!r) throw apiError(404, `Rapport introuvable : ${id}`);
  return r;
}
function listResult(items, empty) { const out = { total: items.length, resultats: items }; if (!items.length) out.message = empty; return out; }

// Mêmes règles que l'API FastAPI, appliquées dans le navigateur
function localApi(path, opts) {
  const url = new URL(path, location.href);
  const p = url.searchParams;
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts[0] === "scans" && parts.length === 1) return listResult(sortedLocal().map(summaryOf), "Aucun rapport chargé.");
  if (parts[0] === "scans" && parts.length === 2) return getLocal(decodeURIComponent(parts[1]));
  if (parts[0] === "scans" && parts[2] === "findings") {
    const r = getLocal(decodeURIComponent(parts[1]));
    let items = r.findings;
    const statut = p.get("statut") || "detecte";
    if (statut !== "tous") items = items.filter((f) => f.status === statut);
    const sev = p.getAll("severite");
    if (sev.length) items = items.filter((f) => sev.includes(f.severity));
    if (p.get("domaine")) items = items.filter((f) => f.domain === p.get("domaine"));
    const q = (p.get("recherche") || "").toLowerCase();
    if (q) items = items.filter((f) => f.title.toLowerCase().includes(q) || (f.evidence || "").toLowerCase().includes(q) || f.key.toLowerCase().includes(q));
    items = [...items].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
    return listResult(items, "Aucun problème ne correspond à ces critères.");
  }
  if (parts[0] === "scans" && parts[2] === "logiciels") {
    const r = getLocal(decodeURIComponent(parts[1]));
    let items = r.inventory?.software || [];
    const q = (p.get("recherche") || "").toLowerCase();
    if (q) items = items.filter((s) => s.name.toLowerCase().includes(q) || String(s.publisher || "").toLowerCase().includes(q));
    if (p.get("cycle_de_vie")) items = items.filter((s) => s.lifecycle === p.get("cycle_de_vie"));
    const res = listResult(items.slice(0, 200), "Aucun logiciel ne correspond à ces critères.");
    res.total = items.length;
    return res;
  }
  if (parts[0] === "scans" && parts[2] === "plan-ia") {
    throw apiError(501, "Le plan IA (Grok) n'est disponible qu'avec l'outil installé (commande « kmb plan-ia »).");
  }
  if (parts[0] === "statistiques") {
    const m = p.get("machine");
    const reports = sortedLocal().filter((r) => !m || r.machine_name === m);
    return { nb_scans: reports.length, evolution: [...reports].reverse().map((r) => ({ scan_id: r.scan_id, date: r.scan_date, scores: r.scores })) };
  }
  if (parts[0] === "comparaison") {
    const old = getLocal(p.get("ancien")); const nw = getLocal(p.get("nouveau") || "dernier");
    if (old.scan_id === nw.scan_id) throw apiError(422, "Choisissez deux rapports différents.");
    return compareReports(old, nw);
  }
  throw apiError(404, "Page introuvable");
}

// Même logique que kmb_library/core/compare.py
function compareReports(old, nw) {
  const brief = (f) => ({ key: f.key, id: f.id, title: f.title, severity: f.severity, domain: f.domain, evidence: f.evidence });
  const oldDet = new Map(old.findings.filter((f) => f.status === "detecte").map((f) => [f.key, f]));
  const newDet = new Map(nw.findings.filter((f) => f.status === "detecte").map((f) => [f.key, f]));
  const newAll = new Map(nw.findings.map((f) => [f.key, f]));
  const unverifiedRules = new Set(nw.findings.filter((f) => f.status === "non_verifiable").map((f) => f.id));
  const fixed = []; const unverified = [];
  for (const [key, f] of oldDet) {
    if (newDet.has(key)) continue;
    const nf = newAll.get(key);
    if ((nf && nf.status === "non_verifiable") || (!nf && unverifiedRules.has(f.id))) unverified.push(brief(f)); else fixed.push(brief(f));
  }
  const remaining = [...newDet.keys()].filter((k) => oldDet.has(k)).map((k) => brief(newDet.get(k)));
  const added = [...newDet].filter(([k]) => !oldDet.has(k)).map(([, f]) => brief(f));
  const delta = {}; for (const k of Object.keys(nw.scores)) delta[k] = nw.scores[k] - (old.scores[k] || 0);
  const warnings = [];
  if (old.machine_name !== nw.machine_name) warnings.push(`Les rapports proviennent de deux ordinateurs différents (${machineLabel(old)} / ${machineLabel(nw)}).`);
  if (old.scan_date > nw.scan_date) warnings.push("Le rapport « avant » est plus récent que le rapport « après ».");
  if (old.is_admin !== nw.is_admin) warnings.push("Les deux scans n'ont pas été lancés avec les mêmes droits : certains contrôles diffèrent.");
  return { ancien: { scan_id: old.scan_id, date: old.scan_date, scores: old.scores }, nouveau: { scan_id: nw.scan_id, date: nw.scan_date, scores: nw.scores },
           evolution_scores: delta, resume: { corriges: fixed.length, restants: remaining.length, nouveaux: added.length, non_verifiables: unverified.length },
           corriges: fixed, restants: remaining, nouveaux: added, non_verifiables: unverified, avertissements: warnings };
}

// ------------------------------------------------------------------ chargement des fichiers (mode local)
function validateReport(doc, fileName) {
  if (doc && doc.collectors && doc.started_at && !doc.findings) {
    throw new Error(`« ${fileName} » contient les données brutes. Choisissez plutôt le fichier qui commence par KMB-rapport_ (dans le dossier Documents\\KMB Library).`);
  }
  if (!doc || !doc.scan_id || !Array.isArray(doc.findings) || !doc.scores) {
    throw new Error(`« ${fileName} » n'est pas un rapport KMB. Choisissez le fichier KMB-rapport_….json créé par le scanner.`);
  }
  return doc;
}

async function addFiles(files) {
  let last = null;
  for (const file of files) {
    try {
      const doc = validateReport(JSON.parse(await file.text()), file.name);
      if (MODE === "serveur") {
        const res = await api("/scans", { method: "POST", body: JSON.stringify(doc) });
        last = res.scan_id;
      } else {
        state.local.set(doc.scan_id, doc);
        last = doc.scan_id;
      }
    } catch (err) {
      toast(err instanceof SyntaxError ? `« ${file.name} » n'est pas un fichier JSON valide.` : err.message);
    }
  }
  if (last) { await loadScans(last); showPage("analyser"); }
}

async function loadExample() {
  try {
    const res = await fetch(CONFIG.exampleReport || "exemple/KMB-rapport_exemple.json");
    if (!res.ok) throw new Error();
    const doc = validateReport(await res.json(), "exemple");
    state.local.set(doc.scan_id, doc);
    await loadScans(doc.scan_id);
  } catch { toast("L'exemple n'est pas disponible."); }
}

// ------------------------------------------------------------------ rapports
async function loadScans(selectId) {
  const data = await api("/scans?limit=200");
  state.scans = data.resultats;
  const has = state.scans.length > 0;
  $("#dashboard").hidden = !has;
  $("#upload-zone").hidden = has || MODE === "serveur";
  if (!has) { if (MODE === "serveur") toast("Aucun rapport dans le dossier de données du serveur."); return; }
  const opts = state.scans.map((s) => `<option value="${esc(s.scan_id)}">${fmtDate(s.scan_date)} · ${esc(machineLabel(s))} · ${OS_LABEL[s.os_family] || ""} · ${s.scores.global}/100</option>`).join("");
  $("#scan-select").innerHTML = opts;
  $("#c-old").innerHTML = opts; $("#c-new").innerHTML = opts;
  if (state.scans.length > 1) $("#c-old").selectedIndex = 1;
  const id = selectId || state.scans[0].scan_id;
  $("#scan-select").value = id;
  $("#c-out").innerHTML = "";
  await loadReport(id);
}

async function loadReport(id) {
  state.report = await api(`/scans/${encodeURIComponent(id)}`);
  renderOverview();
  loadFindings();
  renderPlan();
  loadSoftware();
  renderStorage();
  renderPerformance();
  showTab(document.querySelector(".tabs button.active").dataset.tab);
}

// ------------------------------------------------------------------ vue d'ensemble
async function renderOverview() {
  const r = state.report;
  const life = r.inventory.system?.os_lifecycle || {};
  const name = r.display_name ? `<b>${esc(r.display_name)}</b> <span class="muted">(${esc(r.machine_name)})</span>` : `<b>${esc(r.machine_name)}</b>`;
  $("#meta").innerHTML = `${name}${r.device_model ? " · " + esc(r.device_model) : ""} · <span class="badge b-info">${OS_LABEL[r.os_family] || esc(r.os_family || "Windows")}</span> ${esc(r.os)} (${esc(r.os_version || "")})
    · scan du ${fmtDate(r.scan_date)} · ${r.duration_s} s · ${r.is_admin ? "administrateur" : "sans droits administrateur"}
    ${r.anonymized ? " · anonymisé" : ""}${life.eol ? ` · fin de support du système : ${esc(life.eol)}` : ""}`;
  const order = ["global", "securite", "performance", "stockage", "logiciels"];
  $("#scores").innerHTML = order.map((k) => {
    const v = r.scores[k];
    return `<div class="score ${k === "global" ? "global" : ""}"><div class="label">${DOMAIN_LABEL[k]}</div>
      <div class="value">${v}<small>/100</small></div><div class="bar"><span style="width:${v}%;background:${scoreColor(v)}"></span></div></div>`;
  }).join("");

  const counts = SEV.map((s) => r.summary[s] || 0);
  const colors = SEV.map((s) => cssVar(`--${s}`));
  $("#sev-legend").innerHTML = SEV.map((s, i) => `<span><i style="background:${colors[i]}"></i>${SEV_LABEL[s]} : <b>${counts[i]}</b></span>`).join("")
    + `<span class="muted">· ${r.summary.conformes} conformes · ${r.summary.non_verifiables} non vérifiables</span>`;
  chart("chart-sev", {
    type: "bar",
    data: { labels: SEV.map((s) => SEV_LABEL[s]), datasets: [{ data: counts, backgroundColor: colors, borderRadius: 4 }] },
    options: { maintainAspectRatio: false, plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0, color: cssVar("--muted") }, grid: { color: cssVar("--line") } },
                x: { ticks: { color: cssVar("--muted") }, grid: { display: false } } } },
  });

  const stats = await api(`/statistiques?machine=${encodeURIComponent(r.machine_name)}`);
  const evo = stats.evolution || [];
  $("#evo-note").textContent = evo.length < 2
    ? (MODE === "local" ? "Ajoutez un deuxième rapport de cet ordinateur (après vos corrections) pour voir l'évolution." : "Un seul scan pour cette machine.")
    : `${evo.length} rapports pour cet ordinateur.`;
  const lineColors = { global: cssVar("--accent"), securite: cssVar("--critique"), performance: cssVar("--faible"), stockage: cssVar("--moyen"), logiciels: cssVar("--info") };
  chart("chart-evo", {
    type: "line",
    data: { labels: evo.map((e) => fmtDate(e.date)),
      datasets: order.map((k) => ({ label: DOMAIN_LABEL[k], data: evo.map((e) => e.scores[k]), borderColor: lineColors[k], backgroundColor: lineColors[k],
        borderWidth: k === "global" ? 3 : 1.5, pointRadius: 3, tension: 0.2 })) },
    options: { maintainAspectRatio: false, plugins: { legend: { labels: { color: cssVar("--muted"), boxWidth: 10 } } },
      scales: { y: { min: 0, max: 100, ticks: { color: cssVar("--muted") }, grid: { color: cssVar("--line") } }, x: { ticks: { color: cssVar("--muted") }, grid: { display: false } } } },
  });

  $("#top-plan").innerHTML = r.plan.slice(0, 6).map((p) => `<li>${badge(p.severity)} ${esc(p.title)} <span class="muted small">(${esc(p.gain)})</span></li>`).join("")
    || "<li>Aucune action nécessaire.</li>";
  const LBL = { system: "Système", accounts: "Comptes", network: "Réseau", firewall: "Pare-feu", antivirus: "Antivirus", encryption: "Chiffrement",
                software: "Logiciels", performance: "Performance", storage: "Stockage", duplicates: "Doublons", wifi: "Wi-Fi", hardware: "Matériel" };
  const ST = { ok: "terminé", partiel: "partiel", erreur: "erreur", ignore: "ignoré" };
  $("#collectors").innerHTML = "<tr><th>Partie examinée</th><th>État</th><th class='num'>Durée</th><th>Remarque</th></tr>" +
    Object.entries(r.collectors).map(([k, c]) => `<tr><td>${LBL[k] || k}</td><td>${ST[c.status] || esc(c.status)}</td><td class="num">${c.duration_s} s</td>
      <td class="small muted">${esc(Object.values(c.errors || {})[0] || "")}</td></tr>`).join("");
}

// ------------------------------------------------------------------ problèmes
function findingHtml(f) {
  const steps = (f.remediation.steps || []).map((s) => `<li>${esc(s)}</li>`).join("");
  const all = f.remediation.commands || {};
  const own = all[state.report?.os_family || "windows"];
  const cmds = own || Object.values(all).flat();
  const cmdHtml = cmds.map((c) => `<div class="cmd"><pre>${esc(c)}</pre><button type="button" data-copy="${esc(c)}">Copier</button></div>`).join("");
  return `<details class="finding sev-${f.status === "detecte" ? f.severity : "info"}">
    <summary>${badge(f.severity)} <span>${esc(f.title)}</span> <span class="st st-${f.status}">${STATUS_LABEL[f.status]}</span><span class="key">${esc(f.key)}</span></summary>
    <div class="body">
      <p><b>Constat :</b> ${esc(f.evidence || "—")}</p>
      <dl>
        <dt>De quoi s'agit-il ?</dt><dd>${esc(f.description)}</dd>
        ${f.danger ? `<dt>Pourquoi est-ce dangereux ?</dt><dd>${esc(f.danger)}</dd>` : ""}
        ${f.impact ? `<dt>Conséquences possibles</dt><dd>${esc(f.impact)}</dd>` : ""}
        ${f.location ? `<dt>Où se trouve-t-il ?</dt><dd>${esc(f.location)}</dd>` : ""}
        <dt>Comment corriger${f.remediation.duration ? ` (${esc(f.remediation.duration)})` : ""}${f.remediation.requires_admin ? " · droits administrateur requis" : ""}</dt>
        <dd><ol>${steps}</ol>${cmdHtml}</dd>
      </dl>
      ${f.references?.length ? `<p class="small">Références : ${f.references.map((u) => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a>`).join(" · ")}</p>` : ""}
      <p class="small muted">Score de risque indicatif : ${f.risk_score}/10 · pénalité : ${f.penalty} points (${DOMAIN_LABEL[f.domain]})</p>
    </div></details>`;
}

async function loadFindings() {
  if (!state.report) return;
  const form = $("#f-form");
  if (form.recherche.value && form.recherche.value.length < 2) return;
  try {
    const data = await api(`/scans/${encodeURIComponent(state.report.scan_id)}/findings?${qs(form)}`);
    $("#f-count").textContent = data.message || `${data.total} résultat(s)`;
    $("#f-list").innerHTML = data.resultats.map(findingHtml).join("");
  } catch (e) { toast(e.message); }
}

// ------------------------------------------------------------------ plan
async function renderPlan() {
  const r = state.report;
  $("#plan-table").innerHTML = "<tr><th>#</th><th>Gravité</th><th>Action</th><th>Gain</th><th>Durée</th></tr>" +
    (r.plan.map((p) => `<tr><td>${p.priority}</td><td>${badge(p.severity)}</td><td>${esc(p.title)}<div class="small muted">${esc(p.key)}</div></td>
      <td>${esc(p.gain)}</td><td>${esc(p.duration || "")}</td></tr>`).join("") || "<tr><td colspan='5'>Aucune action nécessaire.</td></tr>");
  $("#ai-out").innerHTML = "";
  if (MODE === "local") return;
  try { renderAi(await api(`/scans/${encodeURIComponent(r.scan_id)}/plan-ia`)); } catch (e) { if (e.status !== 404) toast(e.message); }
}

function renderAi(plan) {
  const v = plan.verification || {};
  const steps = (plan.priorites || []).map((s) => `<div class="ai-step ${s.verifie ? "" : "unverified"}">
    <div class="row-between"><b>${esc(s.ordre)}. ${esc(s.titre)}</b>
      <span class="small ${s.verifie ? "st-conforme" : "st-detecte"}">${s.verifie ? "✓ lié au constat " + esc(s.key) : "⚠ non vérifiée (clé inconnue : " + esc(s.key) + ")"}</span></div>
    <p>${esc(s.pourquoi || "")}</p>
    <ol>${(s.etapes || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ol>
    ${(s.commandes || []).map((c) => `<div class="cmd"><pre>${esc(c)}</pre><button type="button" data-copy="${esc(c)}">Copier</button></div>`).join("")}
    <p class="small muted">Gain estimé : ${esc(s.gain_estime || "—")} · durée : ${esc(s.duree || "—")}</p></div>`).join("");
  const missing = (v.problemes_graves_oublies || []).length ? `<p class="st-detecte small">Problèmes graves non traités par l'IA : ${v.problemes_graves_oublies.map(esc).join(", ")}</p>` : "";
  $("#ai-out").innerHTML = `<p>${esc(plan.resume || "")}</p>
    <p class="small ${v.fiable ? "st-conforme" : "st-detecte"}">Vérification : ${v.etapes || 0} étape(s), ${v.etapes_non_verifiees || 0} non vérifiée(s) — ${v.fiable ? "plan cohérent avec le scan" : "à relire avec prudence"}</p>
    ${missing}${steps}
    ${(plan.conseils_generaux || []).length ? `<h4>Conseils généraux</h4><ul>${plan.conseils_generaux.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>` : ""}
    <p class="small muted">${esc(plan.meta?.fournisseur || "")} · modèle ${esc(plan.meta?.modele || "")} · ${fmtDate(plan.meta?.genere_le)}</p>`;
  $("#ai-btn").textContent = "Régénérer le plan IA";
}

async function generateAi() {
  const btn = $("#ai-btn"); btn.disabled = true; const old = btn.textContent; btn.textContent = "Génération en cours…";
  try {
    const regen = old.startsWith("Régénérer") ? "?regenerer=true" : "";
    renderAi(await api(`/scans/${encodeURIComponent(state.report.scan_id)}/plan-ia${regen}`, { method: "POST" }));
  } catch (e) { toast(e.message); btn.textContent = old; } finally { btn.disabled = false; }
}

// ------------------------------------------------------------------ logiciels
async function loadSoftware() {
  if (!state.report) return;
  const form = $("#s-form");
  if (form.recherche.value && form.recherche.value.length < 2) return;
  try {
    const data = await api(`/scans/${encodeURIComponent(state.report.scan_id)}/logiciels?${qs(form)}`);
    $("#s-count").textContent = data.message || `${data.total} logiciel(s)${data.total > data.resultats.length ? ` — ${data.resultats.length} premiers affichés, affinez la recherche` : ""}`;
    const lifeBadge = (l) => ({ fin_de_support: `<span class="badge b-eleve">${LIFE_LABEL[l]}</span>`, maj_disponible: `<span class="badge b-faible">${LIFE_LABEL[l]}</span>` }[l]
      || `<span class="muted small">${LIFE_LABEL[l] || esc(l)}</span>`);
    $("#s-table").innerHTML = "<tr><th>Logiciel</th><th>Version</th><th>Éditeur</th><th>Cycle de vie</th><th class='num'>Taille</th></tr>" +
      data.resultats.map((s) => `<tr><td>${esc(s.name)}</td><td>${esc(s.version || "")}</td><td>${esc(s.publisher || "")}</td>
        <td>${lifeBadge(s.lifecycle)}${s.eol ? `<div class="small muted">fin : ${esc(String(s.eol))}${s.latest ? " · dernière : " + esc(s.latest) : ""}</div>` : ""}</td>
        <td class="num">${s.size_mb ? s.size_mb + " Mo" : "—"}</td></tr>`).join("");
    const c = state.report.inventory.software_cleaning;
    if (c) $("#s-clean").textContent = `Nettoyage : ${c.raw_entries} entrées brutes → ${c.kept} logiciels retenus. Dates de fin de support : endoflife.date.`;
  } catch (e) { toast(e.message); }
}

// ------------------------------------------------------------------ stockage
function renderStorage() {
  const inv = state.report.inventory; const st = inv.storage || {}; const dup = inv.duplicates || {};
  $("#partitions").innerHTML = (st.partitions || []).map((p) => {
    const free = (100 - p.percent_used).toFixed(1);
    return `<p><b>${esc(p.mount)}</b> (${esc(p.fstype)}) — ${p.free_gb} Go libres sur ${p.total_gb} Go (${free} %)</p>
      <div class="bar"><span style="width:${p.percent_used}%;background:${scoreColor(100 - p.percent_used * 0.9)}"></span></div>`;
  }).join("") + (st.physical_disks || []).map((d) => `<p class="small muted">Disque : ${esc(d.name)} · ${esc(d.media_type)}${d.bus ? " · " + esc(d.bus) : ""} · état ${esc(d.health || "inconnu")}</p>`).join("");
  const folders = st.folders || [];
  chart("chart-folders", {
    type: "bar",
    data: { labels: folders.map((f) => f.name), datasets: [{ label: "Go (local)", data: folders.map((f) => f.local_gb), backgroundColor: cssVar("--accent"), borderRadius: 4 }] },
    options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: cssVar("--muted") }, grid: { color: cssVar("--line") } }, y: { ticks: { color: cssVar("--muted") }, grid: { display: false } } } },
  });
  if (dup.skipped) { $("#dup-sum").textContent = "Recherche de doublons désactivée pour ce scan."; $("#dup-list").innerHTML = ""; }
  else {
    $("#dup-sum").innerHTML = `<b>${dup.duplicate_files || 0}</b> fichier(s) en double dans <b>${dup.group_count || 0}</b> groupe(s) — <b>${size(dup.wasted_bytes)}</b> récupérables.
      <span class="small muted">${dup.files_scanned || 0} fichiers parcourus, ${dup.files_hashed || 0} empreintes calculées${dup.truncated ? ", analyse partielle (temps limité)" : ""}.</span>`;
    $("#dup-list").innerHTML = (dup.groups || []).slice(0, 40).map((g) => `<details class="finding"><summary><b>${g.count} copies</b> · ${size(g.size_bytes)} chacune · ${esc(g.category)}
      <span class="key">${size(g.wasted_bytes)} récupérables</span></summary><div class="body">${g.files.map((p, i) => `<div class="path">${i === 0 ? "✓ " : "✗ "}${esc(p)}</div>`).join("")}
      <p class="small muted">✓ = le plus ancien (original présumé) · ✗ = copies identiques</p></div></details>`).join("");
  }
  $("#large").innerHTML = "<tr><th>Fichier</th><th class='num'>Taille</th></tr>" +
    ((st.large_files || []).map((f) => `<tr><td class="path">${esc(f.path)}</td><td class="num">${f.size_gb} Go</td></tr>`).join("") || "<tr><td colspan='2'>Aucun.</td></tr>");
}

// ------------------------------------------------------------------ performance et matériel
function renderPerformance() {
  const p = state.report.inventory.performance || {}; const cpu = p.cpu || {}; const m = p.memory || {};
  const hw = state.report.inventory.system?.hardware || {};
  const card = (label, value, sub) => `<div class="score"><div class="label">${label}</div><div class="value">${value}</div><div class="small muted">${sub || ""}</div></div>`;
  $("#perf-cards").innerHTML = card("Processeur", `${cpu.usage_percent ?? "—"}<small> %</small>`, `${esc(hw.cpu || "")}${cpu.logical_cores ? ` · ${cpu.physical_cores}c/${cpu.logical_cores}t` : ""}`)
    + card("Mémoire", `${m.percent ?? "—"}<small> %</small>`, `${m.used_gb ?? "?"} / ${m.total_gb ?? "?"} Go`)
    + card("Programmes ouverts", p.process_count ?? "—", "processus en cours")
    + card("Allumé depuis", `${p.uptime_days ?? "—"}<small> j</small>`, `depuis ${fmtDate(p.boot_time)}`)
    + (p.battery ? card("Batterie", `${p.battery.percent}<small> %</small>`, p.battery.plugged ? "sur secteur" : "sur batterie") : "");
  $("#top-mem").innerHTML = "<tr><th>Application</th><th class='num'>Processus</th><th class='num'>Mémoire</th><th class='num'>Processeur</th></tr>" +
    (p.top_memory || []).map((g) => `<tr><td>${esc(g.name)}</td><td class="num">${g.count}</td><td class="num">${g.memory_mb} Mo</td><td class="num">${g.cpu_percent} %</td></tr>`).join("");
  renderHardware();
  $("#services").textContent = p.services_enabled != null ? `${p.services_enabled} services système activés (systemd), non comptés comme programmes de démarrage.` : "";
  $("#startup").innerHTML = "<tr><th>Programme</th><th>Source</th><th>État</th></tr>" +
    (p.startup || []).map((s) => `<tr><td>${esc(s.name)}<div class="small muted path">${esc(s.command)}</div></td><td class="small">${esc(s.source)}</td>
      <td>${s.enabled ? "actif" : "<span class='muted'>désactivé</span>"}</td></tr>`).join("");
}

function renderHardware() {
  const inv = state.report.inventory;
  const hasHw = "hardware" in inv || "wifi" in inv;
  $("#hw-grid").hidden = !hasHw;  // anciens rapports (version 1) : pas de données matérielles
  if (!hasHw) return;
  const hw = inv.hardware || {}; const w = inv.wifi || {}; const b = hw.battery;
  let html = "";
  if (!hw.battery_present && !b) html += "<p class='muted'>Aucune batterie (ordinateur fixe) ou information indisponible.</p>";
  else if (!b || b.health_percent == null) html += "<p class='muted'>Batterie présente, mais le système ne publie pas sa capacité.</p>";
  else html += `<p><b>Batterie :</b> ${b.health_percent} % de la capacité d'origine${b.cycles ? ` · ${b.cycles} cycles` : ""}</p>
      <div class="bar"><span style="width:${b.health_percent}%;background:${scoreColor(b.health_percent)}"></span></div>`;
  html += (hw.temperatures || []).length
    ? `<p><b>Température max. :</b> ${Math.round(hw.max_temperature_c)} °C</p>`
    : "<p class='small muted'>Températures : capteurs non accessibles sur ce système.</p>";
  $("#hw").innerHTML = html;
  if (w.available === false) { $("#wifi").innerHTML = "<p class='muted'>Pas de Wi-Fi sur cet ordinateur.</p>"; return; }
  if (!w.available) { $("#wifi").innerHTML = "<p class='muted'>Information Wi-Fi indisponible.</p>"; return; }
  const cur = w.current;
  $("#wifi").innerHTML = (cur ? `<p><b>Connecté :</b> ${esc(cur.ssid)} — ${WIFI_LABEL[cur.security] || esc(cur.security)}${cur.cipher ? " · " + esc(cur.cipher) : ""}</p>` : "<p class='muted'>Non connecté.</p>")
    + `<div class="table-wrap"><table><tr><th>Réseau mémorisé</th><th>Sécurité</th><th>Connexion auto.</th></tr>${(w.profiles || []).map((p) =>
      `<tr><td>${esc(p.name)}</td><td>${WIFI_LABEL[p.security] || esc(p.security)}</td><td>${p.autoconnect ? "oui" : "non"}</td></tr>`).join("")}</table></div>`;
}

// ------------------------------------------------------------------ comparaison
async function compare(ev) {
  ev?.preventDefault();
  try {
    const c = await api(`/comparaison?${qs($("#c-form"))}`);
    const delta = Object.entries(c.evolution_scores).map(([k, v]) => `<div class="score"><div class="label">${DOMAIN_LABEL[k]}</div>
      <div class="value">${c.nouveau.scores[k]}<small>/100</small></div><div class="${v > 0 ? "delta-pos" : v < 0 ? "delta-neg" : "muted"}">${v > 0 ? "+" : ""}${v} pts</div></div>`).join("");
    const list = (items, empty) => items.length ? `<ul>${items.map((f) => `<li>${badge(f.severity)} ${esc(f.title)}</li>`).join("")}</ul>` : `<p class="muted">${empty}</p>`;
    $("#c-out").innerHTML = `${c.avertissements.map((w) => `<p class="st-detecte small">⚠ ${esc(w)}</p>`).join("")}
      <div class="scores">${delta}</div>
      <div class="cols3">
        <div class="panel"><h3>Corrigés (${c.resume.corriges})</h3>${list(c.corriges, "Aucun problème corrigé.")}</div>
        <div class="panel"><h3>Toujours présents (${c.resume.restants})</h3>${list(c.restants, "Aucun.")}</div>
        <div class="panel"><h3>Nouveaux (${c.resume.nouveaux})</h3>${list(c.nouveaux, "Aucun nouveau problème.")}</div>
      </div>
      ${c.non_verifiables.length ? `<div class="panel"><h3>Devenus non vérifiables (${c.non_verifiables.length})</h3>${list(c.non_verifiables, "")}</div>` : ""}`;
  } catch (e) { $("#c-out").innerHTML = `<p class="muted">${esc(e.message)}</p>`; }
}

// ------------------------------------------------------------------ navigation
const PAGES = ["accueil", "guide", "analyser", "questions"];
function showPage(name) {
  if (!PAGES.includes(name)) name = MODE === "serveur" ? "analyser" : "accueil";
  for (const p of PAGES) document.getElementById(`page-${p}`).hidden = p !== name;
  document.querySelectorAll(".mainnav a").forEach((a) => a.classList.toggle("active", a.dataset.page === name));
  if (name === "analyser" && state.report) renderStorage();
  window.scrollTo(0, 0);
}
function showTab(name) {
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => (p.hidden = p.id !== `tab-${name}` || !state.report));
  if (name === "storage" && state.report) renderStorage();  // un graphique dessiné caché a une taille nulle
  if (name === "compare") {
    if (state.scans.length < 2) $("#c-out").innerHTML = `<p class="muted">Il faut deux rapports : refaites un scan après vos corrections, puis utilisez « + Ajouter un rapport ».</p>`;
    else if (!$("#c-out").innerHTML) compare();
  }
}
function showOs(os) {
  document.querySelectorAll(".ostabs button").forEach((b) => b.classList.toggle("active", b.dataset.os === os));
  document.querySelectorAll("[data-os-panel]").forEach((s) => (s.hidden = s.dataset.osPanel !== os));
}
function closeReports() {
  state.local.clear(); state.scans = []; state.report = null;
  $("#dashboard").hidden = true; $("#upload-zone").hidden = false;
}

document.addEventListener("DOMContentLoaded", () => {
  document.body.dataset.mode = MODE;
  $("#mode-note").textContent = MODE === "serveur"
    ? "Mode serveur : rapports du dossier de données de l'API locale."
    : "Vos rapports sont lus dans votre navigateur et ne sont jamais envoyés.";
  if (MODE === "serveur") { $("#ai-note").hidden = false; $("#clear-btn").hidden = true; }
  else { $("#ai-btn").hidden = true; $("#ai-note").textContent = "Le plan de correction par IA (Grok) est disponible avec l'outil installé : commande « kmb plan-ia ». Le plan ci-dessus, lui, est toujours disponible."; }
  document.querySelectorAll("[data-dl-zip]").forEach((a) => (a.href = CONFIG.downloadZip || "#"));
  // Adresse complète du ZIP (dépend de l'adresse du site) pour « pip install <adresse> »
  const zipUrl = new URL(CONFIG.downloadZip || "telechargements/kmb-library.zip", location.href).href;
  document.querySelectorAll("pre[data-install]").forEach((pre) => (pre.textContent = pre.textContent.replace("{URL_ZIP}", zipUrl)));
  // Bouton « Copier » sur chaque commande du guide
  document.querySelectorAll(".guide pre").forEach((pre) => {
    const box = document.createElement("div"); box.className = "cmd";
    pre.replaceWith(box); box.append(pre);
    const btn = document.createElement("button"); btn.type = "button"; btn.textContent = "Copier"; btn.dataset.copy = pre.textContent;
    box.append(btn);
  });

  window.addEventListener("hashchange", () => showPage(location.hash.slice(1)));
  showPage(location.hash.slice(1));
  document.querySelectorAll(".ostabs button").forEach((b) => b.addEventListener("click", () => showOs(b.dataset.os)));
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
  $("#scan-select").addEventListener("change", (e) => loadReport(e.target.value).catch((err) => toast(err.message)));
  $("#f-form").addEventListener("input", debounce(loadFindings));
  $("#f-form").addEventListener("submit", (e) => e.preventDefault());
  $("#s-form").addEventListener("input", debounce(loadSoftware));
  $("#s-form").addEventListener("submit", (e) => e.preventDefault());
  $("#c-form").addEventListener("submit", compare);
  $("#ai-btn").addEventListener("click", generateAi);
  $("#clear-btn").addEventListener("click", closeReports);
  $("#load-example").addEventListener("click", (e) => { e.preventDefault(); loadExample(); });
  $("#print-btn").addEventListener("click", () => window.print());
  for (const id of ["#upload", "#upload2"]) {
    $(id).addEventListener("change", async (e) => { await addFiles([...e.target.files]); e.target.value = ""; });
  }
  const zone = $("#upload-zone");
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => { e.preventDefault(); zone.classList.remove("over"); addFiles([...e.dataTransfer.files]); });
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-copy]");
    if (b) navigator.clipboard?.writeText(b.dataset.copy).then(() => toast("Commande copiée"));
  });
  // Impression : toutes les sections et toutes les fiches dépliées
  window.addEventListener("beforeprint", () => document.querySelectorAll("#dashboard details").forEach((d) => { d.dataset.wasOpen = d.open; d.open = true; }));
  window.addEventListener("afterprint", () => document.querySelectorAll("#dashboard details").forEach((d) => { d.open = d.dataset.wasOpen === "true"; }));

  if (MODE === "serveur") loadScans().catch((e) => toast("API injoignable : " + e.message));
  if (new URLSearchParams(location.search).get("exemple") === "1") { showPage("analyser"); loadExample(); }
});
