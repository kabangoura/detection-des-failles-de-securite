// Site KMB Library.
// Mode « local » (par défaut, site public) : le rapport est lu par le navigateur, rien n'est envoyé.
// Mode « serveur » (?mode=serveur) : tableau de bord alimenté par l'API FastAPI locale.
"use strict";

const MODE = new URLSearchParams(location.search).get("mode") === "serveur" ? "serveur" : "local";
const CONFIG = window.KMB_CONFIG || {};
// Langue de la page (<html lang="en"> pour la version anglaise, dossier en/). tr(texte, variables) renvoie
// la traduction de web/i18n-en.js sur la version anglaise, et le texte français tel quel sinon.
const LANG = document.documentElement.lang === "en" ? "en" : "fr";
const EN = LANG === "en" ? window.KMB_EN || { ui: {}, phrases: [] } : null;
function tr(fr, vars = {}) {
  let t = (EN && EN.ui[fr]) || fr;
  for (const [k, v] of Object.entries(vars)) t = t.split(`{${k}}`).join(v);
  return t;
}
const NUM_LOCALE = LANG === "en" ? "en-CA" : "fr-CA";
const COLON = LANG === "en" ? ":" : " :";
const GB = tr("Go"); const MB = tr("Mo");
// Fichiers du site (exemple, ZIP, traductions) : chemins relatifs au dossier de config.js, valables aussi depuis en/
const SITE_ROOT = new URL(".", document.querySelector('script[src$="config.js"]')?.src || location.href).href;
const assetUrl = (path) => new URL(path, SITE_ROOT).href;
const SEV = ["critique", "eleve", "moyen", "faible", "info"];
const SEV_LABEL = { critique: tr("Critique"), eleve: tr("Élevé"), moyen: tr("Moyen"), faible: tr("Faible"), info: tr("Information") };
const SEV_RANK = { critique: 0, eleve: 1, moyen: 2, faible: 3, info: 4 };
const DOMAIN_LABEL = { securite: tr("Sécurité"), performance: tr("Performance"), stockage: tr("Stockage"), logiciels: tr("Logiciels"), global: tr("Global") };
const LIFE_LABEL = { fin_de_support: tr("Fin de support"), maj_disponible: tr("Mise à jour disponible"), supporte: tr("Supporté"), inconnu: tr("Inconnu"), non_suivi: tr("Non suivi") };
const STATUS_LABEL = { detecte: tr("Détecté"), conforme: tr("Conforme"), non_verifiable: tr("Non vérifiable") };
const OS_LABEL = { windows: "Windows", linux: "Linux", macos: "macOS" };
const WIFI_LABEL = { ouvert: tr("ouvert (non chiffré)"), wep: tr("WEP (obsolète)"), wpa: tr("WPA (obsolète)"), wpa2: "WPA2", wpa3: "WPA3", entreprise: tr("Entreprise (802.1X)"), inconnu: tr("inconnu") };

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
  const u = LANG === "en" ? ["B", "KB", "MB", "GB", "TB"] : ["o", "Ko", "Mo", "Go", "To"]; let i = 0; let n = bytes;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
function scoreColor(v) { return v >= 80 ? cssVar("--ok") : v >= 60 ? cssVar("--moyen") : cssVar("--critique"); }
function machineLabel(r) { return r.display_name || r.machine_name; }
// Jauge circulaire (score sur 100), animée par animateRings()
function ring(v, sz = 120, stroke = 11) {
  const c = sz / 2, r = (sz - stroke) / 2, len = 2 * Math.PI * r;
  return `<svg class="ring" viewBox="0 0 ${sz} ${sz}" width="${sz}" height="${sz}" role="img" aria-label="${tr("{v} sur 100", { v })}">
    <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="var(--line)" stroke-width="${stroke}"/>
    <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${scoreColor(v)}" stroke-width="${stroke}" stroke-linecap="round"
      stroke-dasharray="${len}" stroke-dashoffset="${len}" data-off="${len * (1 - v / 100)}" transform="rotate(-90 ${c} ${c})"/>
    <text x="50%" y="50%" text-anchor="middle" dominant-baseline="central" font-size="${sz * 0.3}">${v}</text></svg>`;
}
function animateRings(root) {
  requestAnimationFrame(() => requestAnimationFrame(() =>
    root.querySelectorAll("circle[data-off]").forEach((el) => (el.style.strokeDashoffset = el.dataset.off))));
}
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

// ------------------------------------------------------------------ traduction des rapports (version anglaise)
// Les rapports sont écrits en français par le scanner. En anglais, chaque fiche est traduite à partir de
// web/kb_en.json (base de connaissances traduite, commandes indexées par leur texte exact) et les phrases
// générées pendant le scan (constats, titres avec un nom, durées…) par les motifs de web/i18n-en.js.
let KB_EN = null;
async function loadKbEn() {
  if (LANG !== "en" || KB_EN) return;
  try { KB_EN = await (await fetch(assetUrl("kb_en.json"))).json(); } catch { KB_EN = {}; }
}
const PHRASES = (EN?.phrases || []).map(([re, rep]) => [new RegExp(re, "g"), rep]);
const TITRES = (EN?.titres || []).map(([re, rep]) => [new RegExp(re), rep]);
// Titre contenant un nom ou un numéro (« Version dépassée : Chrome ») ; null si c'est un titre fixe de la base
function trTitle(text) {
  for (const [re, rep] of TITRES) if (re.test(text || "")) return text.replace(re, rep);
  return null;
}
function trPhrase(text) {
  if (!EN || !text) return text;
  let t = String(text);
  for (const [re, rep] of PHRASES) t = t.replace(re, rep);
  return t;
}
function locCommand(k, c) {
  const t = typeof c === "string" ? null : k?.commandes?.[c.cmd];
  return t ? { ...c, ...t, remplacer: c.remplacer && { ...c.remplacer, ...t.remplacer } } : c;
}
function loc(f) {
  if (LANG !== "en" || !f) return f;
  const k = KB_EN?.[f.id];
  const os = state.report?.os_family;
  const pick = (field) => k && ((os && os !== "windows" && k[`${field}_${os}`]) || k[field]);
  const out = { ...f, title: trTitle(f.title) || pick("title") || f.title, evidence: trPhrase(f.evidence),
                category: pick("category") || f.category };
  for (const field of ["description", "danger", "impact", "location"]) out[field] = pick(field) || f[field];
  if (f.remediation) {
    const steps = pick("steps");
    const cmds = {};
    for (const [o, list] of Object.entries(f.remediation.commands || {})) cmds[o] = list.map((c) => locCommand(k, c));
    out.remediation = { ...f.remediation, commands: cmds, duration: pick("duration") || trPhrase(f.remediation.duration),
                        steps: steps && steps.length === (f.remediation.steps || []).length ? steps : f.remediation.steps };
  }
  return out;
}
// Titre d'un problème à partir de sa clé (plan, comparaison) : celui de la fiche traduite
function locTitle(item) {
  if (LANG !== "en") return item.title;
  const f = state.report?.findings.find((x) => x.key === item.key);
  return f ? loc(f).title : trTitle(item.title) || trPhrase(item.title);
}

// ------------------------------------------------------------------ accès aux données
async function api(path, opts = {}) {
  if (MODE === "local") return localApi(path, opts);
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw apiError(res.status, body.detail || tr("Erreur HTTP {n}", { n: res.status }));
  return body;
}

function summaryOf(r) {
  return { scan_id: r.scan_id, machine_name: r.machine_name, display_name: r.display_name, device_model: r.device_model,
           os: r.os, os_family: r.os_family, scan_date: r.scan_date, scores: r.scores, summary: r.summary };
}
function sortedLocal() { return [...state.local.values()].sort((a, b) => (a.scan_date < b.scan_date ? 1 : -1)); }
function getLocal(id) {
  const r = id === "dernier" ? sortedLocal()[0] : state.local.get(id);
  if (!r) throw apiError(404, tr("Rapport introuvable : {id}", { id }));
  return r;
}
function listResult(items, empty) { const out = { total: items.length, resultats: items }; if (!items.length) out.message = empty; return out; }

// Mêmes règles que l'API FastAPI, appliquées dans le navigateur
function localApi(path, opts) {
  const url = new URL(path, location.href);
  const p = url.searchParams;
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts[0] === "scans" && parts.length === 1) return listResult(sortedLocal().map(summaryOf), tr("Aucun rapport chargé."));
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
    if (q) items = items.filter((f) => [f.title, f.evidence, f.key, loc(f).title, loc(f).evidence].some((x) => String(x || "").toLowerCase().includes(q)));
    items = [...items].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
    return listResult(items, tr("Aucun problème ne correspond à ces critères."));
  }
  if (parts[0] === "scans" && parts[2] === "logiciels") {
    const r = getLocal(decodeURIComponent(parts[1]));
    let items = r.inventory?.software || [];
    const q = (p.get("recherche") || "").toLowerCase();
    if (q) items = items.filter((s) => s.name.toLowerCase().includes(q) || String(s.publisher || "").toLowerCase().includes(q));
    if (p.get("cycle_de_vie")) items = items.filter((s) => s.lifecycle === p.get("cycle_de_vie"));
    const res = listResult(items.slice(0, 200), tr("Aucun logiciel ne correspond à ces critères."));
    res.total = items.length;
    return res;
  }
  if (parts[0] === "scans" && parts[2] === "plan-ia") throw apiError(404, tr("Plan IA généré à la demande (bouton « Générer le plan IA »)."));
  if (parts[0] === "statistiques") {
    const m = p.get("machine");
    const reports = sortedLocal().filter((r) => !m || r.machine_name === m);
    return { nb_scans: reports.length, evolution: [...reports].reverse().map((r) => ({ scan_id: r.scan_id, date: r.scan_date, scores: r.scores })) };
  }
  if (parts[0] === "comparaison") {
    const old = getLocal(p.get("ancien")); const nw = getLocal(p.get("nouveau") || "dernier");
    if (old.scan_id === nw.scan_id) throw apiError(422, tr("Choisissez deux rapports différents."));
    return compareReports(old, nw);
  }
  throw apiError(404, tr("Page introuvable"));
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
  if (old.machine_name !== nw.machine_name) warnings.push(tr("Les rapports proviennent de deux ordinateurs différents ({a} / {b}).", { a: machineLabel(old), b: machineLabel(nw) }));
  if (old.scan_date > nw.scan_date) warnings.push(tr("Le rapport « avant » est plus récent que le rapport « après »."));
  if (old.is_admin !== nw.is_admin) warnings.push(tr("Les deux scans n'ont pas été lancés avec les mêmes droits : certains contrôles diffèrent."));
  return { ancien: { scan_id: old.scan_id, date: old.scan_date, scores: old.scores }, nouveau: { scan_id: nw.scan_id, date: nw.scan_date, scores: nw.scores },
           evolution_scores: delta, resume: { corriges: fixed.length, restants: remaining.length, nouveaux: added.length, non_verifiables: unverified.length },
           corriges: fixed, restants: remaining, nouveaux: added, non_verifiables: unverified, avertissements: warnings };
}

// ------------------------------------------------------------------ chargement des fichiers (mode local)
function validateReport(doc, fileName) {
  if (doc && doc.collectors && doc.started_at && !doc.findings) {
    throw new Error(tr("« {file} » contient les données brutes. Choisissez plutôt le fichier qui commence par KMB-rapport_ (dans le dossier Documents\\KMB Library).", { file: fileName }));
  }
  if (!doc || !doc.scan_id || !Array.isArray(doc.findings) || !doc.scores) {
    throw new Error(tr("« {file} » n'est pas un rapport KMB. Choisissez le fichier KMB-rapport_….json créé par le scanner.", { file: fileName }));
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
      toast(err instanceof SyntaxError ? tr("« {file} » n'est pas un fichier JSON valide.", { file: file.name }) : err.message);
    }
  }
  if (last) { await loadScans(last); showPage("analyser"); }
}

async function loadExample() {
  try {
    const res = await fetch(assetUrl(CONFIG.exampleReport || "exemple/KMB-rapport_exemple.json"));
    if (!res.ok) throw new Error();
    const doc = validateReport(await res.json(), "exemple");
    state.local.set(doc.scan_id, doc);
    await loadScans(doc.scan_id);
  } catch { toast(tr("L'exemple n'est pas disponible.")); }
}

// ------------------------------------------------------------------ rapports
async function loadScans(selectId) {
  const data = await api("/scans?limit=200");
  state.scans = data.resultats;
  const has = state.scans.length > 0;
  $("#dashboard").hidden = !has;
  $("#upload-zone").hidden = has || MODE === "serveur";
  if (!has) { if (MODE === "serveur") toast(tr("Aucun rapport dans le dossier de données du serveur.")); return; }
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
  await loadKbEn();
  state.report = await api(`/scans/${encodeURIComponent(id)}`);
  for (const sel of ["#ai-summary", "#ai-answer"]) $(sel).innerHTML = "";
  renderOverview();
  loadFindings();
  renderPlan();
  loadSoftware();
  renderStorage();
  renderPerformance();
  // ?onglet=storage (par exemple) ouvre directement un onglet du rapport
  const wanted = new URLSearchParams(location.search).get("onglet");
  const known = [...document.querySelectorAll(".tabs button")].some((b) => b.dataset.tab === wanted);
  showTab(known && !state.tabChosen ? wanted : document.querySelector(".tabs button.active").dataset.tab);
  state.tabChosen = true;
}

// ------------------------------------------------------------------ vue d'ensemble
async function renderOverview() {
  const r = state.report;
  const life = r.inventory.system?.os_lifecycle || {};
  const name = r.display_name ? `<b>${esc(r.display_name)}</b> <span class="muted">(${esc(r.machine_name)})</span>` : `<b>${esc(r.machine_name)}</b>`;
  $("#meta").innerHTML = `${name}${r.device_model ? " · " + esc(r.device_model) : ""} · <span class="badge b-info">${OS_LABEL[r.os_family] || esc(r.os_family || "Windows")}</span> ${esc(r.os)} (${esc(r.os_version || "")})
    · ${tr("scan du {date}", { date: fmtDate(r.scan_date) })} · ${r.duration_s} s · ${r.is_admin ? tr("administrateur") : tr("sans droits administrateur")}
    ${r.anonymized ? " · " + tr("anonymisé") : ""}${life.eol ? " · " + tr("fin de support du système : {date}", { date: esc(life.eol) }) : ""}`;
  const order = ["global", "securite", "performance", "stockage", "logiciels"];
  $("#scores").innerHTML = order.map((k) => {
    const v = r.scores[k];
    if (k !== "global") return `<div class="score gauge">${ring(v, 84, 9)}<div class="label">${DOMAIN_LABEL[k]}</div></div>`;
    const verdict = v >= 80 ? tr("Bon état") : v >= 60 ? tr("À améliorer") : tr("À corriger en priorité");
    return `<div class="score gauge global">${ring(v, 136, 13)}<div><div class="label">${tr("Score global sur 100")}</div>
      <div class="verdict" style="color:${scoreColor(v)}">${verdict}</div>
      <div class="hint">${tr("Commencez par les problèmes les plus graves : onglet « Plan de correction ».")}</div></div></div>`;
  }).join("");
  animateRings($("#scores"));

  const counts = SEV.map((s) => r.summary[s] || 0);
  const colors = SEV.map((s) => cssVar(`--${s}`));
  $("#sev-legend").innerHTML = SEV.map((s, i) => `<span><i style="background:${colors[i]}"></i>${SEV_LABEL[s]}${COLON} <b>${counts[i]}</b></span>`).join("")
    + `<span class="muted">${tr("· {ok} conformes · {nv} non vérifiables", { ok: r.summary.conformes, nv: r.summary.non_verifiables })}</span>`;
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
    ? (MODE === "local" ? tr("Ajoutez un deuxième rapport de cet ordinateur (après vos corrections) pour voir l'évolution.") : tr("Un seul scan pour cette machine."))
    : tr("{n} rapports pour cet ordinateur.", { n: evo.length });
  const lineColors = { global: cssVar("--accent"), securite: cssVar("--critique"), performance: cssVar("--faible"), stockage: cssVar("--moyen"), logiciels: cssVar("--info") };
  chart("chart-evo", {
    type: "line",
    data: { labels: evo.map((e) => fmtDate(e.date)),
      datasets: order.map((k) => ({ label: DOMAIN_LABEL[k], data: evo.map((e) => e.scores[k]), borderColor: lineColors[k], backgroundColor: lineColors[k],
        borderWidth: k === "global" ? 3 : 1.5, pointRadius: 3, tension: 0.2 })) },
    options: { maintainAspectRatio: false, plugins: { legend: { labels: { color: cssVar("--muted"), boxWidth: 10 } } },
      scales: { y: { min: 0, max: 100, ticks: { color: cssVar("--muted") }, grid: { color: cssVar("--line") } }, x: { ticks: { color: cssVar("--muted") }, grid: { display: false } } } },
  });

  $("#top-plan").innerHTML = r.plan.slice(0, 6).map((p) => `<li>${badge(p.severity)} ${esc(locTitle(p))} <span class="muted small">(${esc(trPhrase(p.gain))})</span></li>`).join("")
    || `<li>${tr("Aucune action nécessaire.")}</li>`;
  const LBL = { system: tr("Système"), accounts: tr("Comptes"), network: tr("Réseau"), firewall: tr("Pare-feu"), antivirus: tr("Antivirus"), encryption: tr("Chiffrement"),
                software: tr("Logiciels"), performance: tr("Performance"), storage: tr("Stockage"), duplicates: tr("Doublons"), wifi: tr("Wi-Fi"), hardware: tr("Matériel") };
  const ST = { ok: tr("terminé"), partiel: tr("partiel"), erreur: tr("erreur"), ignore: tr("ignoré") };
  $("#collectors").innerHTML = `<tr><th>${tr("Partie examinée")}</th><th>${tr("État")}</th><th class='num'>${tr("Durée")}</th><th>${tr("Remarque")}</th></tr>` +
    Object.entries(r.collectors).map(([k, c]) => `<tr><td>${LBL[k] || k}</td><td>${ST[c.status] || esc(c.status)}</td><td class="num">${c.duration_s} s</td>
      <td class="small muted">${esc(Object.values(c.errors || {})[0] || "")}</td></tr>`).join("");
}

// ------------------------------------------------------------------ problèmes
// Où taper une commande, et comment ouvrir cet endroit
const WHERE = {
  cmd: { label: tr("Invite de commandes"), how: tr("Démarrer → tapez cmd → Entrée") },
  cmd_admin: { label: tr("Invite de commandes (administrateur)"), how: tr("Démarrer → tapez cmd → clic droit sur « Invite de commandes » → Exécuter en tant qu'administrateur") },
  ps: { label: "PowerShell", how: tr("Démarrer → tapez powershell → Entrée") },
  ps_admin: { label: tr("PowerShell (administrateur)"), how: tr("Démarrer → tapez powershell → clic droit → Exécuter en tant qu'administrateur") },
  terminal: { label: "Terminal", how: "" },
};
const CMD_TYPE = {
  verifier: { icon: "🔍", label: tr("Vérifier") },
  ouvrir: { icon: "⚙️", label: tr("Ouvrir le réglage") },
  corriger: { icon: "🛠️", label: tr("Corriger") },
};
function terminalHow() {
  return state.report?.os_family === "macos" ? tr("Applications → Utilitaires → Terminal") : tr("Ctrl + Alt + T, ou menu des applications → Terminal");
}
function highlight(cmd, words) {
  let html = esc(cmd);
  for (const w of Object.keys(words || {})) html = html.split(esc(w)).join(`<mark>${esc(w)}</mark>`);
  return html;
}
function commandCard(c) {
  if (typeof c === "string") return `<div class="cmd"><pre>${esc(c)}</pre><button type="button" data-copy="${esc(c)}">${tr("Copier")}</button></div>`;
  const t = CMD_TYPE[c.type] || CMD_TYPE.corriger;
  const w = WHERE[c.ou] || WHERE.cmd;
  const how = c.ou === "terminal" ? terminalHow() : w.how;
  const sudo = c.ou === "terminal" && c.cmd.includes("sudo ") ? " · " + tr("votre mot de passe sera demandé (rien ne s'affiche pendant la frappe)") : "";
  const repl = c.remplacer ? `<div class="repl"><b>${tr("À remplacer avant de lancer :")}</b><ul>${Object.entries(c.remplacer).map(([k, v]) => `<li><mark>${esc(k)}</mark>${COLON} ${esc(v)}</li>`).join("")}</ul></div>` : "";
  return `<div class="cmdcard cmd-${c.type}">
    <div class="cmdhead"><span class="cmdtype">${t.icon} ${t.label}</span><span class="where" title="${esc(how)}">${tr("Où :")} <b>${esc(w.label)}</b>${how ? ` <span class="muted">(${esc(how)})</span>` : ""}${sudo}</span></div>
    <div class="cmd"><pre>${highlight(c.cmd, c.remplacer)}</pre><button type="button" data-copy="${esc(c.cmd)}">${tr("Copier")}</button></div>
    <p class="effet">${esc(c.effet)}</p>
    ${c.attendu ? `<p class="attendu">${tr("✔ Résultat attendu si tout va bien :")} <b>${esc(c.attendu)}</b></p>` : ""}
    ${repl}
    ${c.attention ? `<p class="attention">⚠️ ${esc(c.attention)}</p>` : ""}
  </div>`;
}
function findingHtml(f) {
  f = loc(f);
  const all = f.remediation.commands || {};
  const cmds = all[state.report?.os_family || "windows"] || Object.values(all).flat();
  const verifier = cmds.filter((c) => typeof c !== "string" && c.type === "verifier");
  const corriger = cmds.filter((c) => typeof c === "string" || c.type !== "verifier");
  const steps = (f.remediation.steps || []).map((s) => `<li>${esc(s)}</li>`).join("");
  const isProblem = f.status === "detecte";
  const guide = `
    <div class="phase"><h4>1. 🔍 ${tr("Vérifier")}</h4>
      ${verifier.length ? verifier.map(commandCard).join("") : `<p class="muted small">${tr("Le constat ci-dessus suffit : rien à vérifier de plus.")}</p>`}</div>
    <div class="phase"><h4>2. 🛠️ ${tr("Corriger")}${f.remediation.duration ? ` <span class="muted small">(${esc(f.remediation.duration)}${f.remediation.requires_admin ? " · " + tr("droits administrateur requis") : ""})</span>` : ""}</h4>
      ${steps ? `<p class="small"><b>${tr("À la souris :")}</b></p><ol>${steps}</ol>` : ""}
      ${corriger.length ? `<p class="small">${tr("<b>Ou avec des commandes</b> (à lancer vous-même, une à une) :")}</p>${corriger.map(commandCard).join("")}` : ""}</div>
    <div class="phase"><h4>3. ✅ ${tr("Contrôler")}</h4>
      <p>${tr("Relancez le scan (<code>python -m kmb_library scan</code>), puis ajoutez le nouveau rapport ici avec « + Ajouter un rapport » : l'onglet <b>Comparaison</b> doit afficher ce problème dans « Corrigés ».")}</p></div>`;
  return `<details class="finding sev-${isProblem ? f.severity : "info"}">
    <summary>${badge(f.severity)} <span>${esc(f.title)}</span> <span class="st st-${f.status}">${STATUS_LABEL[f.status]}</span><span class="key">${esc(f.key)}</span></summary>
    <div class="body">
      <p><b>${tr("Constat :")}</b> ${esc(f.evidence || "—")}</p>
      <dl>
        <dt>${tr("De quoi s'agit-il ?")}</dt><dd>${esc(f.description)}</dd>
        ${f.danger ? `<dt>${tr("Pourquoi est-ce dangereux ?")}</dt><dd>${esc(f.danger)}</dd>` : ""}
        ${f.impact ? `<dt>${tr("Conséquences possibles")}</dt><dd>${esc(f.impact)}</dd>` : ""}
        ${f.location ? `<dt>${tr("Où se trouve-t-il ?")}</dt><dd>${esc(f.location)}</dd>` : ""}
      </dl>
      ${isProblem && (CONFIG.relaisIA || MODE === "serveur") ? `<div class="ai-explain"><button type="button" class="btn ghost" data-explain="${esc(f.key)}">🤖 ${tr("Explique-moi ce problème")}</button><div></div></div>` : ""}
      ${isProblem ? `<h3 class="guide-title">${tr("Guide de correction")}</h3><p class="small muted">${tr("KMB ne modifie rien sur votre ordinateur : c'est vous qui lancez chaque commande, dans l'ordre.")}</p>${guide}` : ""}
      ${f.references?.length ? `<p class="small">${tr("Références :")} ${f.references.map((u) => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a>`).join(" · ")}</p>` : ""}
      <p class="small muted">${tr("Score de risque indicatif : {r}/10 · pénalité : {p} points ({d})", { r: f.risk_score, p: f.penalty, d: DOMAIN_LABEL[f.domain] })}</p>
    </div></details>`;
}

async function loadFindings() {
  if (!state.report) return;
  const form = $("#f-form");
  if (form.recherche.value && form.recherche.value.length < 2) return;
  try {
    const data = await api(`/scans/${encodeURIComponent(state.report.scan_id)}/findings?${qs(form)}`);
    $("#f-count").textContent = data.message || tr("{n} résultat(s)", { n: data.total });
    $("#f-list").innerHTML = data.resultats.map(findingHtml).join("");
  } catch (e) { toast(e.message); }
}

// ------------------------------------------------------------------ plan
async function renderPlan() {
  const r = state.report;
  $("#plan-table").innerHTML = `<tr><th>#</th><th>${tr("Gravité")}</th><th>${tr("Action")}</th><th>${tr("Gain")}</th><th>${tr("Durée")}</th></tr>` +
    (r.plan.map((p) => `<tr><td>${p.priority}</td><td>${badge(p.severity)}</td><td>${esc(locTitle(p))}<div class="small muted">${esc(p.key)}</div></td>
      <td>${esc(trPhrase(p.gain))}</td><td>${esc(trPhrase(p.duration || ""))}</td></tr>`).join("") || `<tr><td colspan='5'>${tr("Aucune action nécessaire.")}</td></tr>`);
  $("#ai-out").innerHTML = "";
  if (MODE === "local") return;
  try { renderAi(await api(`/scans/${encodeURIComponent(r.scan_id)}/plan-ia`)); } catch (e) { if (e.status !== 404) toast(e.message); }
}

function aiCommands(s) {
  const list = s.commandes_verifiees || (s.commandes || []).map((c) => ({ commande: c, connue: null }));
  return list.map(({ commande, connue }) => `<div class="ai-cmd ${connue === false ? "unknown" : ""}">
    ${connue === false ? `<p class="small st-detecte">${tr("⚠️ Commande non vérifiée (absente de la base KMB) : à ne pas exécuter sans la comprendre.")}</p>`
      : connue ? `<p class="small st-conforme">${tr("✓ Commande vérifiée (base KMB)")}</p>` : ""}
    <div class="cmd"><pre>${esc(commande)}</pre><button type="button" data-copy="${esc(commande)}">${tr("Copier")}</button></div></div>`).join("");
}

function renderAi(plan) {
  const v = plan.verification || {};
  const steps = (plan.priorites || []).map((s) => `<div class="ai-step ${s.verifie ? "" : "unverified"}">
    <div class="row-between"><b>${esc(s.ordre)}. ${esc(s.titre)}</b>
      <span class="small ${s.verifie ? "st-conforme" : "st-detecte"}">${s.verifie ? tr("✓ lié au constat {key}", { key: esc(s.key) }) : tr("⚠ non vérifiée (clé inconnue : {key})", { key: esc(s.key) })}</span></div>
    <p>${esc(s.pourquoi || "")}</p>
    <ol>${(s.etapes || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ol>
    ${aiCommands(s)}
    <p class="small muted">${tr("Gain estimé : {g} · durée : {d}", { g: esc(s.gain_estime || "—"), d: esc(s.duree || "—") })}</p></div>`).join("");
  const missing = (v.problemes_graves_oublies || []).length ? `<p class="st-detecte small">${tr("Problèmes graves non traités par l'IA :")} ${v.problemes_graves_oublies.map(esc).join(", ")}</p>` : "";
  const cmdNote = v.commandes != null ? tr(" · {n} commande(s), dont {u} non vérifiée(s)", { n: v.commandes, u: v.commandes_non_verifiees }) : "";
  $("#ai-out").innerHTML = `<p>${esc(plan.resume || "")}</p>
    <p class="small ${v.fiable ? "st-conforme" : "st-detecte"}">${tr("Vérification : {e} étape(s), {u} non vérifiée(s)", { e: v.etapes || 0, u: v.etapes_non_verifiees || 0 })}${cmdNote} — ${v.fiable ? tr("plan cohérent avec le scan") : tr("à relire avec prudence")}</p>
    ${missing}${steps}
    ${(plan.conseils_generaux || []).length ? `<h4>${tr("Conseils généraux")}</h4><ul>${plan.conseils_generaux.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>` : ""}
    <p class="small muted">${esc(plan.meta?.fournisseur || "")} · ${tr("modèle")} ${esc(plan.meta?.modele || "")}${plan.meta?.genere_le ? " · " + fmtDate(plan.meta.genere_le) : ""}</p>`;
  $("#ai-btn").textContent = tr("Régénérer le plan IA");
}

async function generateAi() {
  const btn = $("#ai-btn"); btn.disabled = true; const old = btn.textContent; btn.textContent = tr("Génération en cours…");
  try {
    if (MODE === "serveur") {
      const regen = old === tr("Régénérer le plan IA") ? "?regenerer=true" : "";
      renderAi(await api(`/scans/${encodeURIComponent(state.report.scan_id)}/plan-ia${regen}`, { method: "POST" }));
    } else {
      const r = await askAI("plan", aiBase());
      if (r) renderAi(verifyPlan({ ...r.resultat, meta: { fournisseur: tr("Groq (relais KMB)"), modele: r.modele } }));
    }
  } catch (e) { toast(e.message); btn.textContent = old; } finally { btn.disabled = false; }
}

// ------------------------------------------------------------------ assistant IA (relais Groq)
// Le site envoie au relais un résumé ANONYME des problèmes (jamais le rapport) ; le relais garde la clé de l'IA secrète.
// Chaque réponse est vérifiée ici : étapes rattachées à de vrais problèmes, commandes comparées à la base KMB.
const AI_FIELDS = new Set(["ordre", "key", "titre", "pourquoi", "etapes", "commandes", "gain_estime", "duree", "resume", "priorites"]);

function aiConsent() {
  try { if (sessionStorage.getItem("kmb-ia-ok") === "1") return Promise.resolve(true); } catch { /* stockage indisponible */ }
  const dlg = $("#ai-consent");
  return new Promise((resolve) => {
    dlg.returnValue = "";
    dlg.addEventListener("close", () => {
      const ok = dlg.returnValue === "oui";
      if (ok) { try { sessionStorage.setItem("kmb-ia-ok", "1"); } catch { /* idem */ } }
      resolve(ok);
    }, { once: true });
    dlg.showModal();
  });
}

function anonymize(text) {
  const r = state.report;
  let t = String(text ?? "");
  for (const name of [r.machine_name, r.display_name].filter((x) => x && x.length > 2)) t = t.split(name).join("[ordinateur]");
  return t.replace(/[A-Za-z]:\\Users\\[^\\\s"]+/gi, "~").replace(/\/(home|Users)\/[^/\s"]+/g, "~")
    .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, "[IP]").replace(/[\w.+-]+@[\w-]+\.[\w.]+/g, "[courriel]").slice(0, 400);
}

function knownCommands(f) {
  const all = f.remediation?.commands || {};
  const cmds = all[state.report.os_family || "windows"] || Object.values(all).flat();
  const order = { corriger: 0, ouvrir: 1, verifier: 2 };
  return [...cmds].sort((a, b) => (order[a.type] ?? 3) - (order[b.type] ?? 3)).slice(0, 3).map((c) => (typeof c === "string" ? c : c.cmd));
}

function aiProblem(f) {
  return { key: f.key, titre: f.title, gravite: f.severity, domaine: f.domain, constat: anonymize(f.evidence),
    correction_connue: (f.remediation?.steps || []).slice(0, 3).map(anonymize), commandes_connues: knownCommands(f) };
}

function detectedFindings() {
  return state.report.findings.filter((f) => f.status === "detecte").sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
}

function aiBase() {
  const r = state.report;
  return { os: r.os, scores: r.scores, resume_gravite: r.summary, problemes: detectedFindings().slice(0, 15).map(aiProblem) };
}

async function askAI(tache, data) {
  if (!CONFIG.relaisIA) throw new Error(tr("Assistant IA non configuré sur ce site."));
  if (!(await aiConsent())) return null;
  let res;
  try {
    res = await fetch(CONFIG.relaisIA, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tache, langue: LANG, ...data }) });
  } catch { throw new Error(tr("IA indisponible pour l'instant (pas de connexion au relais). Le reste du rapport fonctionne normalement.")); }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((LANG === "fr" && body.erreur) || tr("IA indisponible pour l'instant (erreur {n}).", { n: res.status }));
  return body;
}

// Même logique que kmb_library/ai/assistant.py (verify)
const reEscape = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function normCmd(c) { return String(c).replace(/\\"/g, '"').trim().replace(/^`+|`+$/g, "").toLowerCase().split(/\s+/).join(" "); }
function cmdPattern(c) {
  const cmd = typeof c === "string" ? c : c.cmd;
  const words = (typeof c === "string" ? null : c.remplacer) || {};
  let t = reEscape(normCmd(cmd));
  for (const w of Object.keys(words)) t = t.split(reEscape(normCmd(w))).join(".+?");
  t = t.replace(/<[^>]+>/g, ".+?").replace(/ /g, "\\s+");
  return new RegExp(`^${t}\\s*$`);
}
function cleanCommands(raw) {
  return (Array.isArray(raw) ? raw : []).map((c) => {
    c = String(c).replace(/\\"/g, '"').trim().replace(/\\+$/, "").trim();
    return (c.split('"').length - 1) % 2 ? c.replace(/^"+|"+$/g, "").trim() : c;  // guillemet orphelin
  }).filter((c) => {
    const words = c.split(/\s+/).length;
    const prose = (/[.…]$/.test(c) && words >= 3) || (words >= 3 && /[à-ÿ]/.test(c) && !/[-/\\:=|$<>]/.test(c));
    const duration = /^\d+\s*[-–‑à]?\s*\d*\s*(min|minutes?|h|heures?|hours?|s|secondes?|seconds?)\.?$/i.test(c);
    return !duration && c.length >= 3 && !AI_FIELDS.has(c.replace(/[:,[\]{}" ]/g, "").toLowerCase()) && /[A-Za-z]{2}/.test(c) && !prose;
  });
}
function checkCommands(cmds, key) {
  const byKey = {};
  for (const f of state.report.findings) byKey[f.key] = Object.values(f.remediation?.commands || {}).flat().map(cmdPattern);
  const every = Object.values(byKey).flat();
  return cleanCommands(cmds).map((c) => {
    const n = normCmd(c);
    return { commande: c, connue: (byKey[key] || []).some((pt) => pt.test(n)) || every.some((pt) => pt.test(n)) };
  });
}
function verifyPlan(plan) {
  const known = new Map(detectedFindings().map((f) => [f.key, f]));
  let unknown = 0, nCmds = 0, unknownCmds = 0;
  plan.priorites = (plan.priorites || []).map((s) => {
    s.verifie = known.has(s.key); unknown += !s.verifie;
    s.commandes_verifiees = checkCommands(s.commandes, s.key);
    nCmds += s.commandes_verifiees.length; unknownCmds += s.commandes_verifiees.filter((c) => !c.connue).length;
    return s;
  });
  const covered = new Set(plan.priorites.map((s) => s.key));
  const missing = [...known.values()].filter((f) => ["critique", "eleve"].includes(f.severity) && !covered.has(f.key)).map((f) => f.key);
  plan.verification = { etapes: plan.priorites.length, etapes_non_verifiees: unknown, problemes_graves_oublies: missing,
    commandes: nCmds, commandes_non_verifiees: unknownCmds, fiable: unknown === 0 && !missing.length };
  return plan;
}

function aiBox(html) { return `<div class="ai-box"><p class="ai-label">🤖 ${tr("Réponse de l'IA")} <span class="muted small">${tr("(à relire : l'IA peut se tromper)")}</span></p>${html}</div>`; }

async function runAI(button, out, tache, data, render) {
  const old = button.textContent; button.disabled = true; button.textContent = tr("L'IA réfléchit…");
  try {
    const r = await askAI(tache, data);
    if (r) out.innerHTML = aiBox(render(r.resultat) + `<p class="small muted">Groq · ${esc(r.modele)}</p>`);
  } catch (e) { out.innerHTML = `<p class="small st-detecte">${esc(e.message)}</p>`; } finally { button.disabled = false; button.textContent = old; }
}

const AI_RENDER = {
  explique: (x, key) => `<p>${esc(x.explication || "")}</p>
    ${x.risque ? `<p><b>${tr("Le risque :")}</b> ${esc(x.risque)}</p>` : ""}${x.exemple ? `<p><b>${tr("Exemple :")}</b> ${esc(x.exemple)}</p>` : ""}
    ${(x.que_faire || []).length ? `<p><b>${tr("Que faire :")}</b></p><ol>${x.que_faire.map((e) => `<li>${esc(e)}</li>`).join("")}</ol>` : ""}
    ${aiCommands({ commandes_verifiees: checkCommands(x.commandes, key) })}`,
  resume: (x) => `<p>${esc(x.resume || "").replace(/\n/g, "<br>")}</p>`,
  comparaison: (x) => `<p>${esc(x.commentaire || "")}</p>`,
  question: (x) => `<p>${esc(x.reponse || "").replace(/\n/g, "<br>")}</p>${aiCommands({ commandes_verifiees: checkCommands(x.commandes, "") })}`,
};

function explainFinding(button) {
  const f = state.report.findings.find((x) => x.key === button.dataset.explain);
  if (f) runAI(button, button.nextElementSibling, "explique", { os: state.report.os, probleme: aiProblem(f) }, (x) => AI_RENDER.explique(x, f.key));
}

function summarizeReport() { runAI($("#ai-summary-btn"), $("#ai-summary"), "resume", aiBase(), AI_RENDER.resume); }

function askQuestion(ev) {
  ev.preventDefault();
  const q = $("#ai-question").value.trim();
  if (q.length < 3) return;
  runAI($("#ai-ask-btn"), $("#ai-answer"), "question", { ...aiBase(), question: q }, AI_RENDER.question);
}

function commentComparison() {
  const c = state.lastComparison;
  if (!c) return;
  const titles = (items) => items.map((f) => `${f.title} (${f.severity})`);
  runAI($("#ai-compare-btn"), $("#ai-compare"), "comparaison",
    { os: state.report.os, comparaison: { evolution_scores: c.evolution_scores, corriges: titles(c.corriges), restants: titles(c.restants), nouveaux: titles(c.nouveaux) } },
    AI_RENDER.comparaison);
}

// ------------------------------------------------------------------ logiciels
async function loadSoftware() {
  if (!state.report) return;
  const form = $("#s-form");
  if (form.recherche.value && form.recherche.value.length < 2) return;
  try {
    const data = await api(`/scans/${encodeURIComponent(state.report.scan_id)}/logiciels?${qs(form)}`);
    $("#s-count").textContent = data.message || tr("{n} logiciel(s)", { n: data.total }) + (data.total > data.resultats.length ? tr(" — {n} premiers affichés, affinez la recherche", { n: data.resultats.length }) : "");
    const lifeBadge = (l) => ({ fin_de_support: `<span class="badge b-eleve">${LIFE_LABEL[l]}</span>`, maj_disponible: `<span class="badge b-faible">${LIFE_LABEL[l]}</span>` }[l]
      || `<span class="muted small">${LIFE_LABEL[l] || esc(l)}</span>`);
    $("#s-table").innerHTML = `<tr><th>${tr("Logiciel")}</th><th>${tr("Version")}</th><th>${tr("Éditeur")}</th><th>${tr("Cycle de vie")}</th><th class='num'>${tr("Taille")}</th></tr>` +
      data.resultats.map((s) => `<tr><td>${esc(s.name)}</td><td>${esc(s.version || "")}</td><td>${esc(s.publisher || "")}</td>
        <td>${lifeBadge(s.lifecycle)}${s.eol ? `<div class="small muted">${tr("fin :")} ${esc(String(s.eol))}${s.latest ? " · " + tr("dernière :") + " " + esc(s.latest) : ""}</div>` : ""}</td>
        <td class="num">${s.size_mb ? s.size_mb + " " + MB : "—"}</td></tr>`).join("");
    const c = state.report.inventory.software_cleaning;
    if (c) $("#s-clean").textContent = tr("Nettoyage : {a} entrées brutes → {b} logiciels retenus. Dates de fin de support : endoflife.date.", { a: c.raw_entries, b: c.kept });
  } catch (e) { toast(e.message); }
}

// ------------------------------------------------------------------ stockage
const CAT = {
  personnel: { icon: "🟢", label: tr("Personnel"), tip: tr("vos fichiers : vous pouvez décider (supprimer, déplacer)") },
  application: { icon: "🟡", label: tr("Application"), tip: tr("passer par l'application ou la désinstaller ; ne pas supprimer à la main") },
  systeme: { icon: "🔴", label: tr("Système"), tip: tr("ne pas toucher") },
  mixte: { icon: "⚪", label: tr("Mixte"), tip: tr("contient des fichiers personnels et d'applications") },
};
function catBadge(c) { const x = CAT[c] || CAT.personnel; return `<span class="cat cat-${c || "personnel"}" title="${esc(x.tip)}">${x.icon} ${x.label}</span>`; }
function shortPath(p) { return String(p || "").replace(/^[A-Z]:\\Users\\[^\\]+/i, "~").replace(/^\/(home|Users)\/[^/]+/, "~"); }

function renderStorage() {
  const inv = state.report.inventory; const st = inv.storage || {}; const dup = inv.duplicates || {};
  const deep = Array.isArray(st.space_by_folder);
  $("#partitions").innerHTML = (st.partitions || []).map((p) => {
    const free = (100 - p.percent_used).toFixed(1);
    return `<p><b>${esc(p.mount)}</b> (${esc(p.fstype)}) — ${tr("{f} Go libres sur {t} Go ({p} %)", { f: p.free_gb, t: p.total_gb, p: free })}</p>
      <div class="bar"><span style="width:${p.percent_used}%;background:${scoreColor(100 - p.percent_used * 0.9)}"></span></div>`;
  }).join("") + (st.physical_disks || []).map((d) => `<p class="small muted">${tr("Disque :")} ${esc(d.name)} · ${esc(d.media_type)}${d.bus ? " · " + esc(d.bus) : ""} · ${tr("état")} ${esc(d.health || tr("inconnu"))}</p>`).join("")
    + (st.system_estimate_gb != null ? `<p class="small">${catBadge("systeme")} ${tr("{os} et programmes installés : environ <b>{n} Go</b> (non analysés : ne pas toucher).", { os: OS_LABEL[state.report.os_family] || tr("Système"), n: st.system_estimate_gb })}</p>` : "")
    + (deep ? `<p class="small muted">${tr("{n} fichiers analysés ({g} Go)", { n: (st.files_scanned || 0).toLocaleString(NUM_LOCALE), g: st.measured_gb })}${st.truncated ? tr(" — analyse interrompue (temps limité)") : ""}.</p>` : "");
  $("#legend-cat").innerHTML = Object.entries(CAT).filter(([k]) => k !== "mixte").map(([k, x]) => `<span>${x.icon} <b>${x.label}</b>${COLON} ${x.tip}</span>`).join("");

  const folders = deep ? st.space_by_folder.filter((f) => f.depth === 1).slice(0, 10) : (st.folders || []).map((f) => ({ name: f.name, size_gb: f.local_gb }));
  chart("chart-folders", {
    type: "bar",
    data: { labels: folders.map((f) => f.name), datasets: [{ label: GB, data: folders.map((f) => f.size_gb), backgroundColor: cssVar("--accent"), borderRadius: 4 }] },
    options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: cssVar("--muted") }, grid: { color: cssVar("--line") } }, y: { ticks: { color: cssVar("--muted") }, grid: { display: false } } } },
  });

  $("#space").innerHTML = deep
    ? `<tr><th>${tr("Dossier")}</th><th>${tr("Catégorie")}</th><th class='num'>${tr("Taille")}</th></tr>` + st.space_by_folder.map((f) =>
        `<tr><td class="path" style="padding-left:${(f.depth - 1) * 18 + 8}px">${f.depth > 1 ? "└ " : ""}${esc(shortPath(f.path))}</td><td>${catBadge(f.category)}</td><td class="num">${f.size_gb} ${GB}</td></tr>`).join("")
    : `<tr><td>${tr("Non disponible pour ce rapport (version précédente de KMB).")}</td></tr>`;

  const rec = st.recoverable || [];
  const recTotal = rec.reduce((s, r) => s + r.size_gb, 0);
  $("#recoverable").innerHTML = rec.length
    ? `<p>${tr("<b>{n} Go</b> peuvent être libérés sans aucun risque (voir aussi le problème « Espace récupérable sans risque »).", { n: recTotal.toFixed(1) })}</p>
       <div class="table-wrap"><table><tr><th>${tr("Élément")}</th><th class='num'>${tr("Taille")}</th><th>${tr("Comment le libérer")}</th></tr>${rec.map((r) =>
         `<tr><td>${esc(trPhrase(r.name))}</td><td class="num">${r.size_gb} ${GB}</td><td class="small">${esc(trPhrase(r.how))}</td></tr>`).join("")}</table></div>`
    : `<p class="muted">${deep ? tr("Rien d'important à récupérer.") : tr("Non disponible pour ce rapport.")}</p>`;

  $("#apps").innerHTML = (st.apps || []).length
    ? `<tr><th>${tr("Application")}</th><th class='num'>${tr("Taille")}</th><th>${tr("Mesure")}</th></tr>` + st.apps.map((a) =>
        `<tr><td>${esc(a.name)}${a.version ? ` <span class="muted small">${esc(a.version)}</span>` : ""}</td><td class="num">${a.size_gb} ${GB}</td><td class="small">${a.measured ? tr("taille réelle sur le disque") : tr("taille déclarée par l'application")}</td></tr>`).join("")
    : `<tr><td class='muted'>${tr("Non disponible pour ce rapport.")}</td></tr>`;

  if (dup.skipped) { $("#dup-sum").textContent = tr("Recherche de doublons désactivée pour ce scan."); $("#dup-list").innerHTML = ""; }
  else {
    $("#dup-sum").innerHTML = `${catBadge("personnel")} ${tr("<b>{n}</b> fichier(s) en double dans <b>{g}</b> groupe(s) — <b>{s}</b> récupérables.", { n: dup.duplicate_files || 0, g: dup.group_count || 0, s: size(dup.wasted_bytes) })}
      <span class="small muted">${tr("{n} fichiers parcourus, {h} contenus comparés", { n: (dup.files_scanned || 0).toLocaleString(NUM_LOCALE), h: dup.files_hashed || 0 })}${dup.truncated ? tr(", analyse partielle (temps limité)") : ""}. ${tr("Seuls vos fichiers personnels sont proposés : jamais ceux des applications ou du système.")}</span>`;
    $("#dup-list").innerHTML = (dup.groups || []).slice(0, 40).map((g) => `<details class="finding"><summary>${tr("<b>{n} copies</b> · {s} chacune", { n: g.count, s: size(g.size_bytes) })} · ${esc(trPhrase(g.category))}
      <span class="key">${tr("{s} récupérables", { s: size(g.wasted_bytes) })}</span></summary><div class="body">${g.files.map((p, i) => `<div class="path">${i === 0 ? "✓ " : "✗ "}${esc(shortPath(p))}</div>`).join("")}
      <p class="small muted">${tr("✓ = le plus ancien (original présumé) · ✗ = copies identiques (comparaison du {m})", { m: esc(trPhrase(g.method || "contenu complet")) })}</p></div></details>`).join("");
  }
  $("#large").innerHTML = `<tr><th>${tr("Fichier")}</th><th>${tr("Type")}</th><th>${tr("Catégorie")}</th><th class='num'>${tr("Taille")}</th></tr>` +
    ((st.large_files || []).map((f) => `<tr><td class="path">${esc(shortPath(f.path))}</td><td class="small">${esc(trPhrase(f.kind || ""))}</td><td>${f.category ? catBadge(f.category) : ""}</td><td class="num">${f.size_gb} ${GB}</td></tr>`).join("")
      || `<tr><td colspan='4'>${tr("Aucun.")}</td></tr>`);
}

// ------------------------------------------------------------------ performance et matériel
function renderPerformance() {
  const p = state.report.inventory.performance || {}; const cpu = p.cpu || {}; const m = p.memory || {};
  const hw = state.report.inventory.system?.hardware || {};
  const card = (label, value, sub) => `<div class="score"><div class="label">${label}</div><div class="value">${value}</div><div class="small muted">${sub || ""}</div></div>`;
  $("#perf-cards").innerHTML = card(tr("Processeur"), `${cpu.usage_percent ?? "—"}<small> %</small>`, `${esc(hw.cpu || "")}${cpu.logical_cores ? ` · ${cpu.physical_cores}c/${cpu.logical_cores}t` : ""}`)
    + card(tr("Mémoire"), `${m.percent ?? "—"}<small> %</small>`, `${m.used_gb ?? "?"} / ${m.total_gb ?? "?"} ${GB}`)
    + card(tr("Programmes ouverts"), p.process_count ?? "—", tr("processus en cours"))
    + card(tr("Allumé depuis"), `${p.uptime_days ?? "—"}<small> ${tr("j")}</small>`, tr("depuis {date}", { date: fmtDate(p.boot_time) }))
    + (p.battery ? card(tr("Batterie"), `${p.battery.percent}<small> %</small>`, p.battery.plugged ? tr("sur secteur") : tr("sur batterie")) : "");
  $("#top-mem").innerHTML = `<tr><th>${tr("Application")}</th><th class='num'>${tr("Processus")}</th><th class='num'>${tr("Mémoire")}</th><th class='num'>${tr("Processeur")}</th></tr>` +
    (p.top_memory || []).map((g) => `<tr><td>${esc(g.name)}</td><td class="num">${g.count}</td><td class="num">${g.memory_mb} ${MB}</td><td class="num">${g.cpu_percent} %</td></tr>`).join("");
  renderHardware();
  $("#services").textContent = p.services_enabled != null ? tr("{n} services système activés (systemd), non comptés comme programmes de démarrage.", { n: p.services_enabled }) : "";
  $("#startup").innerHTML = `<tr><th>${tr("Programme")}</th><th>${tr("Source")}</th><th>${tr("État")}</th></tr>` +
    (p.startup || []).map((s) => `<tr><td>${esc(s.name)}<div class="small muted path">${esc(s.command)}</div></td><td class="small">${esc(trPhrase(s.source))}</td>
      <td>${s.enabled ? tr("actif") : `<span class='muted'>${tr("désactivé")}</span>`}</td></tr>`).join("");
}

function renderHardware() {
  const inv = state.report.inventory;
  const hasHw = "hardware" in inv || "wifi" in inv;
  $("#hw-grid").hidden = !hasHw;  // anciens rapports (version 1) : pas de données matérielles
  if (!hasHw) return;
  const hw = inv.hardware || {}; const w = inv.wifi || {}; const b = hw.battery;
  let html = "";
  if (!hw.battery_present && !b) html += `<p class='muted'>${tr("Aucune batterie (ordinateur fixe) ou information indisponible.")}</p>`;
  else if (!b || b.health_percent == null) html += `<p class='muted'>${tr("Batterie présente, mais le système ne publie pas sa capacité.")}</p>`;
  else html += `<p>${tr("<b>Batterie :</b> {p} % de la capacité d'origine", { p: b.health_percent })}${b.cycles ? " · " + tr("{n} cycles", { n: b.cycles }) : ""}</p>
      <div class="bar"><span style="width:${b.health_percent}%;background:${scoreColor(b.health_percent)}"></span></div>`;
  html += (hw.temperatures || []).length
    ? `<p><b>${tr("Température max. :")}</b> ${Math.round(hw.max_temperature_c)} °C</p>`
    : `<p class='small muted'>${tr("Températures : capteurs non accessibles sur ce système.")}</p>`;
  $("#hw").innerHTML = html;
  if (w.available === false) { $("#wifi").innerHTML = `<p class='muted'>${tr("Pas de Wi-Fi sur cet ordinateur.")}</p>`; return; }
  if (!w.available) { $("#wifi").innerHTML = `<p class='muted'>${tr("Information Wi-Fi indisponible.")}</p>`; return; }
  const cur = w.current;
  $("#wifi").innerHTML = (cur ? `<p><b>${tr("Connecté :")}</b> ${esc(cur.ssid)} — ${WIFI_LABEL[cur.security] || esc(cur.security)}${cur.cipher ? " · " + esc(cur.cipher) : ""}</p>` : `<p class='muted'>${tr("Non connecté.")}</p>`)
    + `<div class="table-wrap"><table><tr><th>${tr("Réseau mémorisé")}</th><th>${tr("Sécurité")}</th><th>${tr("Connexion auto.")}</th></tr>${(w.profiles || []).map((p) =>
      `<tr><td>${esc(p.name)}</td><td>${WIFI_LABEL[p.security] || esc(p.security)}</td><td>${p.autoconnect ? tr("oui") : tr("non")}</td></tr>`).join("")}</table></div>`;
}

// ------------------------------------------------------------------ comparaison
async function compare(ev) {
  ev?.preventDefault();
  try {
    const c = await api(`/comparaison?${qs($("#c-form"))}`);
    state.lastComparison = c;
    const delta = Object.entries(c.evolution_scores).map(([k, v]) => `<div class="score"><div class="label">${DOMAIN_LABEL[k]}</div>
      <div class="value">${c.nouveau.scores[k]}<small>/100</small></div><div class="${v > 0 ? "delta-pos" : v < 0 ? "delta-neg" : "muted"}">${v > 0 ? "+" : ""}${v} ${tr("pts")}</div></div>`).join("");
    const list = (items, empty) => items.length ? `<ul>${items.map((f) => `<li>${badge(f.severity)} ${esc(locTitle(f))}</li>`).join("")}</ul>` : `<p class="muted">${empty}</p>`;
    $("#c-out").innerHTML = `${c.avertissements.map((w) => `<p class="st-detecte small">⚠ ${esc(w)}</p>`).join("")}
      <div class="scores">${delta}</div>
      <div class="cols3">
        <div class="panel"><h3>${tr("Corrigés")} (${c.resume.corriges})</h3>${list(c.corriges, tr("Aucun problème corrigé."))}</div>
        <div class="panel"><h3>${tr("Toujours présents")} (${c.resume.restants})</h3>${list(c.restants, tr("Aucun."))}</div>
        <div class="panel"><h3>${tr("Nouveaux")} (${c.resume.nouveaux})</h3>${list(c.nouveaux, tr("Aucun nouveau problème."))}</div>
      </div>
      ${c.non_verifiables.length ? `<div class="panel"><h3>${tr("Devenus non vérifiables")} (${c.non_verifiables.length})</h3>${list(c.non_verifiables, "")}</div>` : ""}
      ${CONFIG.relaisIA ? `<div class="panel"><div class="row-between"><h3>${tr("Commentaire de l'IA")}</h3><button type="button" class="btn" id="ai-compare-btn">🤖 ${tr("Commenter mon évolution")}</button></div><div id="ai-compare"></div></div>` : ""}`;
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
    if (state.scans.length < 2) $("#c-out").innerHTML = `<p class="muted">${tr("Il faut deux rapports : refaites un scan après vos corrections, puis utilisez « + Ajouter un rapport ».")}</p>`;
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
  if (window.Chart) Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  // Thème clair / sombre : suit l'ordinateur, sauf si le visiteur a choisi avec le bouton
  const themeBtn = $("#theme-btn");
  const dark = () => (document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark";
  const syncThemeBtn = () => { themeBtn.textContent = dark() ? "☀️" : "🌙"; themeBtn.title = dark() ? tr("Passer en mode clair") : tr("Passer en mode sombre"); };
  syncThemeBtn();
  themeBtn.addEventListener("click", () => {
    const t = dark() ? "light" : "dark";
    document.documentElement.dataset.theme = t;
    try { localStorage.setItem("kmb-theme", t); } catch { /* stockage indisponible : choix valable pour cette visite */ }
    syncThemeBtn();
    if (state.report) loadReport(state.report.scan_id).catch(() => {});  // graphiques redessinés avec les nouvelles couleurs
  });
  // Bouton FR | EN : même page et même onglet dans l'autre langue ; le choix est mémorisé pour les visites suivantes
  const langBtn = $("#lang-btn");
  langBtn?.addEventListener("click", () => {
    try { localStorage.setItem("kmb-lang", langBtn.hreflang); } catch { /* stockage indisponible */ }
    langBtn.href = langBtn.getAttribute("href").split(/[?#]/)[0] + location.search + location.hash;
  });
  // Aperçu du rapport sur l'accueil
  document.querySelectorAll("[data-ring]").forEach((el) => { el.innerHTML = ring(+el.dataset.ring, 104, 11); animateRings(el); });
  $("#mode-note").textContent = MODE === "serveur"
    ? tr("Mode serveur : rapports du dossier de données de l'API locale.")
    : tr("Vos rapports sont lus dans votre navigateur et ne sont jamais envoyés.");
  if (MODE === "serveur") $("#clear-btn").hidden = true;
  if (!CONFIG.relaisIA && MODE !== "serveur") {
    document.querySelectorAll("[data-ai]").forEach((el) => (el.hidden = true));
    $("#ai-btn").hidden = true; $("#ai-note").textContent = tr("Assistant IA non configuré sur ce site : commande « python -m kmb_library plan-ia » avec l'outil installé.");
  }
  $("#ai-summary-btn").addEventListener("click", summarizeReport);
  $("#ai-ask-form").addEventListener("submit", askQuestion);
  document.querySelectorAll("[data-dl-zip]").forEach((a) => (a.href = CONFIG.downloadZip ? assetUrl(CONFIG.downloadZip) : "#"));
  // Adresse complète du ZIP (dépend de l'adresse du site) pour « pip install <adresse> »
  const zipUrl = assetUrl(CONFIG.downloadZip || "telechargements/kmb-library.zip");
  document.querySelectorAll("pre[data-install]").forEach((pre) => (pre.textContent = pre.textContent.replace("{URL_ZIP}", zipUrl)));
  // Bouton « Copier » sur chaque commande du guide
  document.querySelectorAll(".guide pre").forEach((pre) => {
    const box = document.createElement("div"); box.className = "cmd";
    pre.replaceWith(box); box.append(pre);
    const btn = document.createElement("button"); btn.type = "button"; btn.textContent = tr("Copier"); btn.dataset.copy = pre.textContent;
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
    const ex = e.target.closest("[data-explain]");
    if (ex) { explainFinding(ex); return; }
    if (e.target.closest("#ai-compare-btn")) { commentComparison(); return; }
    const b = e.target.closest("[data-copy]");
    if (!b) return;
    const done = () => {
      b.textContent = tr("Copié ✓"); b.classList.add("done");
      clearTimeout(b._t); b._t = setTimeout(() => { b.textContent = tr("Copier"); b.classList.remove("done"); }, 1800);
    };
    if (navigator.clipboard) navigator.clipboard.writeText(b.dataset.copy).then(done, () => toast(tr("Copie impossible : sélectionnez la commande à la main.")));
    else toast(tr("Copie impossible : sélectionnez la commande à la main."));
  });
  // Impression : toutes les sections et toutes les fiches dépliées
  window.addEventListener("beforeprint", () => document.querySelectorAll("#dashboard details").forEach((d) => { d.dataset.wasOpen = d.open; d.open = true; }));
  window.addEventListener("afterprint", () => document.querySelectorAll("#dashboard details").forEach((d) => { d.open = d.dataset.wasOpen === "true"; }));

  if (MODE === "serveur") loadScans().catch((e) => toast(tr("API injoignable : ") + e.message));
  if (new URLSearchParams(location.search).get("exemple") === "1") { showPage("analyser"); loadExample(); }
});
