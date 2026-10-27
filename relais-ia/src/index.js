// Relais IA de KMB Library (Cloudflare Worker).
// Le site envoie un résumé ANONYME des problèmes détectés (jamais le rapport complet) ; le relais ajoute la clé Groq,
// qui reste secrète, interroge l'IA et renvoie la réponse. Rien n'est conservé, sauf des compteurs anti-abus
// (empreinte de l'adresse IP, jamais l'adresse elle-même).
//
// POST /  { tache: "plan" | "explique" | "resume" | "comparaison" | "question", langue: "fr" | "en", ...données }

const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
// Plan gratuit Groq : chaque modèle a ses propres limites ; si l'un est saturé (429), le suivant prend le relais
const MODELES = ["openai/gpt-oss-120b", "qwen/qwen3.8-27b", "openai/gpt-oss-20b"];
const TAILLE_MAX = 24_000; // octets acceptés par demande
const TACHES = ["plan", "explique", "resume", "comparaison", "question"];

const REGLES = {
  fr: `Tu es l'assistant de KMB Library, un outil gratuit d'audit d'ordinateur (sécurité, logiciels, performance, stockage).
Tu réponds en français simple, pour une personne non spécialiste.
Règles strictes :
- Appuie-toi UNIQUEMENT sur les données fournies (résultat anonyme d'un scan). N'invente ni problème, ni version, ni chiffre.
- Pour les commandes, reprends EN PRIORITÉ, mot pour mot, celles du champ "commandes_connues" (elles sont vérifiées) ;
  n'en propose une autre que si aucune ne convient, adaptée au système indiqué (champ "os"), et signale les droits administrateur.
- Aucune instruction offensive ou dangereuse. Si la demande sort du sujet (l'ordinateur analysé), réponds poliment que tu ne peux aider que sur ce rapport.
- Réponds UNIQUEMENT avec un objet JSON valide, sans texte autour.`,
  en: `You are the assistant of KMB Library, a free computer audit tool (security, software, performance, storage).
Answer in plain English for a non-specialist.
Strict rules:
- Rely ONLY on the data provided (anonymous scan result). Never invent problems, versions or numbers.
- For commands, reuse FIRST, word for word, those in the "commandes_connues" field (they are verified);
  only suggest another one if none fits, adapted to the system given ("os" field), and say when admin rights are needed.
- No offensive or dangerous instructions. If the request is off-topic (not about the analysed computer), politely say you can only help with this report.
- Reply ONLY with a valid JSON object, no surrounding text.`,
};

const FORMATS = {
  plan: `{"resume": "3 à 5 phrases", "priorites": [{"ordre": 1, "key": "CLÉ EXACTE DU PROBLÈME", "titre": "...", "pourquoi": "...", "etapes": ["..."], "commandes": ["..."], "gain_estime": "...", "duree": "..."}], "conseils_generaux": ["..."]}
Tâche : plan de correction priorisé (le plus grave d'abord), une entrée par problème important, en citant sa clé exacte (champ "key").`,
  explique: `{"explication": "ce que veut dire ce problème, avec des mots simples", "risque": "ce qui peut arriver concrètement si on ne fait rien", "exemple": "une situation de la vie courante", "que_faire": ["étapes courtes"], "commandes": ["..."]}
Tâche : expliquer UN problème (champ "probleme") à une personne qui n'y connaît rien.`,
  resume: `{"resume": "5 lignes maximum : état général, points forts, 2 ou 3 priorités"}
Tâche : résumer l'état de l'ordinateur à partir des scores et des problèmes.`,
  comparaison: `{"commentaire": "4 à 6 phrases : ce qui a été corrigé (félicite), ce qui reste prioritaire, ce qui est nouveau"}
Tâche : commenter l'évolution entre deux rapports (champ "comparaison").`,
  question: `{"reponse": "réponse courte et précise (8 phrases maximum)", "commandes": ["seulement si utile"]}
Tâche : répondre à la question de l'utilisateur (champ "question") au sujet de CE rapport.`,
};

export default {
  async fetch(request, env) {
    const origine = request.headers.get("Origin") || "";
    const permises = (env.ORIGINES || "").split(",").map((s) => s.trim());
    const cors = {
      "Access-Control-Allow-Origin": permises.includes(origine) ? origine : permises[0],
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      Vary: "Origin",
    };
    const repondre = (statut, corps) => new Response(JSON.stringify(corps), { status: statut, headers: { ...cors, "Content-Type": "application/json; charset=utf-8" } });

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method === "GET") return repondre(200, { service: "Relais IA de KMB Library", statut: "ok" });
    if (request.method !== "POST") return repondre(405, { erreur: "Méthode non autorisée" });
    if (!permises.includes(origine)) return repondre(403, { erreur: "Origine non autorisée : ce relais ne sert que le site KMB Library." });
    if (!env.GROQ_API_KEY) return repondre(503, { erreur: "Relais non configuré (clé absente)." });

    const brut = await request.text();
    if (brut.length > TAILLE_MAX) return repondre(413, { erreur: "Demande trop volumineuse." });
    let d;
    try { d = JSON.parse(brut); } catch { return repondre(400, { erreur: "JSON invalide." }); }
    if (!TACHES.includes(d.tache)) return repondre(400, { erreur: "Tâche inconnue." });
    if (d.tache === "question" && !(typeof d.question === "string" && d.question.trim().length >= 3)) return repondre(400, { erreur: "Question vide." });

    const quota = await verifierQuota(request, env);
    if (quota) return repondre(429, { erreur: quota });

    const langue = d.langue === "en" ? "en" : "fr";
    const donnees = nettoyer(d);
    const messages = [
      { role: "system", content: `${REGLES[langue]}\nFormat attendu :\n${FORMATS[d.tache]}${langue === "en" ? "\nWrite every text value of the JSON in English." : ""}` },
      { role: "user", content: JSON.stringify(donnees) },
    ];
    const erreurs = [];
    for (const modele of MODELES) {
      let r;
      try {
        r = await fetch(GROQ_URL, {
          method: "POST",
          headers: { Authorization: `Bearer ${env.GROQ_API_KEY}`, "Content-Type": "application/json" },
          body: JSON.stringify({ model: modele, temperature: 0.2, max_tokens: d.tache === "plan" ? 2500 : 1200, messages, response_format: { type: "json_object" } }),
        });
      } catch (e) { erreurs.push(`${modele}: réseau`); continue; }
      if (r.status === 429 || r.status >= 500 || r.status === 404) { erreurs.push(`${modele}: ${r.status}`); continue; }
      if (!r.ok) { erreurs.push(`${modele}: ${r.status}`); continue; }
      const data = await r.json();
      const resultat = lireJson(data?.choices?.[0]?.message?.content);
      if (!resultat) { erreurs.push(`${modele}: réponse illisible`); continue; }
      return repondre(200, { ok: true, tache: d.tache, modele: data.model || modele, resultat });
    }
    return repondre(503, { erreur: "L'IA est très demandée pour l'instant (limites du plan gratuit). Réessayez dans une minute.", details: erreurs });
  },
};

// Compteurs : par visiteur et par heure, et total par jour (empreinte SHA-256 de l'IP, jamais l'IP en clair)
async function verifierQuota(request, env) {
  if (!env.KMB_QUOTAS) return null;
  const ip = request.headers.get("CF-Connecting-IP") || "inconnu";
  const empreinte = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ip)))]
    .slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join("");
  const maintenant = new Date();
  const heure = maintenant.toISOString().slice(0, 13);
  const jour = heure.slice(0, 10);
  const cleVisiteur = `v:${empreinte}:${heure}`, cleJour = `j:${jour}`;
  const [nVisiteur, nJour] = await Promise.all([env.KMB_QUOTAS.get(cleVisiteur), env.KMB_QUOTAS.get(cleJour)]).then((v) => v.map((x) => +x || 0));
  if (nVisiteur >= +env.LIMITE_HEURE_VISITEUR) return `Limite atteinte : ${env.LIMITE_HEURE_VISITEUR} demandes par heure. Réessayez dans l'heure qui vient.`;
  if (nJour >= +env.LIMITE_JOUR_TOTAL) return "Limite du jour atteinte pour l'assistant IA. Réessayez demain.";
  await Promise.all([
    env.KMB_QUOTAS.put(cleVisiteur, String(nVisiteur + 1), { expirationTtl: 3700 }),
    env.KMB_QUOTAS.put(cleJour, String(nJour + 1), { expirationTtl: 90000 }),
  ]);
  return null;
}

// Défense en profondeur : le site anonymise déjà ; on retire encore adresses IP, chemins personnels et courriels,
// et on ne garde que les champs utiles (rien d'autre n'est transmis à l'IA).
function nettoyer(d) {
  const masquer = (v) => typeof v === "string"
    ? v.slice(0, 600)
      .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, "[IP]")
      .replace(/[A-Za-z]:\\Users\\[^\\\s"]+/gi, "~").replace(/\/(home|Users)\/[^/\s"]+/g, "~")
      .replace(/[\w.+-]+@[\w-]+\.[\w.]+/g, "[courriel]")
    : v;
  const probleme = (p) => p && ({
    key: masquer(p.key), titre: masquer(p.titre), gravite: masquer(p.gravite), domaine: masquer(p.domaine),
    constat: masquer(p.constat), correction_connue: (p.correction_connue || []).slice(0, 3).map(masquer),
    commandes_connues: (p.commandes_connues || []).slice(0, 3).map(masquer),
  });
  return {
    os: masquer(d.os), scores: d.scores, resume_gravite: d.resume_gravite,
    problemes: (d.problemes || []).slice(0, 15).map(probleme),
    probleme: probleme(d.probleme),
    comparaison: d.comparaison && {
      evolution_scores: d.comparaison.evolution_scores,
      corriges: (d.comparaison.corriges || []).slice(0, 15).map(masquer),
      restants: (d.comparaison.restants || []).slice(0, 15).map(masquer),
      nouveaux: (d.comparaison.nouveaux || []).slice(0, 15).map(masquer),
    },
    question: masquer(d.question)?.slice(0, 500),
  };
}

function lireJson(texte) {
  if (typeof texte !== "string") return null;
  let t = texte.replace(/<think>[\s\S]*?<\/think>/g, "").trim();
  const bloc = t.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (bloc) t = bloc[1];
  const debut = t.indexOf("{"), fin = t.lastIndexOf("}");
  if (debut < 0 || fin < 0) return null;
  try { return JSON.parse(t.slice(debut, fin + 1)); } catch { return null; }
}
