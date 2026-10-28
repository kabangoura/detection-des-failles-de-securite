// Contrôle de la version anglaise du site (lancé par tests/test_traductions.py, ou : node tests/i18n_check.mjs)
// - chaque texte passé à tr() dans web/app.js a sa traduction dans web/i18n-en.js ;
// - chaque {variable} de la traduction existe aussi dans le texte français ;
// - chaque motif de « phrases » est une expression régulière valide.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const web = join(dirname(fileURLToPath(import.meta.url)), "..", "web");
const app = readFileSync(join(web, "app.js"), "utf8");
const window = {};
new Function("window", readFileSync(join(web, "i18n-en.js"), "utf8"))(window);
const en = window.KMB_EN;

const keys = new Set();
for (const m of app.matchAll(/\btr\("((?:[^"\\]|\\.)*)"/g)) keys.add(JSON.parse(`"${m[1]}"`));
const errors = [];
for (const k of keys) {
  if (!(k in en.ui)) errors.push(`non traduit : ${k}`);
  else {
    const vars = (t) => new Set([...t.matchAll(/\{(\w+)\}/g)].map((m) => m[1]));
    for (const v of vars(en.ui[k])) if (!vars(k).has(v)) errors.push(`variable {${v}} inconnue : ${k}`);
  }
}
for (const [re] of en.phrases) { try { new RegExp(re, "g"); } catch (e) { errors.push(`motif invalide : ${re}`); } }
const unused = Object.keys(en.ui).filter((k) => !keys.has(k));
console.log(JSON.stringify({ textes: keys.size, traduits: keys.size - errors.filter((e) => e.startsWith("non")).length, inutilises: unused, erreurs: errors }));
process.exit(errors.length ? 1 : 0);
