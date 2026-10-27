// Réglages du site public : à adapter au moment de l'hébergement (GitHub Pages, Hostinger…).
window.KMB_CONFIG = {
  // Code de KMB Library : le guide fait installer KMB avec « pip install <adresse de ce fichier> »
  downloadZip: "telechargements/kmb-library.zip",
  // Exemple de rapport proposé par le bouton « Voir un exemple »
  exampleReport: "exemple/KMB-rapport_exemple.json",
  // Relais de l'assistant IA (Cloudflare Worker, dossier relais-ia/) : garde la clé de l'IA secrète.
  // Vide = assistant IA désactivé sur le site.
  relaisIA: "https://kmb-ia.relais-ia.workers.dev",
};
