"""Version anglaise du site : fabrique web/en/index.html à partir de web/index.html (page française).

Usage : python scripts/construire_page_anglaise.py

- Chaque texte français de la page est remplacé par sa traduction (liste TEXTES ci-dessous). Si un texte n'est plus
  trouvé (page française modifiée), le script s'arrête : la traduction doit être mise à jour en même temps.
- Les chemins (style, scripts, icônes) sont adaptés au sous-dossier en/ ; les deux pages se signalent mutuellement
  aux moteurs de recherche (hreflang) et ont chacune leurs données structurées (FAQ reprise de la page elle-même).
- Contrôle final : il ne doit rester aucun mot français dans la page anglaise.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FR = ROOT / "web" / "index.html"
EN = ROOT / "web" / "en" / "index.html"
SITE = "https://kabangoura.github.io/detection-des-failles-de-securite/"

DESC_FR = ("KMB Library vérifie gratuitement la sécurité, les logiciels, la performance et le stockage de votre ordinateur "
           "(Windows, Linux, macOS) et explique quoi corriger, étape par étape. Votre rapport reste sur votre ordinateur.")
DESC_EN = ("KMB Library checks the security, software, performance and storage of your computer for free "
           "(Windows, Linux, macOS) and explains what to fix, step by step. Your report stays on your computer.")
TITLE_FR = "KMB Library – Audit gratuit de la sécurité de votre ordinateur"
TITLE_EN = "KMB Library – Free security check-up for your computer"

# Textes de la page : (français exact, anglais). Remplacés dans l'ordre.
TEXTES = [
    ('<html lang="fr">', '<html lang="en">'),
    ('content="KMB Library, KMB, audit ordinateur, sécurité ordinateur, scanner sécurité gratuit, failles de sécurité, Windows, Linux, macOS"',
     'content="KMB Library, KMB, computer audit, computer security, free security scanner, security flaws, Windows, Linux, macOS"'),
    ('title="Résumé pour les assistants IA"', 'title="Summary for AI assistants"'),
    ('<meta property="og:locale" content="fr_CA">', '<meta property="og:locale" content="en_US">\n  <meta property="og:locale:alternate" content="fr_CA">'),
    ('content="KMB Library : audit gratuit de votre ordinateur"', 'content="KMB Library: free check-up for your computer"'),
    ('<small>Audit de votre ordinateur</small>', '<small>Your computer check-up</small>'),
    ('aria-label="Navigation principale"', 'aria-label="Main navigation"'),
    ('data-page="accueil">Accueil</a>', 'data-page="accueil">Home</a>'),
    ('data-page="guide">Guide d\'installation</a>', 'data-page="guide">Installation guide</a>'),
    ('data-page="analyser" class="cta">Analyser mon rapport</a>', 'data-page="analyser" class="cta">Analyse my report</a>'),
    ('title="Mode sombre" aria-label="Changer le thème clair / sombre"', 'title="Dark mode" aria-label="Switch light / dark theme"'),
    # accueil
    ('<span class="kicker">KMB Library · audit gratuit de votre ordinateur</span>', '<span class="kicker">KMB Library · free check-up for your computer</span>'),
    ('<h1>Votre ordinateur est-il <em>bien protégé</em>&nbsp;?</h1>', '<h1>Is your computer <em>well protected</em>?</h1>'),
    ('''<p class="lead">KMB Library vérifie la <b>sécurité</b>, les <b>logiciels</b>, la <b>performance</b> et le <b>stockage</b>
        de votre ordinateur, puis vous explique <b>simplement</b> quoi corriger, étape par étape.</p>''',
     '''<p class="lead">KMB Library checks the <b>security</b>, <b>software</b>, <b>performance</b> and <b>storage</b>
        of your computer, then explains <b>simply</b> what to fix, step by step.</p>'''),
    ('<a class="btn big" href="#guide">Commencer le guide</a>', '<a class="btn big" href="#guide">Start the guide</a>'),
    ('<a class="btn big ghost" href="#analyser">J\'ai déjà mon rapport</a>', '<a class="btn big ghost" href="#analyser">I already have my report</a>'),
    ('<ul class="trust"><li>Gratuit</li><li>Rien n\'est envoyé</li><li>Windows, Linux et macOS</li><li>Assistant IA intégré</li></ul>',
     '<ul class="trust"><li>Free</li><li>Nothing is sent</li><li>Windows, Linux and macOS</li><li>Built-in AI assistant</li></ul>'),
    ('aria-label="Aperçu d\'un rapport KMB"', 'aria-label="Preview of a KMB report"'),
    ('<div class="pv-head"><b>Rapport KMB</b><span>Exemple</span></div>', '<div class="pv-head"><b>KMB report</b><span>Example</span></div>'),
    ('<span>Sécurité</span><i>', '<span>Security</span><i>'),
    ('<span>Stockage</span><i>', '<span>Storage</span><i>'),
    ('<span>Logiciels</span><i>', '<span>Software</span><i>'),
    ('<div class="pv-item"><b>Élevé</b> · Chiffrement du disque désactivé<br><span>Guide : 🔍 Vérifier · ⚙️ Ouvrir le réglage · 🛠️ Corriger</span></div>',
     '<div class="pv-item"><b>High</b> · Disk encryption off<br><span>Guide: 🔍 Check · ⚙️ Open the setting · 🛠️ Fix</span></div>'),
    ('<div class="pv-ai">🤖 Explique-moi ce problème</div>', '<div class="pv-ai">🤖 Explain this problem to me</div>'),
    ('<a href="?exemple=1#analyser">Voir un exemple de rapport →</a>', '<a href="?exemple=1#analyser">See an example report →</a>'),
    ('<h2 class="section-title">Comment ça marche</h2>', '<h2 class="section-title">How it works</h2>'),
    ('<p class="section-sub">Trois étapes, sans rien modifier sur votre ordinateur.</p>', '<p class="section-sub">Three steps, without changing anything on your computer.</p>'),
    ('<h3>Installer</h3><p>Une seule fois, environ 5 minutes : Python (logiciel officiel et gratuit), puis KMB en une commande.</p>',
     '<h3>Install</h3><p>Once, about 5 minutes: Python (official, free software), then KMB in one command.</p>'),
    ('<h3>Scanner</h3><p>Une seule commande à copier. KMB examine votre ordinateur pendant 3 à 5 minutes, sans rien modifier.</p>',
     '<h3>Scan</h3><p>A single command to copy. KMB examines your computer for 3 to 5 minutes, without changing anything.</p>'),
    ('<h3>Voir le résultat</h3><p>Revenez ici, cliquez sur « Analyser mon rapport » et choisissez le fichier créé.</p>',
     '<h3>See the result</h3><p>Come back here, click “Analyse my report” and choose the file that was created.</p>'),
    ('<h2 class="section-title">Ce que KMB vérifie</h2>', '<h2 class="section-title">What KMB checks</h2>'),
    ('<p class="section-sub">Chaque problème trouvé est expliqué, avec les commandes pour le vérifier et le corriger vous-même.</p>',
     '<p class="section-sub">Every problem found is explained, with the commands to check and fix it yourself.</p>'),
    ('<h3>Système</h3><p>Votre Windows, macOS ou Linux reçoit-il encore les mises à jour de sécurité&nbsp;?</p>',
     '<h3>System</h3><p>Does your Windows, macOS or Linux still receive security updates?</p>'),
    ('<h3>Protection</h3><p>Antivirus, pare-feu, chiffrement du disque et comptes d\'utilisateur.</p>',
     '<h3>Protection</h3><p>Antivirus, firewall, disk encryption and user accounts.</p>'),
    ('<h3>Réseau et Wi-Fi</h3><p>Services exposés sur le réseau, Wi-Fi non protégé ou mal chiffré.</p>',
     '<h3>Network and Wi-Fi</h3><p>Services exposed on the network, unprotected or weakly encrypted Wi-Fi.</p>'),
    ('<h3>Logiciels</h3><p>Programmes obsolètes ou qui ne sont plus mis à jour par leur éditeur.</p>',
     '<h3>Software</h3><p>Outdated programs, or programs no longer updated by their publisher.</p>'),
    ('<h3>Performance</h3><p>Mémoire, processeur, programmes au démarrage et batterie.</p>',
     '<h3>Performance</h3><p>Memory, processor, startup programs and battery.</p>'),
    ('<h3>Stockage</h3><p>Où part l\'espace, doublons, gros fichiers, applications et espace récupérable sans risque.</p>',
     '<h3>Storage</h3><p>Where your space goes, duplicates, large files, applications and space you can free safely.</p>'),
    ('<h2 class="section-title">🤖 Un assistant IA pour vous aider à comprendre</h2>', '<h2 class="section-title">🤖 An AI assistant to help you understand</h2>'),
    ('<p class="section-sub">Après le scan, l\'IA explique vos problèmes avec des mots simples et vous aide à les corriger, étape par étape.</p>',
     '<p class="section-sub">After the scan, the AI explains your problems in plain words and helps you fix them, step by step.</p>'),
    ('<h3>Explique-moi ce problème</h3><p>Chaque problème expliqué simplement, avec le risque réel et un exemple concret.</p>',
     '<h3>Explain this problem to me</h3><p>Every problem explained simply, with the real risk and a concrete example.</p>'),
    ('<h3>Résumé de mon rapport</h3><p>L\'état de votre ordinateur en 5 lignes : points forts et priorités.</p>',
     '<h3>Summary of my report</h3><p>The state of your computer in 5 lines: strengths and priorities.</p>'),
    ('<h3>Plan de correction personnalisé</h3><p>Quoi faire, dans quel ordre, avec les bonnes commandes.</p>',
     '<h3>Personalised fix plan</h3><p>What to do, in which order, with the right commands.</p>'),
    ('<h3>Questions libres</h3><p>« Est-ce grave si… ? » : posez vos questions sur votre rapport.</p>',
     '<h3>Free questions</h3><p>“Is it serious if…?”: ask your questions about your report.</p>'),
    ('<h3>Commentaire avant/après</h3><p>Ce que vos corrections ont changé, et ce qui reste à faire.</p>',
     '<h3>Before/after comment</h3><p>What your fixes changed, and what is left to do.</p>'),
    ('''<p>🔒 <b>Uniquement avec votre accord.</b> Seul un résumé anonyme des problèmes est envoyé à l'IA (jamais le nom de l'ordinateur, vos comptes ni vos fichiers).
      Chaque réponse est vérifiée par KMB, et les commandes inconnues sont signalées.</p>''',
     '''<p>🔒 <b>Only with your consent.</b> Only an anonymous summary of the problems is sent to the AI (never the computer name, your accounts or your files).
      Every answer is checked by KMB, and unknown commands are flagged.</p>'''),
    ('<a class="btn" href="?exemple=1#analyser">Essayer sur un exemple</a>', '<a class="btn" href="?exemple=1#analyser">Try it on an example</a>'),
    ('<h2>Prêt à vérifier votre ordinateur&nbsp;?</h2>', '<h2>Ready to check your computer?</h2>'),
    ('<p>🔒 Vos données restent chez vous : le rapport est lu par votre navigateur, rien n\'est envoyé.</p>',
     '<p>🔒 Your data stays with you: the report is read by your browser, nothing is sent.</p>'),
    # guide
    ('<h1>Guide d\'installation et de scan</h1>', '<h1>Installation and scan guide</h1>'),
    ('<p class="lead">Choisissez votre système. Suivez les étapes dans l\'ordre : chaque étape dit exactement quoi faire.</p>',
     '<p class="lead">Choose your system. Follow the steps in order: each step says exactly what to do.</p>'),
    ('<p class="tip">Comptez environ <b>5 minutes la première fois</b>. Les fois suivantes, seule l\'étape 4 est nécessaire (1 minute).</p>',
     '<p class="tip">Allow about <b>5 minutes the first time</b>. After that, only step 4 is needed (1 minute).</p>'),
    ('<li><h3>Installez Python (une seule fois)</h3>', '<li><h3>Install Python (once)</h3>'),
    ('<p>Python est un logiciel gratuit et officiel qui permet à KMB de fonctionner.</p>', '<p>Python is free, official software that KMB needs to run.</p>'),
    ('<li>Ouvrez <a href="https://www.python.org/downloads/" target="_blank" rel="noopener">python.org/downloads</a> et cliquez sur le bouton jaune <b>Download Python</b>.</li>',
     '<li>Open <a href="https://www.python.org/downloads/" target="_blank" rel="noopener">python.org/downloads</a> and click the yellow <b>Download Python</b> button.</li>'),
    ('<li>Ouvrez le fichier téléchargé.</li>', '<li>Open the downloaded file.</li>'),
    ('<li><b>Important :</b> en bas de la première fenêtre, <b>cochez « Add python.exe to PATH »</b>.</li>',
     '<li><b>Important:</b> at the bottom of the first window, <b>check “Add python.exe to PATH”</b>.</li>'),
    ('<li>Cliquez sur <b>Install Now</b>, attendez, puis sur <b>Close</b>.</li>', '<li>Click <b>Install Now</b>, wait, then click <b>Close</b>.</li>'),
    ('<p class="note">Déjà installé&nbsp;? Passez à l\'étape 2. Si vous avez oublié la case « Add python.exe to PATH », relancez l\'installateur, choisissez <b>Modify</b> puis cochez « Add Python to environment variables ».</p></li>',
     '<p class="note">Already installed? Go to step 2. If you forgot the “Add python.exe to PATH” box, run the installer again, choose <b>Modify</b>, then check “Add Python to environment variables”.</p></li>'),
    ('<li><h3>Ouvrez l\'invite de commandes</h3>', '<li><h3>Open the Command Prompt</h3>'),
    ('<p>Cliquez sur le bouton <b>Démarrer</b> de Windows, tapez <code>cmd</code> puis appuyez sur <b>Entrée</b>. Une fenêtre noire s\'ouvre.</p></li>',
     '<p>Click the Windows <b>Start</b> button, type <code>cmd</code> and press <b>Enter</b>. A black window opens.</p></li>'),
    ('<li><h3>Installez KMB (une seule fois)</h3>\n        <p>Copiez cette commande (bouton « Copier »), collez-la dans la fenêtre noire (clic droit) et appuyez sur <b>Entrée</b> :</p>',
     '<li><h3>Install KMB (once)</h3>\n        <p>Copy this command (“Copy” button), paste it into the black window (right-click) and press <b>Enter</b>:</p>'),
    ('''<p class="muted small">L'installation prend 1 à 3 minutes. C'est terminé quand vous voyez <code>Successfully installed … kmb-library</code>.
          Des messages jaunes <code>WARNING … is not on PATH</code> peuvent apparaître : ils sont sans importance.</p></li>''',
     '''<p class="muted small">Installation takes 1 to 3 minutes. It is done when you see <code>Successfully installed … kmb-library</code>.
          Yellow <code>WARNING … is not on PATH</code> messages may appear: they don't matter.</p></li>'''),
    ('<li><h3>Scannez votre ordinateur</h3>', '<li><h3>Scan your computer</h3>'),
    ('<p>KMB trouve tout seul le nom de votre ordinateur et toutes les informations. Le scan dure 3 à 5 minutes (il examine tout votre espace disque) et ne modifie rien.</p>',
     '<p>KMB finds your computer name and all the information by itself. The scan takes 3 to 5 minutes (it examines all your disk space) and changes nothing.</p>'),
    ('<p class="muted small">Les fois suivantes : ouvrez l\'invite de commandes (étape 2) et tapez seulement cette commande.</p>',
     '<p class="muted small">Next times: open the Command Prompt (step 2) and type only this command.</p>'),
    ('''<p class="tip">Examen complet (facultatif) : dans le menu Démarrer, tapez <code>cmd</code>, faites un clic droit sur « Invite de commandes »,
          choisissez <b>Exécuter en tant qu'administrateur</b>, puis tapez la même commande.</p></li>''',
     '''<p class="tip">Full check (optional): in the Start menu, type <code>cmd</code>, right-click “Command Prompt”,
          choose <b>Run as administrator</b>, then type the same command.</p></li>'''),
    ('<li><h3>Voyez le résultat</h3>\n        <p>À la fin, le dossier <code>Documents\\KMB Library</code> s\'ouvre tout seul. Votre rapport s\'appelle par exemple :</p>',
     '<li><h3>See the result</h3>\n        <p>At the end, the <code>Documents\\KMB Library</code> folder opens by itself. Your report is named, for example:</p>'),
    ('<p><a class="btn" href="#analyser">Analyser mon rapport</a> puis choisissez ce fichier.</p></li>',
     '<p><a class="btn" href="#analyser">Analyse my report</a>, then choose this file.</p></li>'),
    ('<li><h3>Vérifiez Python</h3><p>Ouvrez un terminal :</p>', '<li><h3>Check Python</h3><p>Open a terminal:</p>'),
    ('<p class="muted small">Ubuntu / Debian, si nécessaire :</p>', '<p class="muted small">Ubuntu / Debian, if needed:</p>'),
    ('''<li><h3>Installez KMB (une seule fois)</h3>
        <p>KMB s'installe dans son propre dossier <code>~/.kmb</code>, sans toucher au Python du système. Copiez les deux lignes, une à la fois :</p>''',
     '''<li><h3>Install KMB (once)</h3>
        <p>KMB installs into its own <code>~/.kmb</code> folder, without touching the system's Python. Copy the two lines, one at a time:</p>'''),
    ('<li><h3>Scannez</h3><pre>~/.kmb/bin/python -m kmb_library scan</pre>\n        <p class="muted small">Examen complet : <code>',
     '<li><h3>Scan</h3><pre>~/.kmb/bin/python -m kmb_library scan</pre>\n        <p class="muted small">Full check: <code>'),
    ('<li><h3>Voyez le résultat</h3><p>Votre rapport est dans <code>~/Documents/KMB Library</code> : <a href="#analyser">téléversez</a> le fichier <code>KMB-rapport_….json</code>.</p></li>',
     '<li><h3>See the result</h3><p>Your report is in <code>~/Documents/KMB Library</code>: <a href="#analyser">upload</a> the <code>KMB-rapport_….json</code> file.</p></li>'),
    ('<li><h3>Installez Python</h3><p>Depuis <a href="https://www.python.org/downloads/macos/" target="_blank" rel="noopener">python.org</a> : ouvrez le fichier téléchargé et suivez l\'installation.</p></li>',
     '<li><h3>Install Python</h3><p>From <a href="https://www.python.org/downloads/macos/" target="_blank" rel="noopener">python.org</a>: open the downloaded file and follow the installer.</p></li>'),
    ('''<li><h3>Installez KMB (une seule fois)</h3>
        <p>Ouvrez le <b>Terminal</b> (Applications &gt; Utilitaires) et copiez les deux lignes, une à la fois :</p>''',
     '''<li><h3>Install KMB (once)</h3>
        <p>Open <b>Terminal</b> (Applications &gt; Utilities) and copy the two lines, one at a time:</p>'''),
    ('<li><h3>Scannez</h3><pre>~/.kmb/bin/python -m kmb_library scan</pre></li>', '<li><h3>Scan</h3><pre>~/.kmb/bin/python -m kmb_library scan</pre></li>'),
    ('<li><h3>Voyez le résultat</h3><p>Votre rapport est dans <code>Documents/KMB Library</code> : <a href="#analyser">téléversez</a> le fichier <code>KMB-rapport_….json</code>.</p></li>',
     '<li><h3>See the result</h3><p>Your report is in <code>Documents/KMB Library</code>: <a href="#analyser">upload</a> the <code>KMB-rapport_….json</code> file.</p></li>'),
    # analyser
    ('<h1>Analyser mon rapport</h1>', '<h1>Analyse my report</h1>'),
    ('<p>Glissez ici votre fichier <code>KMB-rapport_….json</code>, ou&nbsp;:</p>', '<p>Drop your <code>KMB-rapport_….json</code> file here, or:</p>'),
    ('<label class="btn big">Choisir mon rapport<input', '<label class="btn big">Choose my report<input'),
    ('''<p class="muted small">Vous pouvez choisir deux rapports (avant et après vos corrections) pour les comparer.
      <a href="#" id="load-example">Voir un exemple</a></p>''',
     '''<p class="muted small">You can choose two reports (before and after your fixes) to compare them.
      <a href="#" id="load-example">See an example</a></p>'''),
    ('<p class="reassure">🔒 Le fichier est lu par votre navigateur. Il n\'est ni envoyé ni conservé.</p>',
     '<p class="reassure">🔒 The file is read by your browser. It is neither sent nor stored.</p>'),
    ('<label class="sr" for="scan-select">Rapport affiché</label>', '<label class="sr" for="scan-select">Report shown</label>'),
    ('title="Ajouter un autre rapport (par exemple après corrections)">+ Ajouter un rapport<input',
     'title="Add another report (for example after fixes)">+ Add a report<input'),
    ('title="Imprimer ou enregistrer en PDF">Imprimer / PDF</button>', 'title="Print or save as PDF">Print / PDF</button>'),
    ('id="clear-btn" type="button">Fermer</button>', 'id="clear-btn" type="button">Close</button>'),
    ('data-tab="overview" class="active">Vue d\'ensemble</button>', 'data-tab="overview" class="active">Overview</button>'),
    ('data-tab="findings">Problèmes</button>', 'data-tab="findings">Problems</button>'),
    ('data-tab="plan">Plan de correction</button>', 'data-tab="plan">Fix plan</button>'),
    ('data-tab="software">Logiciels</button>', 'data-tab="software">Software</button>'),
    ('data-tab="storage">Stockage</button>', 'data-tab="storage">Storage</button>'),
    ('data-tab="performance">Performance et matériel</button>', 'data-tab="performance">Performance and hardware</button>'),
    ('data-tab="compare">Comparaison</button>', 'data-tab="compare">Comparison</button>'),
    ('<h3>🤖 Résumé par l\'IA</h3><button type="button" class="btn" id="ai-summary-btn">Résumer mon rapport</button>',
     '<h3>🤖 AI summary</h3><button type="button" class="btn" id="ai-summary-btn">Summarise my report</button>'),
    ('<p class="muted small">Un résumé en quelques lignes de l\'état de votre ordinateur, en mots simples.</p>',
     '<p class="muted small">A few lines summing up the state of your computer, in plain words.</p>'),
    ('<h3>Problèmes par gravité</h3>', '<h3>Problems by severity</h3>'),
    ('<h3>Évolution des scores</h3>', '<h3>Score history</h3>'),
    ('<h3>À corriger en priorité</h3>', '<h3>Fix first</h3>'),
    ('<h3>Examen</h3>', '<h3>Scan details</h3>'),
    ('<option value="detecte">Problèmes détectés</option><option value="conforme">Points conformes</option><option value="non_verifiable">Non vérifiables</option><option value="tous">Tout</option>',
     '<option value="detecte">Problems detected</option><option value="conforme">OK checks</option><option value="non_verifiable">Not checkable</option><option value="tous">All</option>'),
    ('<option value="">Toutes gravités</option><option value="critique">Critique</option><option value="eleve">Élevé</option><option value="moyen">Moyen</option><option value="faible">Faible</option><option value="info">Information</option>',
     '<option value="">All severities</option><option value="critique">Critical</option><option value="eleve">High</option><option value="moyen">Medium</option><option value="faible">Low</option><option value="info">Information</option>'),
    ('<option value="">Tous domaines</option><option value="securite">Sécurité</option><option value="performance">Performance</option><option value="stockage">Stockage</option><option value="logiciels">Logiciels</option>',
     '<option value="">All areas</option><option value="securite">Security</option><option value="performance">Performance</option><option value="stockage">Storage</option><option value="logiciels">Software</option>'),
    ('placeholder="Rechercher (2 caractères min.)"', 'placeholder="Search (2 characters min.)"'),
    ('<h3>Plan de correction</h3>', '<h3>Fix plan</h3>'),
    ('<p class="muted small">Dans l\'ordre : le plus grave d\'abord. Le gain correspond aux points récupérés sur le score.</p>',
     '<p class="muted small">In order: most serious first. The gain is the number of points won back on the score.</p>'),
    ('<h3>🤖 Assistant IA</h3><button class="btn" id="ai-btn">Générer le plan IA</button>', '<h3>🤖 AI assistant</h3><button class="btn" id="ai-btn">Generate the AI plan</button>'),
    ('''<p class="muted small" id="ai-note">Un plan de correction personnalisé. Seul un résumé anonyme des problèmes est envoyé à l'IA (sans nom d'ordinateur, comptes, adresses IP ni fichiers).
          Chaque étape est rattachée à un vrai problème du scan et chaque commande est comparée à la base vérifiée de KMB.</p>''',
     '''<p class="muted small" id="ai-note">A personalised fix plan. Only an anonymous summary of the problems is sent to the AI (no computer name, accounts, IP addresses or files).
          Every step is tied to a real problem from the scan and every command is compared with KMB's verified database.</p>'''),
    ('<h3>🤖 Poser une question sur mon rapport</h3>', '<h3>🤖 Ask a question about my report</h3>'),
    ('<label class="sr" for="ai-question">Votre question</label>', '<label class="sr" for="ai-question">Your question</label>'),
    ('placeholder="Ex. : Est-ce grave si je ne chiffre pas mon disque ?"', 'placeholder="E.g. Is it serious if I don\'t encrypt my disk?"'),
    ('id="ai-ask-btn">Demander</button>', 'id="ai-ask-btn">Ask</button>'),
    ('<option value="">Tous</option><option value="fin_de_support">Fin de support</option><option value="maj_disponible">Mise à jour disponible</option><option value="supporte">Supportés</option><option value="non_suivi">Non suivis</option>',
     '<option value="">All</option><option value="fin_de_support">End of support</option><option value="maj_disponible">Update available</option><option value="supporte">Supported</option><option value="non_suivi">Not tracked</option>'),
    ('placeholder="Nom ou éditeur"', 'placeholder="Name or publisher"'),
    ('<h3>Disques</h3>', '<h3>Disks</h3>'),
    ('<h3>Les plus gros dossiers</h3>', '<h3>Largest folders</h3>'),
    ('<h3>Espace récupérable sans risque</h3>', '<h3>Space you can free safely</h3>'),
    ('<h3>Où part l\'espace</h3>', '<h3>Where your space goes</h3>'),
    ('<h3>Gros fichiers (200 Mo et plus)</h3>', '<h3>Large files (200 MB and more)</h3>'),
    ('<h3>Applications installées les plus volumineuses</h3>', '<h3>Largest installed applications</h3>'),
    ('<p class="small muted">Pour libérer cet espace : désinstallez l\'application (Paramètres > Applications), ne supprimez jamais son dossier à la main.</p>',
     '<p class="small muted">To free this space: uninstall the application (Settings > Apps); never delete its folder by hand.</p>'),
    ('<h3>Fichiers en double</h3>', '<h3>Duplicate files</h3>'),
    ('<h3>Applications qui utilisent le plus de mémoire</h3>', '<h3>Applications using the most memory</h3>'),
    ('<h3>Programmes lancés au démarrage</h3>', '<h3>Programs launched at startup</h3>'),
    ('<h3>Santé matérielle</h3>', '<h3>Hardware health</h3>'),
    ('<label>Avant <select name="ancien"', '<label>Before <select name="ancien"'),
    ('<label>Après <select name="nouveau"', '<label>After <select name="nouveau"'),
    ('<button class="btn" type="submit">Comparer</button>', '<button class="btn" type="submit">Compare</button>'),
    # questions
    ('<h1>Questions fréquentes</h1>', '<h1>Frequently asked questions</h1>'),
    ('<summary>Mes données sont-elles envoyées sur Internet&nbsp;?</summary>', '<summary>Is my data sent over the Internet?</summary>'),
    ('''<p>Non. Le rapport est lu par votre navigateur, sur votre ordinateur. Il n'est ni envoyé ni conservé par ce site.
      Le scanner contacte seulement le site public endoflife.date pour connaître les dates de fin de support des logiciels (sans rien envoyer de personnel).</p>
    <p><b>Seule exception, si vous l'acceptez :</b> l'assistant IA. Voir la question suivante.</p>''',
     '''<p>No. The report is read by your browser, on your computer. This site neither sends nor stores it.
      The scanner only contacts the public endoflife.date site to find out software end-of-support dates (without sending anything personal).</p>
    <p><b>The only exception, if you agree:</b> the AI assistant. See the next question.</p>'''),
    ('<summary>Comment fonctionne l\'assistant IA&nbsp;?</summary>', '<summary>How does the AI assistant work?</summary>'),
    ('''<p>Les boutons 🤖 (« Explique-moi ce problème », « Résumer mon rapport », plan de correction, questions, comparaison) font appel à une IA.
      La première fois, le site vous demande votre accord. Il envoie alors un <b>résumé anonyme</b> des problèmes détectés (titre, gravité, constat,
      commandes de correction connues) : jamais le nom de l'ordinateur, les comptes, les adresses IP, vos fichiers ni le rapport complet.</p>
    <p>Ce résumé passe par le relais de KMB Library, qui l'envoie au service d'IA Groq (modèles ouverts) puis vous renvoie la réponse ; rien n'est conservé.
      L'IA peut se tromper : KMB vérifie que chaque étape correspond à un vrai problème du scan et signale toute commande absente de sa base vérifiée.
      Le nombre de demandes est limité (10 par heure) pour que le service reste gratuit pour tous.</p>''',
     '''<p>The 🤖 buttons (“Explain this problem to me”, “Summarise my report”, fix plan, questions, comparison) use an AI.
      The first time, the site asks for your consent. It then sends an <b>anonymous summary</b> of the problems detected (title, severity, finding,
      known fix commands): never the computer name, accounts, IP addresses, your files or the full report.</p>
    <p>This summary goes through the KMB Library relay, which sends it to the Groq AI service (open models) and returns the answer; nothing is stored.
      AI can be wrong: KMB checks that every step matches a real problem from the scan and flags any command missing from its verified database.
      The number of requests is limited (10 per hour) so that the service stays free for everyone.</p>'''),
    ('<summary>Le scanner peut-il abîmer mon ordinateur&nbsp;?</summary>', '<summary>Can the scanner damage my computer?</summary>'),
    ('<p>Non. Il lit des informations, il ne modifie rien. Les corrections sont proposées : c\'est vous qui décidez de les appliquer.</p>',
     '<p>No. It reads information and changes nothing. Fixes are suggested: you decide whether to apply them.</p>'),
    ('<summary>Pourquoi faut-il installer Python&nbsp;?</summary>', '<summary>Why do I need to install Python?</summary>'),
    ('''<p>KMB Library est une librairie Python, comme beaucoup d'outils informatiques. Python s'installe depuis son site officiel, puis une seule commande
      installe KMB depuis <a href="https://pypi.org/project/kmb-library/" target="_blank" rel="noopener">PyPI</a>, la bibliothèque officielle des logiciels Python : pas de programme inconnu à ouvrir, et le code de KMB reste consultable.</p>''',
     '''<p>KMB Library is a Python library, like many computer tools. Python is installed from its official website, then a single command
      installs KMB from <a href="https://pypi.org/project/kmb-library/" target="_blank" rel="noopener">PyPI</a>, the official Python software repository: no unknown program to open, and KMB's code stays open to inspection.</p>'''),
    ('<summary>« python » n\'est pas reconnu, ou le Microsoft Store s\'ouvre&nbsp;?</summary>', '<summary>“python” is not recognized, or the Microsoft Store opens?</summary>'),
    ('''<p>Python n'est pas installé, ou la case « Add python.exe to PATH » n'a pas été cochée. Relancez l'installateur de Python, choisissez « Modify »,
      cochez « Add Python to environment variables », puis fermez et rouvrez l'invite de commandes.</p>''',
     '''<p>Python is not installed, or the “Add python.exe to PATH” box was not checked. Run the Python installer again, choose “Modify”,
      check “Add Python to environment variables”, then close and reopen the Command Prompt.</p>'''),
    ('<summary>Comment mettre KMB à jour ou le désinstaller&nbsp;?</summary>', '<summary>How do I update or uninstall KMB?</summary>'),
    ('''<p>Mise à jour : <code>python -m pip install --upgrade kmb-library</code>.
      Désinstallation : <code>python -m pip uninstall kmb-library</code>.</p>
    <p class="muted small">Pour consulter le code : <a data-dl-zip href="#">télécharger KMB Library (ZIP)</a>.</p>''',
     '''<p>Update: <code>python -m pip install --upgrade kmb-library</code>.
      Uninstall: <code>python -m pip uninstall kmb-library</code>.</p>
    <p class="muted small">To look at the code: <a data-dl-zip href="#">download KMB Library (ZIP)</a>.</p>'''),
    ('<summary>Que veut dire « non vérifiable »&nbsp;?</summary>', '<summary>What does “not checkable” mean?</summary>'),
    ('''<p>Certains contrôles exigent les droits d'administrateur. Pour un examen complet, lancez le scan depuis une invite de commandes ouverte « en tant qu'administrateur » (voir le guide, étape 4).
      Ces contrôles ne retirent aucun point.</p>''',
     '''<p>Some checks require administrator rights. For a full check, run the scan from a Command Prompt opened “as administrator” (see the guide, step 4).
      These checks don't cost any points.</p>'''),
    ('<summary>Comment voir mes progrès après mes corrections&nbsp;?</summary>', '<summary>How can I see my progress after my fixes?</summary>'),
    ('<p>Refaites un scan, puis dans « Analyser mon rapport », ajoutez l\'ancien <b>et</b> le nouveau rapport. L\'onglet « Comparaison » montre ce qui est corrigé, ce qui reste et ce qui est nouveau.</p>',
     '<p>Scan again, then in “Analyse my report”, add the old <b>and</b> the new report. The “Comparison” tab shows what is fixed, what remains and what is new.</p>'),
    ('<summary>Quel fichier dois-je choisir&nbsp;?</summary>', '<summary>Which file should I choose?</summary>'),
    ('''<p>Le fichier qui commence par <code>KMB-rapport_</code> et finit par <code>.json</code> : c'est votre rapport, et ce site sert à l'afficher.
      Le dossier <code>donnees-brutes</code> (données de départ) et le dossier <code>.cache</code> servent uniquement au fonctionnement et à la vérification.</p>''',
     '''<p>The file that starts with <code>KMB-rapport_</code> and ends with <code>.json</code>: it is your report, and this site displays it.
      The <code>donnees-brutes</code> folder (raw data) and the <code>.cache</code> folder are only used internally and for verification.</p>'''),
    # consentement et pied de page
    ('<h2>🤖 Utiliser l\'assistant IA ?</h2>', '<h2>🤖 Use the AI assistant?</h2>'),
    ('''<p>Pour vous répondre, KMB envoie à l'IA un <b>résumé anonyme</b> des problèmes détectés : leur titre, leur gravité, le constat et les
      commandes de correction connues.</p>''',
     '''<p>To answer you, KMB sends the AI an <b>anonymous summary</b> of the problems detected: their title, severity, finding and
      known fix commands.</p>'''),
    ('<li>Jamais envoyés : le nom de l\'ordinateur, les comptes, les adresses IP, vos fichiers ni le rapport complet.</li>',
     '<li>Never sent: the computer name, accounts, IP addresses, your files or the full report.</li>'),
    ('<li>Le relais KMB transmet ce résumé au service d\'IA <b>Groq</b>, puis vous renvoie la réponse. Rien n\'est conservé.</li>',
     '<li>The KMB relay passes this summary to the <b>Groq</b> AI service, then returns the answer. Nothing is stored.</li>'),
    ('<li>L\'IA peut se tromper : chaque réponse est vérifiée par KMB, et les commandes inconnues sont signalées.</li>',
     '<li>AI can be wrong: every answer is checked by KMB, and unknown commands are flagged.</li>'),
    ('<p class="muted small">Sans votre accord, rien n\'est envoyé et le reste du rapport fonctionne normalement.</p>',
     '<p class="muted small">Without your consent, nothing is sent and the rest of the report works normally.</p>'),
    ('<button value="non" class="btn ghost">Non merci</button><button value="oui" class="btn">J\'accepte</button>',
     '<button value="non" class="btn ghost">No thanks</button><button value="oui" class="btn">I agree</button>'),
    ('<nav><a href="#guide">Guide</a><a href="#analyser">Analyser mon rapport</a><a href="#questions">Questions</a>',
     '<nav><a href="#guide">Guide</a><a href="#analyser">Analyse my report</a><a href="#questions">Questions</a>'),
    ('rel="noopener">Code sur GitHub</a></nav>', 'rel="noopener">Code on GitHub</a></nav>'),
    ('<div>Projet scolaire · <span id="mode-note"></span></div>', '<div>School project · <span id="mode-note"></span></div>'),
]

# Chemins : la page anglaise est dans le sous-dossier en/
CHEMINS = [
    ('href="favicon.svg"', 'href="../favicon.svg"'), ('href="icon-512.png" type', 'href="../icon-512.png" type'),
    ('<link rel="apple-touch-icon" href="icon-512.png">', '<link rel="apple-touch-icon" href="../icon-512.png">'),
    ('href="style.css"', 'href="../style.css"'), ('href="llms.txt"', 'href="../llms.txt"'),
    ('<script src="config.js" defer></script>', '<script src="../config.js" defer></script>\n  <script src="../i18n-en.js" defer></script>'),
    ('<script src="app.js" defer></script>', '<script src="../app.js" defer></script>'),
]
# Mots français qui ne doivent plus apparaître dans le texte visible de la page anglaise
FRANCAIS = re.compile(r"\b(?:votre|vous|ordinateur|problème|rapport(?!_)|sécurité|logiciels|commande|données|fichiers|"
                      r"vérifie|gratuit|étape|dossier|corriger|réglage|Accueil|Questions fréquentes)\b", re.I)


def remplacer(s: str, paires: list[tuple[str, str]]) -> str:
    for fr, en in paires:
        assert s.count(fr) >= 1, f"texte introuvable dans la page française : {fr[:90]}"
        s = s.replace(fr, en)
    return s


def faq_jsonld(page: str) -> list[dict]:
    """Questions-réponses de la page elle-même (données structurées pour Google)."""
    def texte(t):
        return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", t))).strip()
    return [{"@type": "Question", "name": texte(q), "acceptedAnswer": {"@type": "Answer", "text": texte(r)}}
            for q, r in re.findall(r'<details class="faq"[^>]*><summary>(.*?)</summary>(.*?)</details>', page, re.S)]


def donnees_structurees(page: str, langue: str) -> str:
    m = re.search(r'(<script type="application/ld\+json">\n)(.*?)(\n  </script>)', page, re.S)
    ld = json.loads(m.group(2))
    url = SITE + ("en/" if langue == "en" else "")
    for g in ld["@graph"]:
        if g["@type"] == "WebSite":
            g.update({"@id": url + "#site", "url": url, "inLanguage": langue})
        elif g["@type"] == "SoftwareApplication":
            g.update({"url": url, "inLanguage": langue, "installUrl": url + "#guide"})
            if langue == "en":
                g.update({"description": DESC_EN, "softwareRequirements": "Python 3.10 or newer", "featureList": [
                    "End of support of the system and software", "Antivirus, firewall, disk encryption, accounts",
                    "Exposed network services and Wi-Fi", "Performance: memory, processor, startup, battery",
                    "Storage: large files, duplicates, applications, space you can free",
                    "Fix guide: check, open the setting, fix",
                    "AI assistant (with consent): problem explanations, summary, fix plan, questions, before/after comment"]})
        elif g["@type"] == "FAQPage":
            g["mainEntity"] = faq_jsonld(page)
    return page[:m.start(2)] + json.dumps(ld, ensure_ascii=False, indent=1) + page[m.end(2):]


def entete_langues(page: str, langue: str) -> str:
    """Liens hreflang (les deux versions se signalent) et bouton de langue dans la barre du haut."""
    liens = (f'<link rel="alternate" hreflang="fr" href="{SITE}">\n  <link rel="alternate" hreflang="en" href="{SITE}en/">\n'
             f'  <link rel="alternate" hreflang="x-default" href="{SITE}">\n')
    page = re.sub(r'  <link rel="alternate" hreflang=[^\n]*\n', "", page)
    page = page.replace('  <link rel="alternate" type="text/plain"', "  " + liens + '  <link rel="alternate" type="text/plain"', 1)
    bouton = ('<a class="lang-btn" id="lang-btn" href="en/" hreflang="en" lang="en" title="English version">EN</a>' if langue == "fr"
              else '<a class="lang-btn" id="lang-btn" href="../" hreflang="fr" lang="fr" title="Version française">FR</a>')
    page = re.sub(r'\n    <a class="lang-btn"[^\n]*', "", page)
    # Langue choisie avec ce bouton lors d'une visite précédente (sans effet pour les moteurs de recherche : pas de mémoire)
    autre, cible = ("en", "en/") if langue == "fr" else ("fr", "../")
    page = re.sub(r'  <script>try \{ if \(localStorage\.getItem\("kmb-lang"\)[^\n]*\n', "", page)
    redirection = (f'  <script>try {{ if (localStorage.getItem("kmb-lang") === "{autre}") '
                   f'location.replace("{cible}" + location.search + location.hash); }} catch (e) {{}}</script>\n')
    page = page.replace("  <script src=", redirection + "  <script src=", 1)
    return page.replace('\n    <button type="button" class="theme-btn"', "\n    " + bouton + '\n    <button type="button" class="theme-btn"', 1)


if __name__ == "__main__":
    fr = FR.read_text(encoding="utf-8")
    fr = donnees_structurees(entete_langues(fr, "fr"), "fr")   # page française : FAQ pour Google à jour, liens de langue
    FR.write_text(fr, encoding="utf-8")

    en = remplacer(fr, [(TITLE_FR, TITLE_EN), (DESC_FR, DESC_EN)] + TEXTES + CHEMINS)
    en = en.replace(f'<link rel="canonical" href="{SITE}">', f'<link rel="canonical" href="{SITE}en/">')
    en = en.replace(f'<meta property="og:url" content="{SITE}">', f'<meta property="og:url" content="{SITE}en/">')
    en = entete_langues(donnees_structurees(en, "en"), "en")
    visible = re.sub(r"<script.*?</script>|<style.*?</style>|<code[^>]*>.*?</code>|<pre>.*?</pre>|<[^>]+>", " ", en, flags=re.S)
    restes = sorted(set(m.group(0) for m in FRANCAIS.finditer(visible)))
    assert not restes, f"mots français restés dans la page anglaise : {restes}"
    EN.parent.mkdir(exist_ok=True)
    EN.write_text(en, encoding="utf-8")
    print(f"Page anglaise : {EN.relative_to(ROOT)} ({len(TEXTES)} textes traduits) ; page française mise à jour (hreflang, FAQ).")
