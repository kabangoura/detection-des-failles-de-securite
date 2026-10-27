"""Catalogue des commandes de correction, classées pour l'utilisateur, appliqué à knowledge_base.json.

Chaque commande est décrite par :
    type      verifier (🔍 montre le problème) | ouvrir (⚙️ ouvre le bon réglage) | corriger (🛠️ corrige directement)
    cmd       la commande exacte à copier
    ou        cmd | cmd_admin | ps | ps_admin | terminal  (où la taper)
    effet     ce que fait la commande, en une phrase
    attendu   (vérifier) ce qu'on doit voir si tout va bien
    remplacer mots à remplacer avant de lancer la commande, avec leur explication
    attention avertissement affiché à côté de la commande

Usage : python scripts/catalogue_commandes.py   (met à jour kmb_library/rules/knowledge_base.json)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def V(cmd, ou, effet, attendu=None, remplacer=None, attention=None):
    return _c("verifier", cmd, ou, effet, attendu, remplacer, attention)


def O(cmd, ou, effet, remplacer=None, attention=None):
    return _c("ouvrir", cmd, ou, effet, None, remplacer, attention)


def C(cmd, ou, effet, remplacer=None, attention=None):
    return _c("corriger", cmd, ou, effet, None, remplacer, attention)


def _c(type_, cmd, ou, effet, attendu, remplacer, attention):
    d = {"type": type_, "cmd": cmd, "ou": ou, "effet": effet}
    if attendu:
        d["attendu"] = attendu
    if remplacer:
        d["remplacer"] = remplacer
    if attention:
        d["attention"] = attention
    return d


REBOOT = "Enregistrez votre travail : l'ordinateur redémarre immédiatement."
UPDATE_DEB = "Ubuntu / Debian. Fedora : sudo dnf upgrade --refresh"

CATALOGUE: dict[str, dict[str, list[dict]]] = {
    # ------------------------------------------------------------------ système
    "SYS-001": {
        "windows": [
            V("winver", "cmd", "Affiche la version de Windows installée.", "Windows 11 ; « Windows 10 version 22H2 » signifie : plus de mises à jour de sécurité."),
            O("start ms-settings:windowsupdate", "cmd", "Ouvre Windows Update : si l'ordinateur est compatible, l'offre « Passer à Windows 11 » y apparaît."),
        ],
        "linux": [
            V("cat /etc/os-release", "terminal", "Affiche le nom et la version de la distribution.", "une version encore supportée (voir endoflife.date)"),
            C("sudo do-release-upgrade", "terminal", "Lance la mise à niveau vers la version suivante d'Ubuntu.",
              attention="Sauvegardez vos données avant. Comptez une heure ou plus, ordinateur branché."),
        ],
        "macos": [
            V("sw_vers", "terminal", "Affiche la version de macOS.", "une version encore supportée par Apple"),
            O('open "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"', "terminal",
              "Ouvre Réglages Système > Mise à jour de logiciels, où la mise à niveau est proposée."),
        ],
    },
    "SYS-002": {
        "windows": [O("start ms-settings:windowsupdate", "cmd", "Ouvre Windows Update pour installer la version suivante de Windows.")],
    },
    "SYS-003": {
        "windows": [
            O("start ms-settings:windowsupdate", "cmd", "Ouvre Windows Update : cliquez ensuite sur « Rechercher des mises à jour » puis « Installer »."),
            C("UsoClient StartInteractiveScan", "cmd", "Lance la recherche et le téléchargement des mises à jour, comme le bouton « Rechercher des mises à jour ».",
              attention="Redémarrez l'ordinateur quand Windows le demande."),
        ],
        "linux": [
            C("sudo apt update && sudo apt upgrade", "terminal", "Télécharge et installe toutes les mises à jour (répondez « O » ou « Y » pour confirmer).",
              attention=UPDATE_DEB),
        ],
        "macos": [
            V("softwareupdate -l", "terminal", "Liste les mises à jour disponibles.", "« No new software available »"),
            C("sudo softwareupdate -ia --restart", "terminal", "Installe toutes les mises à jour disponibles.", attention=REBOOT),
        ],
    },
    "SYS-004": {
        "windows": [
            V("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID,InstalledOn", "ps",
              "Liste les 5 derniers correctifs installés avec leur date.", "une date de moins de 45 jours"),
            O("start ms-settings:windowsupdate-history", "cmd", "Ouvre l'historique de Windows Update pour repérer les installations en échec."),
            C("UsoClient StartInteractiveScan", "cmd", "Relance la recherche et l'installation des mises à jour."),
        ],
        "linux": [
            V("grep \" upgrade \" /var/log/dpkg.log | tail -5", "terminal", "Affiche les dernières mises à jour de paquets installées.", "des dates récentes"),
            C("sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades", "terminal",
              "Active l'installation automatique des mises à jour de sécurité (répondez « Oui »)."),
        ],
    },
    "SYS-005": {
        "windows": [
            V('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA', "cmd",
              "Affiche l'état du contrôle de compte d'utilisateur (UAC).", "EnableLUA    REG_DWORD    0x1  (0x0 = désactivé)"),
            O("UserAccountControlSettings", "cmd", "Ouvre le réglage de l'UAC : placez le curseur sur le niveau par défaut (2e cran en partant du haut)."),
            C("Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1", "ps_admin",
              "Réactive l'UAC.", attention="Redémarrez ensuite l'ordinateur pour que le changement s'applique."),
        ],
    },
    "SYS-006": {
        "windows": [
            V('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin', "cmd",
              "Affiche le niveau de confirmation demandé aux administrateurs.", "0x5 (valeur par défaut) ; 0x0 = aucune confirmation"),
            O("UserAccountControlSettings", "cmd", "Ouvre le réglage de l'UAC pour remonter le curseur au niveau par défaut."),
            C("Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 5",
              "ps_admin", "Rétablit la demande de confirmation par défaut."),
        ],
    },
    "SYS-007": {
        "windows": [
            V("msinfo32", "cmd", "Ouvre « Informations système » : lisez la ligne « État du démarrage sécurisé ».", "Activé ; « Mode BIOS : Hérité » = Secure Boot impossible sans conversion"),
            O("shutdown /r /fw /t 0", "cmd_admin", "Redémarre directement dans les réglages UEFI (BIOS) pour activer « Secure Boot ».",
              attention=REBOOT + " Fonctionne seulement sur les PC en mode UEFI."),
        ],
        "linux": [V("mokutil --sb-state", "terminal", "Affiche l'état de Secure Boot.", "SecureBoot enabled")],
    },
    # ------------------------------------------------------------------ comptes
    "ACC-001": {
        "windows": [
            V("Get-LocalGroupMember -SID S-1-5-32-544", "ps", "Liste les comptes membres du groupe Administrateurs.", "au plus 2 comptes actifs"),
            O("lusrmgr.msc", "cmd", "Ouvre « Utilisateurs et groupes locaux » (Windows Pro) : Groupes > Administrateurs."),
            C("Remove-LocalGroupMember -SID S-1-5-32-544 -Member 'NOM_DU_COMPTE'", "ps_admin", "Retire ce compte du groupe Administrateurs.",
              {"NOM_DU_COMPTE": "le nom exact du compte à retirer, lu avec la commande de vérification (sans le nom du PC devant)"},
              "Ne retirez jamais le dernier compte administrateur, ni le vôtre avant d'avoir un autre compte administrateur qui fonctionne."),
        ],
        "linux": [
            V("getent group sudo wheel", "terminal", "Liste les comptes autorisés à utiliser sudo.", "au plus 2 comptes"),
            C("sudo gpasswd -d NOM sudo", "terminal", "Retire ce compte du groupe sudo.", {"NOM": "le nom du compte à retirer"},
              "Gardez au moins un compte qui peut utiliser sudo."),
        ],
        "macos": [
            V("dscl . -read /Groups/admin GroupMembership", "terminal", "Liste les comptes administrateurs.", "au plus 2 comptes (root compris)"),
            C("sudo dseditgroup -o edit -d NOM -t user admin", "terminal", "Retire les droits d'administration de ce compte.",
              {"NOM": "le nom court du compte"}, "Gardez au moins un compte administrateur."),
        ],
    },
    "ACC-002": {
        "windows": [
            V("Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Select-Object Name,Enabled", "ps", "Affiche l'état du compte Invité.", "Enabled : False"),
            C("Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Disable-LocalUser", "ps_admin", "Désactive le compte Invité."),
        ],
        "macos": [
            V("defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled", "terminal", "Affiche l'état du compte invité.", "0"),
            C("sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false", "terminal", "Désactive le compte invité."),
        ],
    },
    "ACC-003": {
        "windows": [
            V("Get-LocalUser | Where-Object { $_.SID -like '*-500' } | Select-Object Name,Enabled", "ps", "Affiche l'état du compte Administrateur intégré.", "Enabled : False"),
            C("Get-LocalUser | Where-Object { $_.SID -like '*-500' } | Disable-LocalUser", "ps_admin", "Désactive le compte Administrateur intégré.",
              attention="Vérifiez d'abord qu'un autre compte administrateur fonctionne."),
        ],
    },
    "ACC-004": {
        "windows": [
            V("Get-LocalUser | Select-Object Name,Enabled,PasswordRequired", "ps", "Liste les comptes et indique s'ils exigent un mot de passe.",
              "PasswordRequired : True pour chaque compte activé"),
            C("net user NOM_DU_COMPTE *", "cmd_admin", "Demande de saisir un nouveau mot de passe pour ce compte (rien ne s'affiche pendant la frappe : c'est normal).",
              {"NOM_DU_COMPTE": "le nom du compte indiqué dans le constat"}),
            C("net user NOM_DU_COMPTE /passwordreq:yes", "cmd_admin", "Rend le mot de passe obligatoire pour ce compte.",
              {"NOM_DU_COMPTE": "le nom du compte indiqué dans le constat"}),
        ],
        "linux": [
            V("sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow", "terminal", "Liste les comptes sans mot de passe.", "aucune ligne"),
            C("sudo passwd NOM", "terminal", "Définit un mot de passe pour ce compte.", {"NOM": "le nom du compte indiqué dans le constat"}),
            C("sudo passwd -l NOM", "terminal", "Verrouille ce compte s'il n'est pas utilisé.", {"NOM": "le nom du compte indiqué dans le constat"}),
        ],
    },
    "ACC-005": {
        "windows": [
            V("Get-LocalGroupMember -SID S-1-5-32-544", "ps", "Vérifie si votre compte fait partie des administrateurs.", "votre compte absent de la liste"),
            O("start ms-settings:otherusers", "cmd", "Ouvre la page des comptes pour créer un compte administrateur de maintenance, puis changer le type du vôtre."),
            C("net user admin-maintenance * /add", "cmd_admin", "Crée le compte « admin-maintenance » et demande son mot de passe."),
            C("Add-LocalGroupMember -SID S-1-5-32-544 -Member 'admin-maintenance'", "ps_admin", "Donne les droits d'administration au compte de maintenance.",
              attention="Testez le compte de maintenance AVANT de retirer les droits de votre compte quotidien."),
        ],
        "macos": [
            O('open "x-apple.systempreferences:com.apple.Users-Groups-Settings.extension"', "terminal", "Ouvre Utilisateurs et groupes pour créer un compte administrateur de maintenance."),
            C("sudo dseditgroup -o edit -d NOM -t user admin", "terminal", "Retire les droits d'administration de votre compte quotidien.",
              {"NOM": "le nom court de votre compte"}, "Créez et testez d'abord un autre compte administrateur."),
        ],
    },
    # ------------------------------------------------------------------ réseau
    "NET-001": {
        "windows": [
            V("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol", "ps_admin", "Indique si le protocole SMBv1 est activé.", "False"),
            O("optionalfeatures", "cmd", "Ouvre « Fonctionnalités Windows » : décochez « Support de partage de fichiers SMB 1.0/CIFS »."),
            C("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force", "ps_admin", "Désactive SMBv1 immédiatement."),
            C("Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol", "ps_admin", "Retire complètement la fonctionnalité SMBv1.",
              attention="Windows demande ensuite de redémarrer."),
        ],
    },
    "NET-002": {
        "windows": [
            V('reg query "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections', "cmd",
              "Indique si le Bureau à distance est activé.", "0x1 = désactivé (0x0 = activé)"),
            O("start ms-settings:remotedesktop", "cmd", "Ouvre le réglage « Bureau à distance » pour le désactiver."),
            C("Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1", "ps_admin",
              "Désactive le Bureau à distance.", attention="Si vous êtes connecté à ce PC à distance, la connexion sera coupée."),
        ],
    },
    "NET-003": {
        "windows": [
            V('reg query "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication', "cmd",
              "Indique si l'authentification réseau (NLA) est exigée.", "0x1"),
            O("SystemPropertiesRemote", "cmd", "Ouvre les propriétés « Utilisation à distance » : cochez « …authentification au niveau du réseau »."),
            C("Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
              "ps_admin", "Exige l'authentification réseau (NLA) pour le Bureau à distance."),
        ],
    },
    "NET-004": {
        "windows": [
            V("netstat -ano | findstr :PORT", "cmd", "Montre si le port est ouvert et le numéro du programme (PID, dernière colonne).",
              "aucune ligne LISTENING avec 0.0.0.0", {"PORT": "le numéro de port indiqué dans le constat (ex. 5432)"}),
            V('tasklist /FI "PID eq PID"', "cmd", "Affiche le nom du programme qui utilise ce port.", remplacer={"PID": "le numéro de programme (PID) indiqué dans le constat"}),
            O("services.msc", "cmd", "Ouvre la liste des services : arrêtez le service s'il n'est pas utilisé et passez son démarrage en « Manuel »."),
            C("New-NetFirewallRule -DisplayName 'KMB - bloquer PORT' -Direction Inbound -LocalPort PORT -Protocol TCP -Action Block -Profile Public",
              "ps_admin", "Bloque ce port sur les réseaux publics (Wi-Fi d'un café, d'une école…).",
              {"PORT": "le numéro de port indiqué dans le constat (ex. 5432), aux deux endroits"}),
        ],
        "linux": [
            V("sudo ss -tlnp | grep :PORT", "terminal", "Montre si le port est ouvert et par quel programme.", "aucune ligne avec 0.0.0.0 ou *",
              {"PORT": "le numéro de port indiqué dans le constat"}),
            C("sudo systemctl disable --now SERVICE", "terminal", "Arrête le service et l'empêche de redémarrer.",
              {"SERVICE": "le nom du service (ex. postgresql, vsftpd)"}),
            C("sudo ufw deny PORT/tcp", "terminal", "Bloque ce port dans le pare-feu.", {"PORT": "le numéro de port indiqué dans le constat"}),
        ],
        "macos": [
            V("sudo lsof -nP -iTCP:PORT -sTCP:LISTEN", "terminal", "Montre quel programme écoute sur ce port.", "aucune ligne",
              {"PORT": "le numéro de port indiqué dans le constat"}),
            C("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on", "terminal", "Active le pare-feu de macOS."),
        ],
    },
    "NET-005": {
        "windows": [
            V("Get-SmbShare", "ps", "Liste les dossiers partagés.", "seulement ADMIN$, C$ et IPC$ (partages par défaut)"),
            V("Get-SmbShareAccess -Name NOM_DU_PARTAGE", "ps", "Montre qui a accès au partage.", "pas de « Tout le monde » (Everyone)",
              {"NOM_DU_PARTAGE": "le nom du partage indiqué dans le constat"}),
            O("fsmgmt.msc", "cmd", "Ouvre « Dossiers partagés » pour arrêter le partage ou réduire les accès."),
            C("Remove-SmbShare -Name NOM_DU_PARTAGE -Force", "ps_admin", "Arrête le partage (le dossier et ses fichiers ne sont pas supprimés).",
              {"NOM_DU_PARTAGE": "le nom du partage indiqué dans le constat"}),
        ],
        "linux": [
            V("sudo exportfs -v", "terminal", "Liste les dossiers partagés en NFS.", "aucune ligne, ou des clients précis (pas *)"),
            V("testparm -s", "terminal", "Affiche les partages Samba.", "pas de « guest ok = yes »"),
            C("sudo nano /etc/exports", "terminal", "Ouvre le fichier des partages NFS : supprimez ou restreignez la ligne, puis Ctrl+O, Entrée, Ctrl+X."),
            C("sudo exportfs -ra", "terminal", "Applique les modifications des partages NFS."),
            C("sudo systemctl reload smbd", "terminal", "Applique les modifications des partages Samba (après modification de /etc/samba/smb.conf)."),
        ],
    },
    "NET-006": {
        "macos": [
            V("sudo systemsetup -getremotelogin", "terminal", "Indique si la session à distance (SSH) est activée.", "Remote Login: Off"),
            O('open "x-apple.systempreferences:com.apple.Sharing-Settings.extension"', "terminal", "Ouvre Réglages > Général > Partage pour désactiver ce qui n'est pas utilisé."),
            C("sudo systemsetup -setremotelogin off", "terminal", "Désactive la session à distance (SSH)."),
        ],
    },
    # ------------------------------------------------------------------ pare-feu
    "FW-001": {
        "windows": [
            V("netsh advfirewall show allprofiles state", "cmd", "Affiche l'état du pare-feu pour chaque profil réseau.", "État  ACTIVÉ (ON) pour les 3 profils"),
            O("start windowsdefender://network", "cmd", "Ouvre « Pare-feu et protection du réseau » de Sécurité Windows."),
            C("netsh advfirewall set allprofiles state on", "cmd_admin", "Active le pare-feu pour les 3 profils (domaine, privé, public)."),
        ],
        "linux": [
            V("sudo ufw status", "terminal", "Affiche l'état du pare-feu.", "Status: active"),
            C("sudo ufw allow OpenSSH", "terminal", "Garde l'accès SSH autorisé.", attention="Seulement si vous vous connectez à ce PC à distance en SSH."),
            C("sudo ufw enable", "terminal", "Active le pare-feu (répondez « y »). Fedora : sudo systemctl enable --now firewalld"),
        ],
        "macos": [
            V("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", "terminal", "Affiche l'état du pare-feu.", "Firewall is enabled"),
            C("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on", "terminal", "Active le pare-feu de macOS."),
        ],
    },
    "FW-002": {
        "windows": [
            V("Get-NetFirewallProfile | Select-Object Name,DefaultInboundAction", "ps", "Affiche l'action par défaut pour les connexions entrantes.",
              "Block ou NotConfigured pour chaque profil"),
            O("wf.msc", "cmd", "Ouvre le pare-feu avancé : Propriétés > « Connexions entrantes : Bloquer »."),
            C("Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block", "ps_admin", "Bloque par défaut les connexions entrantes."),
        ],
        "linux": [
            V("sudo ufw status verbose", "terminal", "Affiche la politique par défaut.", "Default: deny (incoming)"),
            C("sudo ufw default deny incoming", "terminal", "Bloque par défaut les connexions entrantes."),
            C("sudo ufw reload", "terminal", "Applique le changement."),
        ],
    },
    "FW-003": {
        "windows": [
            V("Get-NetFirewallRule -DisplayName 'NOM_DE_LA_REGLE' | Select-Object DisplayName,Enabled,Profile", "ps_admin",
              "Affiche la règle signalée.", "Enabled : False, ou un profil autre que Public",
              {"NOM_DE_LA_REGLE": "le nom de la règle indiqué dans le constat"}),
            O("wf.msc", "cmd", "Ouvre le pare-feu avancé : Règles de trafic entrant."),
            C("Disable-NetFirewallRule -DisplayName 'NOM_DE_LA_REGLE'", "ps_admin", "Désactive cette règle.",
              {"NOM_DE_LA_REGLE": "le nom de la règle indiqué dans le constat"}),
        ],
    },
    # ------------------------------------------------------------------ antivirus
    "AV-001": {
        "windows": [
            V("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled", "ps", "Affiche l'état de Microsoft Defender.", "True et True"),
            O("start windowsdefender://threat", "cmd", "Ouvre « Protection contre les virus et menaces »."),
            C("Set-MpPreference -DisableRealtimeMonitoring $false", "ps_admin", "Active la protection en temps réel de Defender."),
            C("Start-MpScan -ScanType QuickScan", "ps_admin", "Lance une analyse rapide (quelques minutes)."),
        ],
        "linux": [
            C("sudo apt install clamav clamav-daemon", "terminal", "Installe l'antivirus ClamAV.", attention=UPDATE_DEB.replace("sudo dnf upgrade --refresh", "sudo dnf install clamav")),
            C("sudo systemctl enable --now clamav-freshclam", "terminal", "Active la mise à jour automatique des signatures."),
            V("clamscan -r ~/Téléchargements", "terminal", "Analyse le dossier Téléchargements.", "Infected files: 0"),
        ],
    },
    "AV-002": {
        "windows": [
            V("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled", "ps", "Indique si la protection en temps réel est active.", "True"),
            O("start windowsdefender://threat", "cmd", "Ouvre « Protection contre les virus et menaces » > Gérer les paramètres."),
            C("Set-MpPreference -DisableRealtimeMonitoring $false", "ps_admin", "Active la protection en temps réel."),
        ],
    },
    "AV-003": {
        "windows": [
            V("Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated,AntivirusSignatureAge", "ps",
              "Affiche la date et l'âge (en jours) des signatures.", "âge de 0 ou 1 jour"),
            C("Update-MpSignature", "ps_admin", "Télécharge les dernières signatures antivirus."),
        ],
        "linux": [C("sudo systemctl restart clamav-freshclam", "terminal", "Relance la mise à jour des signatures ClamAV.")],
        "macos": [O('open "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"', "terminal",
                    "Ouvre Mise à jour de logiciels : activez « Installer les réponses de sécurité et les fichiers système ».")],
    },
    # ------------------------------------------------------------------ chiffrement
    "ENC-001": {
        "windows": [
            V("manage-bde -status C:", "cmd_admin", "Affiche l'état de BitLocker sur le disque C:.", "Statut de la protection : Protection activée"),
            O("control /name Microsoft.BitLockerDriveEncryption", "cmd", "Ouvre « Gérer BitLocker » (méthode recommandée : l'assistant guide chaque étape)."),
            C("manage-bde -on C: -RecoveryPassword", "cmd_admin", "Crée une clé de récupération et lance le chiffrement de C: (l'ordinateur reste utilisable).",
              attention="AVANT : notez la clé de récupération affichée (48 chiffres) et gardez-la hors de ce PC (papier, photo, compte Microsoft). "
                        "Sans elle, vos données peuvent être perdues. Windows Famille : BitLocker n'existe pas, utilisez « Chiffrement de l'appareil » dans Paramètres."),
        ],
        "linux": [V("lsblk -f", "terminal", "Affiche les disques et leur chiffrement.", "« crypto_LUKS » sous le disque qui contient « / »")],
        "macos": [
            V("fdesetup status", "terminal", "Affiche l'état de FileVault.", "FileVault is On."),
            O('open "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension"', "terminal", "Ouvre Confidentialité et sécurité, section FileVault (méthode recommandée)."),
            C("sudo fdesetup enable", "terminal", "Active FileVault et affiche la clé de secours.",
              attention="Notez la clé de secours affichée et gardez-la hors de ce Mac."),
        ],
    },
    "ENC-002": {
        "windows": [
            V("manage-bde -status", "cmd_admin", "Affiche l'état de BitLocker pour chaque disque.", "Protection activée pour chaque disque"),
            C("manage-bde -on LETTRE: -RecoveryPassword", "cmd_admin", "Lance le chiffrement de ce disque.",
              {"LETTRE": "la lettre du disque indiquée dans le constat (ex. D)"},
              "Notez la clé de récupération affichée et gardez-la hors de ce PC."),
        ],
    },
    # ------------------------------------------------------------------ logiciels
    "APP-001": {
        "windows": [
            V('winget list --name "NOM_DU_LOGICIEL"', "cmd", "Vérifie que le logiciel est installé et affiche sa version.", "la version actuelle, ou rien s'il est désinstallé",
              {"NOM_DU_LOGICIEL": "le nom du logiciel indiqué dans le constat (ex. Visual C++ 2010)"}),
            O("start ms-settings:appsfeatures", "cmd", "Ouvre la liste des applications installées (Désinstaller ou Modifier)."),
            C('winget upgrade --name "NOM_DU_LOGICIEL"', "cmd", "Installe la dernière version du logiciel.", {"NOM_DU_LOGICIEL": "le nom du logiciel indiqué dans le constat"}),
            C('winget uninstall --name "NOM_DU_LOGICIEL"', "cmd", "Désinstalle le logiciel, si vous ne l'utilisez plus.",
              {"NOM_DU_LOGICIEL": "le nom du logiciel indiqué dans le constat"},
              "Vérifiez avant qu'aucun programme n'en a besoin (les composants Visual C++ servent parfois à d'autres logiciels)."),
        ],
        "linux": [
            V("apt list --installed 2>/dev/null | grep NOM", "terminal", "Affiche le paquet et sa version.", remplacer={"NOM": "le nom du paquet indiqué dans le constat"}),
            C("sudo apt update && sudo apt upgrade", "terminal", "Met à jour les paquets vers la dernière version fournie par la distribution."),
            C("sudo apt remove NOM", "terminal", "Désinstalle le paquet s'il n'est plus utilisé.", {"NOM": "le nom du paquet indiqué dans le constat"}),
        ],
        "macos": [
            O('open -a "App Store"', "terminal", "Ouvre l'App Store, onglet Mises à jour."),
            C("brew upgrade", "terminal", "Met à jour les logiciels installés avec Homebrew."),
        ],
    },
    "APP-002": {
        "windows": [
            V("winget upgrade", "cmd", "Liste les logiciels qui ont une mise à jour disponible.", "« Aucune mise à jour disponible »"),
            C('winget upgrade --name "NOM_DU_LOGICIEL"', "cmd", "Met à jour ce logiciel.", {"NOM_DU_LOGICIEL": "le nom du logiciel indiqué dans le constat"}),
            C("winget upgrade --all", "cmd", "Met à jour tous les logiciels de la liste.", attention="Fermez les logiciels concernés avant."),
        ],
        "linux": [
            C("sudo apt update && sudo apt upgrade", "terminal", "Met à jour les paquets."),
            C("flatpak update", "terminal", "Met à jour les applications Flatpak."),
            C("sudo snap refresh", "terminal", "Met à jour les applications Snap."),
        ],
        "macos": [C("brew upgrade", "terminal", "Met à jour les logiciels Homebrew ; pour les autres : App Store > Mises à jour.")],
    },
    "APP-003": {
        "windows": [
            V('winget list --name "NOM"', "cmd", "Liste toutes les versions installées avec leur identifiant (colonne ID).", remplacer={"NOM": "le nom commun (ex. Python, Java)"}),
            O("start ms-settings:appsfeatures", "cmd", "Ouvre la liste des applications pour désinstaller l'ancienne version."),
            C("winget uninstall --id IDENTIFIANT", "cmd", "Désinstalle la version choisie.",
              {"IDENTIFIANT": "le contenu de la colonne ID de la version à retirer"}, "Gardez la version qu'utilisent vos projets."),
        ],
        "linux": [
            V("apt list --installed 2>/dev/null | grep NOM", "terminal", "Liste les versions installées.", remplacer={"NOM": "le nom commun (ex. python3, openjdk)"}),
            C("sudo apt remove PAQUET", "terminal", "Désinstalle la version choisie.", {"PAQUET": "le nom exact du paquet à retirer"}),
            C("sudo apt autoremove", "terminal", "Supprime les dépendances devenues inutiles."),
        ],
        "macos": [
            V("brew list --versions", "terminal", "Liste les logiciels Homebrew et leurs versions."),
            C("brew cleanup", "terminal", "Supprime les anciennes versions gardées par Homebrew."),
        ],
    },
    "APP-004": {
        "windows": [O("start ms-settings:appsfeatures", "cmd", "Ouvre la liste des applications : triez par taille et désinstallez celles qui ne servent plus.")],
        "macos": [O("open /Applications", "terminal", "Ouvre le dossier Applications (glisser une application dans la Corbeille la désinstalle).")],
    },
    # ------------------------------------------------------------------ performance
    "PERF-001": {
        "windows": [
            O("taskmgr", "cmd", "Ouvre le Gestionnaire des tâches : cliquez sur la colonne « Processeur » pour trier."),
            V("Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,CPU", "ps", "Liste les 10 programmes qui ont le plus utilisé le processeur."),
        ],
    },
    "PERF-002": {
        "windows": [V("Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity,Speed,DeviceLocator", "ps",
                      "Affiche chaque barrette de mémoire (taille en octets, vitesse, emplacement).", "au moins 8 Go au total")],
    },
    "PERF-003": {
        "windows": [
            O("taskmgr", "cmd", "Ouvre le Gestionnaire des tâches : triez par « Mémoire » et fermez ce qui ne sert pas."),
            V("Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 Name,@{n='Mo';e={[int]($_.WorkingSet64/1MB)}}", "ps",
              "Liste les 10 programmes qui utilisent le plus de mémoire."),
        ],
    },
    "PERF-004": {
        "windows": [
            O("start ms-settings:startupapps", "cmd", "Ouvre Paramètres > Applications > Démarrage : un interrupteur par programme."),
            O("taskmgr /0 /startup", "cmd", "Ouvre directement l'onglet « Démarrage » du Gestionnaire des tâches."),
            V("Get-CimInstance Win32_StartupCommand | Select-Object Name,Command", "ps", "Liste les programmes lancés au démarrage."),
        ],
        "linux": [V("ls ~/.config/autostart", "terminal", "Liste les applications lancées à l'ouverture de session.")],
        "macos": [O('open "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"', "terminal", "Ouvre Ouverture et éléments de connexion.")],
    },
    "PERF-005": {
        "windows": [
            V("Get-Process -Name NOM | Measure-Object WorkingSet64 -Sum", "ps", "Affiche la mémoire totale utilisée par cette application (Sum, en octets).",
              remplacer={"NOM": "le nom de l'application sans « .exe » (ex. Code, chrome)"}),
            O("taskmgr", "cmd", "Ouvre le Gestionnaire des tâches pour fermer l'application ou la redémarrer."),
        ],
    },
    "PERF-006": {
        "windows": [C("shutdown /r /t 0", "cmd", "Redémarre l'ordinateur.", attention=REBOOT)],
        "linux": [
            V("cat /var/run/reboot-required", "terminal", "Indique si un redémarrage est demandé par les mises à jour.", "« No such file » = pas de redémarrage en attente"),
            C("sudo reboot", "terminal", "Redémarre l'ordinateur.", attention=REBOOT),
        ],
        "macos": [C("sudo shutdown -r now", "terminal", "Redémarre le Mac.", attention=REBOOT)],
    },
    "PERF-007": {
        "windows": [V("Get-PhysicalDisk | Select-Object FriendlyName,MediaType", "ps", "Indique si chaque disque est un SSD ou un HDD.", "SSD")],
    },
    # ------------------------------------------------------------------ stockage
    "STO-001": {
        "windows": [
            O("start ms-settings:storagesense", "cmd", "Ouvre Paramètres > Stockage : « Recommandations de nettoyage » et Assistant Stockage."),
            C("cleanmgr /d C:", "cmd", "Ouvre le Nettoyage de disque : cochez ce que vous voulez supprimer (fichiers temporaires, Corbeille…).",
              attention="Cliquez aussi sur « Nettoyer les fichiers système » pour libérer davantage."),
        ],
        "linux": [
            V("df -h /", "terminal", "Affiche l'espace libre du disque.", "plus de 20 % libres"),
            C("sudo apt autoremove && sudo apt clean", "terminal", "Supprime les paquets inutiles et ceux déjà installés gardés en cache."),
            C("sudo journalctl --vacuum-size=200M", "terminal", "Réduit les journaux système à 200 Mo."),
        ],
        "macos": [
            V("df -h /", "terminal", "Affiche l'espace libre du disque.", "plus de 20 % libres"),
            O('open "x-apple.systempreferences:com.apple.settings.Storage"', "terminal", "Ouvre Réglages > Général > Stockage et ses recommandations."),
        ],
    },
    "STO-002": {
        "windows": [
            V("Get-FileHash -Algorithm SHA256 'CHEMIN1','CHEMIN2'", "ps", "Calcule l'empreinte de deux fichiers pour confirmer qu'ils sont identiques.",
              "deux « Hash » identiques = même contenu",
              {"CHEMIN1": "le chemin complet du 1er fichier (clic droit sur le fichier > Copier en tant que chemin d'accès)",
               "CHEMIN2": "le chemin complet du 2e fichier"}),
            O("explorer", "cmd", "Ouvre l'Explorateur : supprimez les copies (✗ dans la liste du site) et gardez l'original (✓)."),
        ],
        "linux": [V("sha256sum \"CHEMIN1\" \"CHEMIN2\"", "terminal", "Calcule l'empreinte de deux fichiers.", "deux empreintes identiques",
                    {"CHEMIN1": "le chemin du 1er fichier", "CHEMIN2": "le chemin du 2e fichier"})],
        "macos": [V("shasum -a 256 \"CHEMIN1\" \"CHEMIN2\"", "terminal", "Calcule l'empreinte de deux fichiers.", "deux empreintes identiques",
                    {"CHEMIN1": "le chemin du 1er fichier", "CHEMIN2": "le chemin du 2e fichier"})],
    },
    "STO-003": {
        "windows": [
            V("Get-ChildItem $env:USERPROFILE -File -Recurse -ErrorAction SilentlyContinue | Where-Object Length -gt 1GB | Select-Object FullName,@{n='Go';e={[math]::Round($_.Length/1GB,1)}}",
              "ps", "Liste les fichiers de plus de 1 Go de votre profil (peut prendre une minute)."),
            O("explorer", "cmd", "Ouvre l'Explorateur pour déplacer ces fichiers vers un disque externe ou les supprimer."),
        ],
        "linux": [V("find ~ -type f -size +1G -exec ls -lh {} \\; 2>/dev/null", "terminal", "Liste les fichiers de plus de 1 Go de votre dossier personnel.")],
        "macos": [V("find ~ -type f -size +1G -exec ls -lh {} \\; 2>/dev/null", "terminal", "Liste les fichiers de plus de 1 Go de votre dossier personnel.")],
    },
    "STO-004": {
        "windows": [O("explorer shell:Downloads", "cmd", "Ouvre le dossier Téléchargements : triez par taille et supprimez les installateurs déjà utilisés.")],
    },
    "STO-005": {
        "windows": [V("Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus", "ps", "Affiche l'état de santé de chaque disque.", "Healthy et OK")],
        "linux": [V("sudo smartctl -H /dev/sda", "terminal", "Affiche le bilan de santé SMART du disque.", "PASSED", {"sda": "le nom du disque (voir la commande lsblk)"})],
        "macos": [V("diskutil info / | grep SMART", "terminal", "Affiche l'état SMART du disque de démarrage.", "Verified")],
    },
    "STO-006": {
        "windows": [
            O("start ms-settings:storagesense", "cmd", "Ouvre Paramètres > Stockage > Fichiers temporaires : cochez les éléments puis « Supprimer les fichiers »."),
            C("cleanmgr /d C:", "cmd", "Ouvre le Nettoyage de disque (fichiers temporaires, miniatures, rapports d'erreurs, anciennes mises à jour).",
              attention="Cliquez sur « Nettoyer les fichiers système » pour inclure les anciennes mises à jour de Windows."),
            C('Remove-Item "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue', "ps",
              "Vide le dossier des fichiers temporaires de votre compte (les fichiers en cours d'utilisation sont ignorés).",
              attention="Fermez vos programmes avant."),
            C("Clear-RecycleBin -Force", "ps", "Vide la Corbeille.", attention="Les fichiers de la Corbeille seront supprimés définitivement."),
        ],
        "linux": [
            V("du -sh ~/.cache ~/.local/share/Trash 2>/dev/null", "terminal", "Affiche la taille du cache et de la corbeille."),
            C("rm -rf ~/.cache/*", "terminal", "Vide le cache des applications (il se reconstitue tout seul).", attention="Fermez vos applications avant."),
            C("gio trash --empty", "terminal", "Vide la corbeille.", attention="Les fichiers de la corbeille seront supprimés définitivement."),
            C("sudo apt clean", "terminal", "Supprime les paquets déjà installés gardés en cache."),
        ],
        "macos": [
            V("du -sh ~/Library/Caches ~/.Trash", "terminal", "Affiche la taille des caches et de la corbeille."),
            C("rm -rf ~/Library/Caches/*", "terminal", "Vide les caches des applications (ils se reconstituent).", attention="Quittez vos applications avant."),
            C("osascript -e 'tell application \"Finder\" to empty trash'", "terminal", "Vide la corbeille.", attention="Suppression définitive."),
        ],
    },
    # ------------------------------------------------------------------ Linux / macOS
    "LNX-001": {
        "linux": [
            V("awk -F: '$3 == 0 {print $1}' /etc/passwd", "terminal", "Liste les comptes qui ont les pleins pouvoirs (UID 0).", "seulement « root »"),
            C("sudo usermod -L NOM", "terminal", "Verrouille ce compte immédiatement.", {"NOM": "le nom du compte indiqué dans le constat"},
              "Analysez ensuite le système : ce compte peut être une porte dérobée."),
        ],
    },
    "LNX-002": {
        "linux": [
            V("sudo sshd -T | grep -i permitrootlogin", "terminal", "Affiche si root peut se connecter en SSH.", "permitrootlogin no (ou prohibit-password)"),
            C("sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config", "terminal", "Interdit la connexion directe de root en SSH."),
            C("sudo systemctl restart ssh || sudo systemctl restart sshd", "terminal", "Redémarre SSH pour appliquer le changement.",
              attention="Vérifiez qu'un autre compte avec sudo peut se connecter avant de fermer votre session."),
        ],
    },
    "LNX-003": {
        "linux": [
            V("sudo sshd -T | grep -i passwordauthentication", "terminal", "Indique si les mots de passe sont acceptés en SSH.", "passwordauthentication no"),
            C("ssh-keygen -t ed25519", "terminal", "À lancer sur l'ordinateur qui se connecte : crée une paire de clés (appuyez sur Entrée pour les valeurs par défaut)."),
            C("ssh-copy-id utilisateur@serveur", "terminal", "Copie votre clé sur ce PC.", {"utilisateur@serveur": "votre compte et l'adresse de ce PC"}),
            C("sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config", "terminal",
              "Désactive la connexion SSH par mot de passe.",
              attention="Testez la connexion par clé AVANT, sinon vous pourriez perdre l'accès à distance."),
            C("sudo systemctl restart ssh || sudo systemctl restart sshd", "terminal", "Redémarre SSH pour appliquer le changement."),
        ],
    },
    "LNX-004": {
        "linux": [
            V("sudo aa-status", "terminal", "Affiche l'état d'AppArmor (Ubuntu, Debian).", "apparmor module is loaded"),
            V("getenforce", "terminal", "Affiche l'état de SELinux (Fedora, RHEL).", "Enforcing"),
            C("sudo systemctl enable --now apparmor", "terminal", "Active AppArmor."),
            C("sudo setenforce 1", "terminal", "Passe SELinux en mode « Enforcing » jusqu'au prochain redémarrage (pour le rendre permanent : /etc/selinux/config)."),
        ],
    },
    "MAC-001": {
        "macos": [
            V("spctl --status", "terminal", "Indique si Gatekeeper est actif.", "assessments enabled"),
            C("sudo spctl --master-enable", "terminal", "Réactive Gatekeeper."),
        ],
    },
    "MAC-002": {
        "macos": [
            V("csrutil status", "terminal", "Indique si la protection de l'intégrité du système (SIP) est active.", "System Integrity Protection status: enabled."),
            C("csrutil enable", "terminal", "Réactive SIP : à taper dans le Terminal du MODE DE RÉCUPÉRATION, puis redémarrer.",
              attention="Ne fonctionne pas dans une session normale : démarrez d'abord en mode de récupération."),
        ],
    },
    "MAC-003": {
        "macos": [
            V("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled", "terminal", "Indique si la recherche automatique est active.", "1"),
            O('open "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"', "terminal", "Ouvre Mise à jour de logiciels > Mises à jour automatiques."),
            C("sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true", "terminal", "Active la recherche automatique des mises à jour."),
            C("sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true", "terminal", "Active l'installation automatique des correctifs de sécurité."),
        ],
    },
    "MAC-004": {
        "macos": [
            V("defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser", "terminal", "Indique le compte ouvert automatiquement.", "« does not exist » = désactivé"),
            C("sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser", "terminal", "Désactive l'ouverture de session automatique."),
        ],
    },
    "MAC-005": {
        "macos": [
            V("/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode", "terminal", "Indique si le mode furtif est actif.", "Stealth mode enabled"),
            C("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on", "terminal", "Active le mode furtif."),
        ],
    },
    # ------------------------------------------------------------------ Wi-Fi et matériel
    "WIFI-001": {
        "windows": [
            V("netsh wlan show interfaces", "cmd", "Affiche le réseau Wi-Fi connecté et sa protection (ligne « Authentification »).", "WPA2 ou WPA3"),
            C("netsh wlan disconnect", "cmd", "Se déconnecte du réseau Wi-Fi actuel."),
        ],
        "linux": [
            V("nmcli -f IN-USE,SSID,SECURITY dev wifi", "terminal", "Affiche le réseau connecté (*) et sa protection.", "WPA2 ou WPA3"),
            C("nmcli dev disconnect wlan0", "terminal", "Se déconnecte du Wi-Fi.", {"wlan0": "le nom de l'interface Wi-Fi (voir « nmcli dev »)"}),
        ],
        "macos": [
            V("networksetup -getairportnetwork en0", "terminal", "Affiche le réseau Wi-Fi connecté."),
            C("networksetup -setairportpower en0 off", "terminal", "Coupe le Wi-Fi."),
        ],
    },
    "WIFI-002": {
        "windows": [V("netsh wlan show interfaces", "cmd", "Affiche la protection du réseau connecté (lignes « Authentification » et « Chiffrement »).", "WPA2-Personnel et CCMP, ou WPA3")],
        "linux": [V("nmcli -f IN-USE,SSID,SECURITY dev wifi", "terminal", "Affiche la protection du réseau connecté.", "WPA2 ou WPA3")],
    },
    "WIFI-003": {
        "windows": [
            V("netsh wlan show profiles", "cmd", "Liste les réseaux Wi-Fi mémorisés."),
            C('netsh wlan delete profile name="NOM"', "cmd", "Oublie ce réseau Wi-Fi.", {"NOM": "le nom du réseau indiqué dans le constat"}),
        ],
        "linux": [C('nmcli con delete "NOM"', "terminal", "Oublie ce réseau Wi-Fi.", {"NOM": "le nom du réseau indiqué dans le constat"})],
        "macos": [C('sudo networksetup -removepreferredwirelessnetwork en0 "NOM"', "terminal", "Oublie ce réseau Wi-Fi.", {"NOM": "le nom du réseau indiqué dans le constat"})],
    },
    "HW-001": {
        "windows": [V("powercfg /batteryreport", "cmd",
                      "Crée le fichier battery-report.html dans le dossier affiché : ouvrez-le et comparez DESIGN CAPACITY (origine) et FULL CHARGE CAPACITY (actuelle).",
                      "une capacité actuelle supérieure à 80 % de l'origine")],
        "linux": [V("upower -i $(upower -e | grep BAT)", "terminal", "Affiche l'état de la batterie (ligne « capacity »).", "capacity supérieure à 80 %")],
        "macos": [V("system_profiler SPPowerDataType | grep -E 'Cycle Count|Condition|Maximum Capacity'", "terminal", "Affiche l'état de la batterie.", "Condition: Normal")],
    },
    "HW-002": {
        "linux": [V("sensors", "terminal", "Affiche les températures (paquet lm-sensors).", "moins de 80 °C au repos"),
                  O("top", "terminal", "Affiche les programmes qui utilisent le plus le processeur (touche q pour quitter).")],
    },
}

STO_006 = {
    "domain": "stockage", "category": "Disque", "severity": "faible",
    "title": "Espace récupérable sans risque",
    "description": "Fichiers temporaires, caches des navigateurs, Corbeille, anciens installateurs et mises à jour déjà installées occupent de l'espace inutilement.",
    "danger": "Aucun danger de sécurité. Ces fichiers sont recréés au besoin par le système ou les applications : les supprimer ne fait rien perdre d'important.",
    "impact": "Espace disque gaspillé ; un disque trop plein ralentit l'ordinateur et peut bloquer les mises à jour.",
    "location": "Paramètres > Système > Stockage > Fichiers temporaires",
    "remediation": {"steps": ["Ouvrez Paramètres > Système > Stockage > Fichiers temporaires.",
                              "Cochez « Fichiers temporaires », « Corbeille », « Miniatures » et « Nettoyage de Windows Update ».",
                              "Cliquez sur « Supprimer les fichiers ».",
                              "Dans votre navigateur : Paramètres > Confidentialité > Effacer les données de navigation > Images et fichiers en cache."],
                    "commands": {}, "duration": "5 minutes", "requires_admin": False},
    "location_linux": "~/.cache, corbeille, /var/cache/apt",
    "remediation_linux": {"steps": ["Videz la corbeille.", "Supprimez le contenu de ~/.cache (les applications le recréent).", "Nettoyez le cache des paquets."],
                          "commands": {}, "duration": "5 minutes", "requires_admin": False},
    "location_macos": "~/Library/Caches, Corbeille",
    "remediation_macos": {"steps": ["Videz la corbeille.", "Quittez vos applications puis videz ~/Library/Caches.", "Réglages > Général > Stockage : suivez les recommandations."],
                          "commands": {}, "duration": "5 minutes", "requires_admin": False},
    "references": [],
}


def apply(kb_path: Path, systems: tuple[str, ...]) -> int:
    kb = json.loads(kb_path.read_text(encoding="utf-8"))
    kb.setdefault("STO-006", STO_006)
    if "linux" not in systems:  # Livrable 1 : variantes Linux/macOS inutiles
        for k in [k for k in kb["STO-006"] if k.endswith(("_linux", "_macos"))]:
            del kb["STO-006"][k]
    count = 0
    for rule, per_os in CATALOGUE.items():
        if rule not in kb:
            continue
        entry = kb[rule]
        for os_, cmds in per_os.items():
            if os_ not in systems:
                continue
            target = entry.get(f"remediation_{os_}") or entry.setdefault("remediation", {"steps": [], "commands": {}})
            # Ne garder que les commandes du système concerné dans chaque bloc de remédiation
            target.setdefault("commands", {})[os_] = cmds
            count += len(cmds)
        # Les étapes « relancer un scan » deviennent l'étape 3 « Contrôler », affichée par le site
        for key in [k for k in entry if k.startswith("remediation")]:
            entry[key]["steps"] = [s for s in entry[key].get("steps", []) if "scan KMB" not in s and "Relancer un scan" not in s]
    kb_path.write_text(json.dumps(kb, ensure_ascii=False, indent=2), encoding="utf-8")
    return count


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    systems = tuple(sys.argv[1:]) or ("windows", "linux", "macos")
    n = apply(root / "kmb_library" / "rules" / "knowledge_base.json", systems)
    print(f"{n} commandes décrites ({', '.join(systems)})")
