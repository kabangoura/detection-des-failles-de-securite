"""Règles de sécurité : système, comptes, réseau, pare-feu, antivirus, chiffrement (Windows, Linux, macOS)."""

from __future__ import annotations

from kmb_library.core.models import Finding
from kmb_library.core.utils import days_since
from kmb_library.rules.engine import RawView, make

SENSITIVE_PORTS = {
    21: ("FTP", "eleve"), 22: ("SSH", "moyen"), 23: ("Telnet", "critique"), 2375: ("API Docker non chiffrée", "critique"),
    3389: ("Bureau à distance", "eleve"), 5800: ("VNC", "eleve"), 5900: ("VNC / partage d'écran", "eleve"),
    5985: ("WinRM", "eleve"), 5986: ("WinRM", "moyen"), 1433: ("SQL Server", "eleve"),
    3306: ("MySQL/MariaDB", "eleve"), 5432: ("PostgreSQL", "eleve"), 27017: ("MongoDB", "critique"),
    6379: ("Redis", "critique"), 9200: ("Elasticsearch", "critique"), 11211: ("Memcached", "eleve"),
}
HOTFIX_MAX_DAYS = 45
SIGNATURE_MAX_DAYS = 7


# --------------------------------------------------------------------------- système

def _system(v: RawView, enr: dict) -> list[Finding]:
    out: list[Finding] = []
    s = v.data("system")
    os_info = s.get("os") or {}
    life = enr.get("os_lifecycle") or {}
    if v.os == "windows":
        name = f"{os_info.get('caption', 'Windows')} {os_info.get('display_version') or ''} (build {os_info.get('build')}.{os_info.get('ubr')})"
    else:
        name = os_info.get("caption") or v.os
    if life.get("status") == "fin_de_support":
        out.append(make("SYS-001", "detecte", f"{name} : fin de support le {life.get('eol')} (cycle {life.get('label')}, source endoflife.date)",
                        details=life))
    elif life.get("status") in ("supporte", "maj_disponible"):
        eol = life.get("eol")
        out.append(make("SYS-001", "conforme", f"{name} : supporté" + (f" jusqu'au {eol}" if isinstance(eol, str) else ""), details=life))
        if (life.get("days_to_eol") or 9999) < 183:
            out.append(make("SYS-002", "detecte", f"Fin de support dans {life['days_to_eol']} jours ({eol})"))
    else:
        out.append(make("SYS-001", "non_verifiable", f"Cycle de vie introuvable pour {name}" + (f" ({life['reason']})" if life.get("reason") else "")))

    pending = s.get("pending_updates")
    if pending is None:
        reason = "Recherche des mises à jour désactivée (--sans-maj)" if s.get("pending_updates_skipped") else v.reason("system", "windows_update" if v.os == "windows" else "updates")
        out.append(make("SYS-003", "non_verifiable", reason))
    elif pending:
        important = [u for u in pending if u.get("security") or str(u.get("severity")) in ("Critical", "Important")
                     or "secur" in str(u.get("categories", "")).lower() or "sécur" in str(u.get("categories", "")).lower()]
        titles = "; ".join(u["title"] for u in pending[:5] if u.get("title"))
        source = {"windows": "Windows Update", "linux": f"le gestionnaire de paquets ({s.get('package_manager')})", "macos": "softwareupdate"}[v.os]
        out.append(make("SYS-003", "detecte", f"{len(pending)} mise(s) à jour en attente selon {source}"
                        + (f", dont {len(important)} de sécurité" if important else "") + f" : {titles}",
                        severity="eleve" if important else "moyen", details={"updates": pending[:50]}))
    else:
        out.append(make("SYS-003", "conforme", "Aucune mise à jour en attente"))

    if v.os == "windows":
        hf = s.get("hotfixes")
        if hf and hf.get("latest_date"):
            age = days_since(hf["latest_date"], v.now)
            out.append(make("SYS-004", "detecte" if age is not None and age > HOTFIX_MAX_DAYS else "conforme",
                            f"Dernier correctif installé le {hf['latest_date']} (il y a {age} jours), {hf['count']} correctifs au total"))
        else:
            out.append(make("SYS-004", "non_verifiable", v.reason("system", "hotfixes")))
    elif v.os == "linux" and s.get("last_update_date"):
        age = days_since(s["last_update_date"], v.now)
        out.append(make("SYS-004", "detecte" if age is not None and age > HOTFIX_MAX_DAYS else "conforme",
                        f"Dernière installation de paquets le {s['last_update_date']} (il y a {age} jours)"))

    if v.os == "windows":
        uac = s.get("uac")
        if uac is None:
            out.append(make("SYS-005", "non_verifiable", v.reason("system", "uac")))
        elif uac.get("enable_lua") == 0:
            out.append(make("SYS-005", "detecte", "EnableLUA = 0"))
        else:
            out.append(make("SYS-005", "conforme", f"EnableLUA = {uac.get('enable_lua')}"))
            if uac.get("consent_prompt_admin") == 0:
                out.append(make("SYS-006", "detecte", "ConsentPromptBehaviorAdmin = 0 (élévation sans confirmation)"))

    if v.os in ("windows", "linux"):
        if s.get("firmware") == "BIOS":
            out.append(make("SYS-007", "detecte", "Démarrage en mode BIOS hérité (Legacy) : Secure Boot ne peut pas fonctionner"))
        elif s.get("secure_boot") is False:
            out.append(make("SYS-007", "detecte", f"Micrologiciel {s.get('firmware') or 'UEFI'}, Secure Boot désactivé"))
        elif s.get("secure_boot") is True:
            out.append(make("SYS-007", "conforme", "Secure Boot actif"))
        else:
            out.append(make("SYS-007", "non_verifiable", v.reason("system", "secure_boot")))

    if v.os == "linux":
        mf = s.get("mac_framework") or {}
        if mf.get("selinux") is None and mf.get("apparmor") is None:
            out.append(make("LNX-004", "non_verifiable", v.reason("system", "mac_framework", "Ni SELinux ni AppArmor détectés")))
        elif mf.get("selinux") == "enforcing" or mf.get("apparmor"):
            out.append(make("LNX-004", "conforme", f"SELinux : {mf.get('selinux') or 'absent'} ; AppArmor : {'actif' if mf.get('apparmor') else 'inactif'}"))
        else:
            out.append(make("LNX-004", "detecte", f"SELinux : {mf.get('selinux') or 'absent'} ; AppArmor : {'actif' if mf.get('apparmor') else 'inactif'}"))

    if v.os == "macos":
        for rule, key, label in (("MAC-001", "gatekeeper", "Gatekeeper"), ("MAC-002", "sip", "SIP")):
            val = s.get(key)
            if val is None:
                out.append(make(rule, "non_verifiable", v.reason("system", key)))
            else:
                out.append(make(rule, "conforme" if val else "detecte", f"{label} {'activé' if val else 'désactivé'}"))
        au = s.get("auto_update")
        if au is None:
            out.append(make("MAC-003", "non_verifiable", v.reason("system", "auto_update")))
        else:
            off = [k for k in ("automatic_check", "critical_updates") if not au.get(k)]
            out.append(make("MAC-003", "detecte" if off else "conforme",
                            "Désactivé : " + ", ".join(off) if off else "Recherche automatique et réponses de sécurité activées"))
    return out


# --------------------------------------------------------------------------- comptes

def _admins(v: RawView, a: dict, users: list[dict] | None, by_sid: bool) -> list[Finding]:
    out = []
    admins = a.get("administrators")
    if admins is None:
        reason = v.reason("accounts", "admin_group")
        out.append(make("ACC-001", "non_verifiable", reason))
        if v.os != "linux":
            out.append(make("ACC-005", "non_verifiable", reason))
        return out
    if by_sid and users is not None:
        index = {u.get("sid"): u for u in users}
        active = [m for m in admins if index.get(m.get("sid"), {"enabled": True})["enabled"]]
    else:
        active = admins
    names = ", ".join(m["name"] for m in active) or "aucun"
    out.append(make("ACC-001", "detecte" if len(active) > 2 else "conforme", f"{len(active)} administrateur(s) actif(s) : {names}"))
    if v.os != "linux":  # sous Linux, appartenir à sudo avec mot de passe est l'usage normal
        current = next((m for m in admins if m.get("is_current_user")), None)
        out.append(make("ACC-005", "detecte" if current else "conforme",
                        f"Le compte courant « {a.get('current_user')} » est administrateur" if current
                        else f"Le compte courant « {a.get('current_user')} » est un utilisateur standard"))
    return out


def _accounts(v: RawView) -> list[Finding]:
    a = v.data("accounts")
    users = a.get("local_users")
    if v.os == "windows":
        if users is None:
            reason = v.reason("accounts", "local_users")
            return [make(r, "non_verifiable", reason) for r in ("ACC-002", "ACC-003", "ACC-004")] + _admins(v, a, None, True)
        out: list[Finding] = []
        guest = next((u for u in users if str(u.get("sid", "")).endswith("-501")), None)
        out.append(make("ACC-002", "detecte" if guest and guest["enabled"] else "conforme",
                        f"Compte « {guest['name']} » {'activé' if guest['enabled'] else 'désactivé'}" if guest else "Compte Invité absent"))
        builtin = next((u for u in users if str(u.get("sid", "")).endswith("-500")), None)
        out.append(make("ACC-003", "detecte" if builtin and builtin["enabled"] else "conforme",
                        f"Compte « {builtin['name']} » {'activé' if builtin['enabled'] else 'désactivé'}" if builtin else "Compte intégré absent"))
        nopass = [u for u in users if u["enabled"] and u.get("password_required") is False and not str(u.get("sid", "")).endswith("-501")]
        for u in nopass:
            out.append(make("ACC-004", "detecte", f"Compte « {u['name']} » : PasswordRequired = False", suffix=u["name"]))
        if not nopass:
            out.append(make("ACC-004", "conforme", "Tous les comptes actifs exigent un mot de passe"))
        return out + _admins(v, a, users, True)

    if v.os == "linux":
        out = []
        uid0 = a.get("uid0_accounts")
        if uid0 is not None:
            for name in uid0:
                out.append(make("LNX-001", "detecte", f"Compte « {name} » avec UID 0", suffix=name))
            if not uid0:
                out.append(make("LNX-001", "conforme", "Seul root possède l'UID 0"))
        if not a.get("shadow_readable"):
            out.append(make("ACC-004", "non_verifiable", v.reason("accounts", "shadow")))
        else:
            empty = [u for u in users or [] if u.get("password_required") is False]
            for u in empty:
                out.append(make("ACC-004", "detecte", f"Compte « {u['name']} » sans mot de passe", suffix=u["name"]))
            if not empty:
                out.append(make("ACC-004", "conforme", "Aucun compte interactif sans mot de passe"))
        return out + _admins(v, a, users, False)

    # macOS
    out = [make("ACC-002", "detecte" if a.get("guest_enabled") else "conforme",
                f"Compte invité {'activé' if a.get('guest_enabled') else 'désactivé'}")]
    auto = a.get("autologin_user")
    out.append(make("MAC-004", "detecte" if auto else "conforme",
                    f"Session ouverte automatiquement pour « {auto} »" if auto else "Mot de passe demandé au démarrage"))
    return out + _admins(v, a, users, False)


# --------------------------------------------------------------------------- réseau

def _network(v: RawView) -> list[Finding]:
    out: list[Finding] = []
    n = v.data("network")

    if v.os == "windows":
        smb1 = n.get("smb1_enabled")
        if smb1 is None:
            out.append(make("NET-001", "non_verifiable", v.reason("network", "smb_config")))
        else:
            out.append(make("NET-001", "detecte" if smb1 else "conforme", f"EnableSMB1Protocol = {smb1}"))
        rdp = n.get("rdp")
        if rdp is None:
            out.append(make("NET-002", "non_verifiable", v.reason("network", "rdp")))
        else:
            out.append(make("NET-002", "detecte" if rdp["enabled"] else "conforme",
                            f"Bureau à distance {'activé' if rdp['enabled'] else 'désactivé'} (port {rdp.get('port')})"))
            if rdp["enabled"] and not rdp.get("nla"):
                out.append(make("NET-003", "detecte", "UserAuthentication = 0"))

    listening = n.get("listening")
    skip = {22, 5900} if v.os == "macos" else set()  # couverts par NET-006 (session à distance / partage d'écran)
    if listening is None:
        out.append(make("NET-004", "non_verifiable", v.reason("network", "listening_ports")))
    else:
        exposed = {}
        for p in listening:
            if p["exposed"] and p["port"] in SENSITIVE_PORTS and p["port"] not in skip:
                exposed.setdefault(p["port"], p)
        for port, p in sorted(exposed.items()):
            label, sev = SENSITIVE_PORTS[port]
            out.append(make("NET-004", "detecte",
                            f"Port {port} ({label}) en écoute sur {p['ip'] or 'toutes les interfaces'} par {p.get('process') or 'processus inconnu'} (PID {p.get('pid')})",
                            suffix=str(port), severity=sev, title=f"{label} accessible depuis le réseau (port {port})",
                            details={"port": port, "process": p.get("process"), "pid": p.get("pid")}))
        if not exposed:
            out.append(make("NET-004", "conforme", f"Aucun service sensible exposé ({len(listening)} ports en écoute analysés)"))

    if v.os == "linux":
        ssh = n.get("ssh") or {}
        if not ssh.get("installed") or not ssh.get("running"):
            out.append(make("LNX-002", "conforme", "Serveur SSH absent ou arrêté"))
        else:
            root = str(ssh.get("permit_root_login", "")).lower()
            out.append(make("LNX-002", "detecte" if root == "yes" else "conforme", f"PermitRootLogin {root}"))
            out.append(make("LNX-003", "detecte" if ssh.get("password_authentication") else "conforme",
                            f"PasswordAuthentication {'yes' if ssh.get('password_authentication') else 'no'} (port {ssh.get('port')})"))

    if v.os == "macos":
        ssh, sharing = n.get("ssh") or {}, n.get("sharing") or {}
        active = [label for label, on in (("session à distance (SSH)", ssh.get("running")), ("partage d'écran", sharing.get("screen_sharing")),
                                          ("partage de fichiers", sharing.get("file_sharing"))) if on]
        out.append(make("NET-006", "detecte" if active else "conforme",
                        "Actif : " + ", ".join(active) if active else "Aucun partage ni accès à distance actif"))

    shares = n.get("smb_shares")
    if shares is None:
        if v.os == "windows":
            out.append(make("NET-005", "non_verifiable", v.reason("network", "smb_shares")))
    else:
        custom = [s for s in shares if not s.get("administrative")]
        for s in custom:
            kind = {"nfs": "Export NFS", "smb": "Partage Samba"}.get(s.get("type"), "Partage")
            extra = f", accès invité autorisé" if s.get("guest_ok") else (f", clients : {s['clients']}" if s.get("clients") else "")
            out.append(make("NET-005", "detecte", f"{kind} « {s['name']} » -> {s.get('path')}{extra}", suffix=s["name"],
                            severity="eleve" if s.get("guest_ok") or s.get("clients") in ("*", "*(rw)") else None))
        if not custom:
            out.append(make("NET-005", "conforme", "Aucun dossier partagé sur le réseau"
                            + (f" (seulement {len(shares)} partages administratifs par défaut)" if shares else "")))
    return out


# --------------------------------------------------------------------------- pare-feu, antivirus, chiffrement

def _firewall(v: RawView) -> list[Finding]:
    out: list[Finding] = []
    fw = v.data("firewall")
    profiles = fw.get("profiles")
    if not profiles:
        return [make("FW-001", "non_verifiable", v.reason("firewall", "profiles"))]
    if v.os == "windows":
        off = [p for p in profiles if not p["enabled"]]
        for p in off:
            out.append(make("FW-001", "detecte", f"Profil {p['name']} : désactivé", suffix=p["name"]))
        if not off:
            out.append(make("FW-001", "conforme", "Profils " + ", ".join(p["name"] for p in profiles) + " activés"))
    else:
        active = [p for p in profiles if p["enabled"]]
        out.append(make("FW-001", "conforme" if active else "detecte",
                        ("Actif : " + ", ".join(p["name"] for p in active)) if active
                        else "Inactif : " + ", ".join(p["name"] for p in profiles)))
    allow = [p for p in profiles if p.get("enabled") and p.get("default_inbound") == "Allow"]
    for p in allow:
        out.append(make("FW-002", "detecte", f"{p['name']} : connexions entrantes autorisées par défaut", suffix=p["name"]))
    if not allow and any(p.get("default_inbound") for p in profiles):
        out.append(make("FW-002", "conforme", "Connexions entrantes bloquées par défaut"))
    if v.os == "windows":
        rules = fw.get("sensitive_inbound_rules")
        if rules is None:
            out.append(make("FW-003", "non_verifiable", v.reason("firewall", "sensitive_rules")))
        else:
            for r in rules:
                out.append(make("FW-003", "detecte", f"Règle « {r['name']} » (profil {r['profile']}) : ports {r['ports']}", suffix=r["name"]))
            if not rules:
                out.append(make("FW-003", "conforme", "Aucune règle entrante sensible sur le profil Public"))
    if v.os == "macos" and fw.get("stealth_mode") is not None:
        out.append(make("MAC-005", "conforme" if fw["stealth_mode"] else "detecte",
                        f"Mode furtif {'activé' if fw['stealth_mode'] else 'désactivé'}"))
    return out


def _antivirus(v: RawView) -> list[Finding]:
    out: list[Finding] = []
    av = v.data("antivirus")
    products, defender = av.get("products"), av.get("defender")
    if products is None and defender is None:
        return [make("AV-001", "non_verifiable", v.reason("antivirus", "security_center"))]
    active = [p for p in (products or []) if p.get("enabled")]
    if v.os == "windows":
        defender_on = bool(defender and defender.get("antivirus_enabled"))
        if not (active or defender_on):
            return [make("AV-001", "detecte", "Aucun produit antivirus actif déclaré au Centre de sécurité")]
        out.append(make("AV-001", "conforme", "Antivirus actif : " + (", ".join(p["name"] for p in active) or "Microsoft Defender")))
        third_party = [p for p in active if "defender" not in p["name"].lower()]
        if defender and not third_party:
            rt = defender.get("realtime_enabled")
            out.append(make("AV-002", "detecte" if rt is False else "conforme", f"RealTimeProtectionEnabled = {rt}"))
            age = defender.get("signature_age_days")
            if age is not None:
                out.append(make("AV-003", "detecte" if age > SIGNATURE_MAX_DAYS else "conforme",
                                f"Signatures âgées de {age} jour(s) (mises à jour le {str(defender.get('signature_updated'))[:10]})"))
        for p in third_party:
            if p.get("up_to_date") is False:
                out.append(make("AV-003", "detecte", f"{p['name']} signale des signatures périmées", suffix=p["name"]))
        return out

    installed = products or []
    if not installed:
        # Sous Linux le risque est moindre ; macOS intègre toujours XProtect (absence = anomalie)
        return [make("AV-001", "detecte", "Aucun antivirus détecté", severity="moyen" if v.os == "linux" else None)]
    names = ", ".join(f"{p['name']}{'' if p.get('enabled') else ' (service arrêté)'}" for p in installed)
    out.append(make("AV-001", "conforme" if active else "detecte", f"Détecté : {names}",
                    severity="faible" if not active else None))
    for p in installed:
        if p.get("up_to_date") is False:
            out.append(make("AV-003", "detecte", f"{p['name']} : signatures âgées de {p.get('signature_age_days')} jours", suffix=p["name"]))
        elif p.get("up_to_date"):
            out.append(make("AV-003", "conforme", f"{p['name']} : signatures âgées de {p.get('signature_age_days')} jour(s)", suffix=p["name"]))
    return out


def _encryption(v: RawView) -> list[Finding]:
    out: list[Finding] = []
    enc = v.data("encryption")
    vols = enc.get("volumes")
    if not vols:
        return [make("ENC-001", "non_verifiable", v.reason("encryption", "bitlocker_admin" if v.os == "windows" else
                                                           ("lsblk" if v.os == "linux" else "filevault")))]
    system = str(enc.get("system_drive", "C:")).upper()
    for vol in vols:
        drive = str(vol.get("drive", "")).upper().rstrip("\\") or "/"
        protected = vol["state"] in ("on", "in_progress")
        evidence = f"{'Lecteur' if v.os == 'windows' else 'Volume'} {vol.get('drive')} : {vol.get('label')} (méthode : {vol.get('method')})"
        if drive == system:
            out.append(make("ENC-001", "conforme" if protected else "detecte", evidence))
        elif not protected:
            out.append(make("ENC-002", "detecte", evidence, suffix=drive))
    return out


def evaluate(v: RawView, enr: dict) -> list[Finding]:
    return _system(v, enr) + _accounts(v) + _network(v) + _firewall(v) + _antivirus(v) + _encryption(v)
