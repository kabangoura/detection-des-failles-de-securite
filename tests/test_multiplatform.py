"""Analyseurs Linux / macOS / Wi-Fi / matériel testés sur des sorties de commandes représentatives,
puis traitement complet d'un scan Linux et d'un scan macOS simulés.

Ces tests s'exécutent sur n'importe quel système : ils ne lancent aucune commande.
"""

import json
from datetime import date
from pathlib import Path

from kmb_library.collectors import detect_os_family
from kmb_library.collectors.common import parse_lsof_listen
from kmb_library.collectors.hardware import parse_ioreg_battery, parse_powercfg_xml, parse_sys_battery
from kmb_library.collectors.linux import accounts as lx_acc
from kmb_library.collectors.linux import encryption as lx_enc
from kmb_library.collectors.linux import firewall as lx_fw
from kmb_library.collectors.linux import network as lx_net
from kmb_library.collectors.linux import performance as lx_perf
from kmb_library.collectors.linux import software as lx_sw
from kmb_library.collectors.linux import storage as lx_sto
from kmb_library.collectors.linux import system as lx_sys
from kmb_library.collectors.macos import accounts as mac_acc
from kmb_library.collectors.macos import encryption as mac_enc
from kmb_library.collectors.macos import firewall as mac_fw
from kmb_library.collectors.macos import network as mac_net
from kmb_library.collectors.macos import storage as mac_sto
from kmb_library.collectors.macos import system as mac_sys
from kmb_library.collectors.wifi import (classify, parse_airport_json, parse_netsh_interfaces, parse_netsh_profile,
                                         parse_netsh_profiles, parse_nmcli_wifi)
from kmb_library.core.context import ScanContext
from kmb_library.core.fswalk import parse_xdg_user_dirs
from kmb_library.core.runner import process
from kmb_library.enrich.endoflife import match_linux, match_macos, match_software

FIXTURES = Path(__file__).parent / "fixtures"


class FakeClient:
    def __init__(self, products):
        self.products = products

    def cycles(self, product):
        return self.products.get(product)


def test_detect_os_family():
    assert detect_os_family("win32") == "windows"
    assert detect_os_family("linux") == "linux"
    assert detect_os_family("darwin") == "macos"
    assert detect_os_family("freebsd13") == "unsupported"


# ------------------------------------------------------------------ Linux

def test_linux_os_release_and_updates():
    rel = lx_sys.parse_os_release('NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\n')
    assert rel["ID"] == "ubuntu" and rel["VERSION_ID"] == "22.04"
    apt = ("Listing... Done\n"
           "openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.14]\n"
           "vim/jammy-updates 2:8.2.3995-1ubuntu2.17 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.16]\n")
    ups = lx_sys.parse_apt_upgradable(apt)
    assert [u["security"] for u in ups] == [True, False]
    dnf = "\nopenssl.x86_64     1:3.0.7-27.el9     baseos\nkernel.x86_64   5.14.0-427.el9   baseos\n"
    assert [u["title"].split()[0] for u in lx_sys.parse_dnf_check_update(dnf)] == ["openssl", "kernel"]


def test_linux_accounts():
    passwd = ("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
              "alice:x:1000:1000:Alice:/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n")
    group = "sudo:x:27:alice\nwheel:x:10:\nalice:x:1000:\n"
    shadow = "root:!:19000::::::\nalice:$6$abc:19000::::::\nbob::19000::::::\n"
    a = lx_acc.analyse(passwd, group, shadow, "alice")
    assert a["uid0_accounts"] == ["backdoor"]
    assert [x["name"] for x in a["administrators"]] == ["alice"] and a["administrators"][0]["is_current_user"]
    bob = next(u for u in a["local_users"] if u["name"] == "bob")
    assert bob["password_required"] is False
    no_shadow = lx_acc.analyse(passwd, group, None, "alice")
    assert no_shadow["shadow_readable"] is False and no_shadow["local_users"][0]["password_required"] is None


def test_linux_sshd_and_shares():
    ssh = lx_net.parse_sshd_config(["PasswordAuthentication no\n", "#PermitRootLogin no\nPermitRootLogin yes\nPort 2222\nMatch User x\n  PasswordAuthentication yes\n"])
    assert ssh == {"permit_root_login": "yes", "password_authentication": False, "port": 2222}
    assert lx_net.parse_sshd_config([""])["permit_root_login"] == "prohibit-password"
    nfs = lx_net.parse_exports("# commentaire\n/srv/data  192.168.1.0/24(rw,sync)\n/home *(ro)\n")
    assert [s["path"] for s in nfs] == ["/srv/data", "/home"]
    smb = lx_net.parse_smb_conf("[global]\nworkgroup = W\n[public]\npath = /srv/public\nguest ok = yes\n[printers]\npath=/var\n")
    assert len(smb) == 1 and smb[0]["guest_ok"] and smb[0]["path"] == "/srv/public"
    assert lx_net.parse_resolv_conf("nameserver 127.0.0.53\noptions edns0\n") == ["127.0.0.53"]


def test_linux_firewall_parsers():
    assert lx_fw.parse_ufw_conf("ENABLED=yes\n", 'DEFAULT_INPUT_POLICY="DROP"\n') == {"name": "ufw", "enabled": True, "default_inbound": "Block"}
    assert lx_fw.parse_ufw_conf("ENABLED=no\n", 'DEFAULT_INPUT_POLICY="ACCEPT"\n')["default_inbound"] == "Allow"
    st = lx_fw.parse_ufw_status("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n")
    assert st["enabled"] and st["default_inbound"] == "Block"


def test_linux_luks_detection():
    doc = json.loads((FIXTURES / "lsblk_luks.json").read_text(encoding="utf-8"))
    vols = {v["drive"]: v["state"] for v in lx_enc.parse_lsblk(doc)}
    assert vols == {"/": "on", "/home": "off"}


def test_linux_software_and_disks():
    dpkg = "python3.10\t3.10.12-1~22.04.3\t21000\tii \npython3.12\t3.12.3-1\t500\tii \nold-pkg\t1.0\t10\trc \n"
    apps = lx_sw.parse_dpkg(dpkg)
    assert [a["name"] for a in apps] == ["python3.10", "python3.12"] and apps[0]["size_mb"] == 20.5
    assert lx_sw.parse_rpm("bash\t5.1.8-9.el9\t7700000\ngpg-pubkey\tx\t0\n")[0]["name"] == "bash"
    snaps = lx_sw.parse_snap("Name  Version  Rev  Tracking  Publisher  Notes\nfirefox  131.0  4955  latest/stable  mozilla**  -\n")
    assert snaps == [{"name": "firefox", "version": "131.0", "size_mb": None, "source": "snap"}]
    disks = lx_sto.parse_lsblk_disks({"blockdevices": [{"name": "sda", "type": "disk", "rota": True, "model": "WDC "},
                                                        {"name": "nvme0n1", "type": "disk", "rota": "0", "model": "Samsung"},
                                                        {"name": "loop0", "type": "loop", "rota": False}]})
    assert [(d["name"], d["media_type"]) for d in disks] == [("WDC", "HDD"), ("Samsung", "SSD")]
    assert lx_sto.parse_smartctl_health("SMART overall-health self-assessment test result: PASSED") == "Healthy"


def test_linux_autostart_and_xdg(tmp_path):
    e = lx_perf.parse_desktop_entry("[Desktop Entry]\nName=Slack\nExec=/usr/bin/slack -u\nX-GNOME-Autostart-enabled=false\n")
    assert e == {"name": "Slack", "command": "/usr/bin/slack -u", "enabled": False}
    dirs = parse_xdg_user_dirs('XDG_DOWNLOAD_DIR="$HOME/Téléchargements"\nXDG_MUSIC_DIR="$HOME/Musique"\n', tmp_path)
    assert dirs["Téléchargements"] == tmp_path / "Téléchargements"


def test_linux_lifecycle():
    client = FakeClient({"ubuntu": [{"cycle": "24.04", "eol": "2029-05-31"}, {"cycle": "20.04", "eol": "2025-05-29"}],
                         "python": [{"cycle": "3.8", "eol": "2024-10-07", "latest": "3.8.20"}]})
    old = match_linux({"id": "ubuntu", "version": "20.04", "caption": "Ubuntu 20.04.6 LTS"}, client, date(2026, 1, 1))
    assert old["status"] == "fin_de_support"
    assert match_linux({"id": "gentoo", "version": "2.15"}, client, date(2026, 1, 1))["status"] == "inconnu"
    py = match_software({"name": "python3.8", "version": "3.8.10-0ubuntu1", "source": "dpkg"}, client, date(2026, 1, 1), "linux")
    assert py["status"] == "fin_de_support" and py["cycle"] == "3.8"
    # Pas de comparaison au « latest » de l'éditeur : la distribution rétroporte les correctifs
    client.products["python"] = [{"cycle": "3.12", "eol": "2028-10-31", "latest": "3.12.10"}]
    ok = match_software({"name": "python3.12", "version": "3.12.3-1", "source": "dpkg"}, client, date(2026, 1, 1), "linux")
    assert ok["status"] == "supporte"


# ------------------------------------------------------------------ macOS

def test_macos_parsers():
    v = mac_sys.parse_sw_vers("ProductName:\t\tmacOS\nProductVersion:\t\t14.6.1\nBuildVersion:\t\t23G93\n")
    assert v["ProductVersion"] == "14.6.1"
    su = mac_sys.parse_softwareupdate("Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n"
                                      "* Label: macOS Sonoma 14.7-23H124\n\tTitle: macOS Sonoma 14.7, Version: 14.7, Size: 1234567KiB, Recommended: YES, Action: restart,\n")
    assert su[0]["title"] == "macOS Sonoma 14.7" and su[0]["severity"] == "Important"
    assert mac_sys.parse_softwareupdate("No new software available.\n") == []
    assert mac_sys.parse_auto_update({"AutomaticCheckEnabled": False})["automatic_check"] is False
    users = mac_acc.parse_dscl_uids("_spotlight 89\nalice 501\nbob 502\nnobody -2\n")
    assert [u["name"] for u in users] == ["alice", "bob"]
    assert mac_acc.parse_group_membership("GroupMembership: root alice\n") == ["root", "alice"]
    assert mac_fw.parse_state("Firewall is enabled. (State = 1)") is True
    assert mac_fw.parse_state("Firewall is disabled. (State = 0)") is False
    assert mac_enc.parse_fdesetup("FileVault is Off.\n")["state"] == "off"
    assert mac_enc.parse_fdesetup("FileVault is On.\n")["state"] == "on"
    assert mac_net.parse_scutil_dns("resolver #1\n  nameserver[0] : 192.168.1.1\n  nameserver[1] : 1.1.1.1\nresolver #2\n  nameserver[0] : 192.168.1.1\n") == ["192.168.1.1", "1.1.1.1"]
    disk = mac_sto.parse_diskutil_info({"MediaName": "APPLE SSD AP0512Z", "SolidState": True, "SMARTStatus": "Verified", "TotalSize": 500 * 1024 ** 3})
    assert disk["media_type"] == "SSD" and disk["health"] == "Healthy"


def test_lsof_listen():
    out = ("COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
           "rapportd  512 alice  4u  IPv4 0x1      0t0  TCP *:49152 (LISTEN)\n"
           "postgres  777 alice  7u  IPv6 0x2      0t0  TCP [::1]:5432 (LISTEN)\n")
    ports = parse_lsof_listen(out)
    assert ports[0]["port"] == 5432 and ports[0]["exposed"] is False
    assert ports[1]["port"] == 49152 and ports[1]["exposed"] is True


def test_macos_lifecycle():
    client = FakeClient({"macos": [{"cycle": "15", "codename": "Sequoia", "eol": False, "latest": "15.7"},
                                   {"cycle": "12", "codename": "Monterey", "eol": True, "latest": "12.7.6"},
                                   {"cycle": "10.15", "codename": "Catalina", "eol": True, "latest": "10.15.7"}]})
    assert match_macos({"version": "12.7.6"}, client, date(2026, 1, 1))["status"] == "fin_de_support"
    assert match_macos({"version": "10.15.7"}, client, date(2026, 1, 1))["cycle"] == "10.15"
    assert match_macos({"version": "15.6"}, client, date(2026, 1, 1))["status"] == "maj_disponible"


# ------------------------------------------------------------------ Wi-Fi et matériel

def test_wifi_classification():
    assert classify("WPA2 - Personnel", "CCMP") == "wpa2"
    assert classify("WPA2-Personal", "TKIP") == "wpa"
    assert classify("WPA3-Personnel") == "wpa3"
    assert classify("Ouvrir") == "ouvert" and classify("Open") == "ouvert" and classify("none") == "ouvert"
    assert classify("WEP") == "wep"
    assert classify("WPA2-Entreprise") == "entreprise"


def test_netsh_parsers_fr_en():
    fr = ("Il existe 1 interface sur le système :\n\n    Nom                   : Wi-Fi\n    État                  : connecté\n"
          "    SSID                   : CafeLibre\n    BSSID                  : aa:bb\n    Authentification         : Ouvrir\n    Chiffrement                 : Aucune\n")
    cur = parse_netsh_interfaces(fr)
    assert cur["ssid"] == "CafeLibre" and cur["security"] == "ouvert"
    en = "    Name : Wi-Fi\n    State : connected\n    SSID : Home\n    Authentication : WPA3-Personal\n    Cipher : CCMP\n"
    assert parse_netsh_interfaces(en)["security"] == "wpa3"
    assert parse_netsh_interfaces("    State : disconnected\n") is None
    names = parse_netsh_profiles("Profils utilisateurs\n-------------\n    Profil Tous les utilisateurs     : Maison\n    All User Profile : Gare\n")
    assert names == ["Maison", "Gare"]
    prof = parse_netsh_profile("Gare", "    Mode de connexion    : connexion automatique\n    Authentification         : Ouvrir\n")
    assert prof["security"] == "ouvert" and prof["autoconnect"] is True


def test_nmcli_and_airport():
    assert parse_nmcli_wifi("no:Voisin:WPA2\nyes:Mon\\:Wifi:WPA1 WPA2\n") == {"ssid": "Mon:Wifi", "auth": "WPA1 WPA2", "cipher": None, "security": "wpa2"}
    assert parse_nmcli_wifi("yes:Gare:\n")["security"] == "ouvert"
    doc = {"SPAirPortDataType": [{"spairport_airport_interfaces": [{"_name": "en0", "spairport_current_network_information": {
        "_name": "Maison", "spairport_security_mode": "spairport_security_mode_wpa2_personal"}}]}]}
    assert parse_airport_json(doc)["security"] == "wpa2"


def test_battery_parsers():
    xml = ('<?xml version="1.0"?><BatteryReport xmlns="http://schemas.microsoft.com/battery/2012"><Batteries><Battery>'
           '<DesignCapacity>50000</DesignCapacity><FullChargeCapacity>35000</FullChargeCapacity><CycleCount>412</CycleCount>'
           '</Battery></Batteries></BatteryReport>')
    b = parse_powercfg_xml(xml)
    assert b["health_percent"] == 70.0 and b["cycles"] == 412
    assert parse_powercfg_xml('<BatteryReport xmlns="http://schemas.microsoft.com/battery/2012"><Batteries></Batteries></BatteryReport>') is None
    assert parse_sys_battery({"energy_full_design": "57000000\n", "energy_full": "45600000\n", "cycle_count": "120"})["health_percent"] == 80.0
    io = '"CycleCount" = 300\n"DesignCapacity" = 5000\n"AppleRawMaxCapacity" = 4100\n"MaxCapacity" = 82\n'
    assert parse_ioreg_battery(io)["health_percent"] == 82.0


# ------------------------------------------------------------------ traitement complet simulé

def _process_fixture(name: str):
    raw = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return process(raw, ScanContext(offline=True, cache_dir=None))


def test_linux_scan_end_to_end():
    r = _process_fixture("raw_linux.json")
    f = {x.key: x for x in r.findings}
    assert r.os_family == "linux" and r.os.startswith("Ubuntu")
    assert f["LNX-001:toor"].severity == "critique"
    assert f["LNX-002"].status == "detecte" and f["LNX-003"].status == "detecte"
    assert f["FW-001"].status == "detecte" and f["FW-001"].title == "Pare-feu inactif"
    assert "ufw" in " ".join(c.cmd for c in f["FW-001"].remediation.commands["linux"])
    assert f["ENC-001"].status == "detecte" and "LUKS" in f["ENC-001"].title
    assert f["AV-001"].severity == "moyen"
    assert f["NET-005:public"].severity == "eleve"
    assert f["SYS-003"].severity == "eleve"  # mise à jour de sécurité en attente
    assert f["WIFI-001"].status == "detecte"  # connecté à un réseau ouvert
    assert f["HW-001"].status == "detecte" and f["HW-001"].severity == "moyen"
    assert "APP-003:python3" in f
    assert not any(k.startswith(("SYS-005", "NET-001", "FW-003", "ACC-005")) for k in f)  # contrôles propres à Windows
    assert r.scores["securite"] < 50


def test_macos_scan_end_to_end():
    r = _process_fixture("raw_macos.json")
    f = {x.key: x for x in r.findings}
    assert r.os_family == "macos"
    assert f["MAC-001"].status == "detecte" and f["MAC-002"].status == "conforme"
    assert f["ENC-001"].status == "detecte" and "FileVault" in f["ENC-001"].title
    assert "fdesetup" in " ".join(c.cmd for c in f["ENC-001"].remediation.commands["macos"])
    assert f["MAC-004"].status == "detecte" and f["ACC-002"].status == "detecte"
    assert f["NET-006"].status == "detecte" and "NET-004:22" not in f
    assert f["AV-001"].status == "conforme"   # XProtect intégré
    assert f["MAC-005"].status == "detecte"
    assert f["FW-001"].title == "Pare-feu de macOS désactivé"


def test_distro_package_downgraded_when_distro_supported():
    from kmb_library.rules.engine import RawView
    from kmb_library.rules.software import evaluate

    raw = json.loads((FIXTURES / "raw_linux.json").read_text(encoding="utf-8"))
    lc = {"name": "python3.10", "version": "3.10.12", "product": "python", "cycle": "3.10", "status": "fin_de_support",
          "eol": "2026-10-01", "rolling": False, "distro_package": True, "source": "endoflife.date"}
    supported = evaluate(RawView(raw), {"os_lifecycle": {"status": "supporte"}, "software_lifecycle": [lc]})
    assert next(f for f in supported if f.key == "APP-001:python-3.10").severity == "info"
    eol_distro = evaluate(RawView(raw), {"os_lifecycle": {"status": "fin_de_support"}, "software_lifecycle": [lc]})
    assert next(f for f in eol_distro if f.key == "APP-001:python-3.10").severity == "eleve"


def test_durations_use_scan_date():
    r = _process_fixture("raw_linux.json")   # scan du 2026-03-01, dernière mise à jour le 2026-02-27
    f = {x.key: x for x in r.findings}
    assert f["SYS-004"].status == "conforme" and "il y a 2 jours" in f["SYS-004"].evidence
