"""Vérifie que chaque règle transforme correctement les données brutes en constats."""

from kmb_library.rules.engine import evaluate
from tests.conftest import data


def by_key(findings):
    return {f.key: f for f in findings}


def test_clean_machine_has_no_security_problem(raw, enrichment):
    findings = evaluate(raw, enrichment)
    detected = [f for f in findings if f.status == "detecte" and f.domain == "securite"]
    # Seul constat attendu : le compte courant est administrateur
    assert [f.key for f in detected] == ["ACC-005"]


def test_keys_are_unique(raw, enrichment):
    keys = [f.key for f in evaluate(raw, enrichment)]
    assert len(keys) == len(set(keys))


def test_end_of_life_os_is_critical(raw, enrichment):
    enrichment["os_lifecycle"] = {"status": "fin_de_support", "eol": "2025-10-14", "label": "10 22H2"}
    f = by_key(evaluate(raw, enrichment))["SYS-001"]
    assert f.status == "detecte" and f.severity == "critique" and f.penalty == 15


def test_smbv1_guest_and_firewall(raw, enrichment):
    data(raw, "network")["smb1_enabled"] = True
    data(raw, "accounts")["local_users"][1]["enabled"] = True       # Invité
    data(raw, "firewall")["profiles"][2]["enabled"] = False          # Public
    f = by_key(evaluate(raw, enrichment))
    assert f["NET-001"].status == "detecte" and f["NET-001"].severity == "critique"
    assert f["ACC-002"].status == "detecte"
    assert f["FW-001:Public"].status == "detecte"
    assert "FW-001" not in f  # pas de constat « conforme » global quand un profil est coupé


def test_exposed_database_port(raw, enrichment):
    data(raw, "network")["listening"].append({"ip": "0.0.0.0", "port": 3306, "pid": 4, "process": "mysqld.exe", "exposed": True})
    data(raw, "network")["listening"].append({"ip": "0.0.0.0", "port": 23, "pid": 5, "process": "telnetd", "exposed": True})
    f = by_key(evaluate(raw, enrichment))
    assert f["NET-004:3306"].severity == "eleve"
    assert f["NET-004:23"].severity == "critique"
    assert "mysqld.exe" in f["NET-004:3306"].evidence


def test_local_only_port_is_not_reported(raw, enrichment):
    f = by_key(evaluate(raw, enrichment))
    assert f["NET-004"].status == "conforme"


def test_bitlocker_off(raw, enrichment):
    data(raw, "encryption")["volumes"][0]["state"] = "off"
    assert by_key(evaluate(raw, enrichment))["ENC-001"].status == "detecte"


def test_missing_data_becomes_non_verifiable(raw, enrichment):
    data(raw, "firewall")["sensitive_inbound_rules"] = None
    data(raw, "firewall")["_errors"] = {"sensitive_rules": "CommandError: Get-NetFirewallRule : Accès refusé."}
    f = by_key(evaluate(raw, enrichment))["FW-003"]
    assert f.status == "non_verifiable" and f.penalty == 0
    assert "administrateur" in f.evidence


def test_disk_space_thresholds(raw, enrichment):
    part = data(raw, "storage")["partitions"][0]
    part["percent_used"] = 85
    assert by_key(evaluate(raw, enrichment))["STO-001:C:"].severity == "moyen"
    part["percent_used"] = 95
    assert by_key(evaluate(raw, enrichment))["STO-001:C:"].severity == "eleve"


def test_software_lifecycle_rules(raw, enrichment):
    enrichment["software_lifecycle"] = [
        {"name": "Python 3.8.10", "version": "3.8.10", "product": "python", "cycle": "3.8", "status": "fin_de_support",
         "eol": "2024-10-07", "rolling": False, "source": "endoflife.date"},
        {"name": "Google Chrome", "version": "120.0", "product": "chrome", "cycle": "120", "status": "fin_de_support",
         "eol": "2024-01-01", "rolling": True, "newest": "155", "source": "endoflife.date"},
        {"name": "Node.js", "version": "24.1.0", "product": "nodejs", "cycle": "24", "status": "maj_disponible",
         "latest": "24.21.0", "rolling": False, "source": "endoflife.date"},
    ]
    f = by_key(evaluate(raw, enrichment))
    assert f["APP-001:python-3.8"].severity == "eleve"
    assert f["APP-002:chrome-120"].severity == "moyen"
    assert f["APP-002:nodejs-24"].severity == "faible"


def test_multiple_versions(raw, enrichment):
    data(raw, "software")["installed"] = [
        {"name": "Python 3.10.11 (64-bit)", "version": "3.10.11"},
        {"name": "Python 3.12.4 (64-bit)", "version": "3.12.4"},
        {"name": "Microsoft Visual C++ 2015 Redistributable (x64)", "version": "14.0"},
        {"name": "Microsoft Visual C++ 2015 Redistributable (x86)", "version": "14.1"},
    ]
    f = by_key(evaluate(raw, enrichment))
    assert "APP-003:python" in f
    assert not any("visual" in k for k in f if k.startswith("APP-003"))
