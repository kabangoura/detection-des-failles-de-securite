"""Scores, comparaison, enrichissement, nettoyage, doublons et anonymisation."""

from datetime import date

from kmb_library.collectors.duplicates import find_duplicates, normalize_name
from kmb_library.collectors.windows.software import clean_entries
from kmb_library.core.anonymize import anonymize
from kmb_library.core.compare import compare_reports
from kmb_library.core.context import ScanContext
from kmb_library.core.runner import process
from kmb_library.core.scoring import compute_scores
from kmb_library.enrich.endoflife import lifecycle_status, match_software, match_windows
from kmb_library.rules.engine import make
from tests.conftest import data

WINDOWS_CYCLES = [
    {"cycle": "11-24h2-w", "releaseLabel": "11 24H2 (W)", "eol": "2026-10-13", "latest": "10.0.26100"},
    {"cycle": "11-24h2-e", "releaseLabel": "11 24H2 (E)", "eol": "2027-10-12", "latest": "10.0.26100"},
    {"cycle": "10-22h2", "releaseLabel": "10 22H2", "eol": "2025-10-14", "latest": "10.0.19045"},
]


class FakeClient:
    def __init__(self, products):
        self.products = products

    def cycles(self, product):
        return self.products.get(product)


# ------------------------------------------------------------------ scores

def test_score_penalties():
    findings = [make("SYS-001", "detecte"), make("ENC-001", "detecte"), make("NET-002", "detecte"),
                make("ACC-005", "detecte"), make("NET-001", "conforme")]
    s = compute_scores(findings)
    assert s["securite"] == 100 - 15 - 10 - 5 - 1
    assert s["performance"] == 100
    assert s["global"] == round(0.4 * 69 + 0.2 * 100 * 3)


def test_score_never_negative():
    findings = [make("SYS-001", "detecte", suffix=str(i)) for i in range(10)]
    assert compute_scores(findings)["securite"] == 0


# ------------------------------------------------------------------ cycle de vie

def test_windows_10_is_end_of_life():
    r = match_windows({"build": "19045", "edition": "Professional"}, FakeClient({"windows": WINDOWS_CYCLES}), date(2026, 10, 9))
    assert r["status"] == "fin_de_support" and r["eol"] == "2025-10-14"


def test_windows_edition_selects_cycle():
    client = FakeClient({"windows": WINDOWS_CYCLES})
    pro = match_windows({"build": "26100", "edition": "Professional"}, client, date(2026, 1, 1))
    ent = match_windows({"build": "26100", "edition": "Enterprise"}, client, date(2026, 1, 1))
    assert pro["cycle"] == "11-24h2-w" and ent["cycle"] == "11-24h2-e"


def test_lifecycle_status():
    cycle = {"cycle": "3.12", "eol": "2028-10-31", "latest": "3.12.10"}
    assert lifecycle_status(cycle, "3.12.4", date(2026, 1, 1))["status"] == "maj_disponible"
    assert lifecycle_status(cycle, "3.12.10", date(2026, 1, 1))["status"] == "supporte"
    assert lifecycle_status(cycle, "3.12.10", date(2029, 1, 1))["status"] == "fin_de_support"


def test_match_python_and_unknown_software():
    client = FakeClient({"python": [{"cycle": "3.8", "eol": "2024-10-07", "latest": "3.8.20"}]})
    r = match_software({"name": "Python 3.8.10 (64-bit)", "version": "3.8.10"}, client, date(2026, 1, 1))
    assert r["product"] == "python" and r["status"] == "fin_de_support"
    assert match_software({"name": "VLC media player", "version": "3.0"}, client, date(2026, 1, 1)) is None


def test_source_unavailable_gives_unknown():
    r = match_software({"name": "Node.js", "version": "24.1.0"}, FakeClient({}), date(2026, 1, 1))
    assert r["status"] == "inconnu"


# ------------------------------------------------------------------ nettoyage du registre

def test_registry_cleaning():
    entries = [
        {"DisplayName": "App A", "DisplayVersion": "1.0", "_scope": "machine", "_arch": "64"},
        {"DisplayName": "App A", "DisplayVersion": "1.0", "_scope": "machine", "_arch": "32"},   # doublon 32/64 bits
        {"DisplayName": "Composant", "SystemComponent": 1, "_scope": "machine", "_arch": "64"},
        {"DisplayName": "Correctif", "ParentKeyName": "Office", "_scope": "machine", "_arch": "64"},
        {"DisplayVersion": "2.0", "_scope": "machine", "_arch": "64"},                           # sans nom
        {"DisplayName": "  App   B ", "EstimatedSize": 2048, "InstallDate": "20250102", "_scope": "utilisateur", "_arch": ""},
    ]
    apps, stats = clean_entries(entries)
    assert [a["name"] for a in apps] == ["App A", "App B"]
    assert stats == {"raw_entries": 6, "without_name": 1, "system_components": 1, "updates": 1, "duplicates": 1, "kept": 2}
    assert apps[1]["size_mb"] == 2.0 and apps[1]["install_date"].startswith("2025-01-02")


# ------------------------------------------------------------------ doublons

def test_normalize_copy_names():
    assert normalize_name("Film (1).mp4") == normalize_name("Film - copie.mp4") == "film.mp4"
    assert normalize_name("Copie de rapport.docx") == normalize_name("rapport-final-v2.docx") == "rapport.docx"
    assert normalize_name("photo_copy.JPG") == "photo.jpg"


def test_find_duplicates(tmp_path):
    a = tmp_path / "a"; b = tmp_path / "b"; a.mkdir(); b.mkdir()
    content = b"x" * 5000
    (a / "photo.jpg").write_bytes(content)
    (b / "photo (1).jpg").write_bytes(content)
    (b / "photo - copie.jpg").write_bytes(content)
    (a / "autre.jpg").write_bytes(b"y" * 5000)            # même taille, contenu différent
    (a / "petit.jpg").write_bytes(b"z" * 10)              # sous la taille minimale
    (a / "notes.xyz").write_bytes(content)                # extension non suivie
    r = find_duplicates([tmp_path], budget_s=30)
    assert r["group_count"] == 1
    assert r["groups"][0]["count"] == 3
    assert r["wasted_bytes"] == 2 * 5000


# ------------------------------------------------------------------ anonymisation

def test_anonymize():
    doc = {"machine": "PC-ALICE", "path": "C:\\Users\\alice\\Downloads\\x.zip", "ip": "192.168.1.25",
           "sid": "S-1-5-21-111-222-333-1001", "text": "Compte « alice » administrateur", "local": "127.0.0.1"}
    out = anonymize(doc, "PC-ALICE", ["alice", "Administrateur"])
    flat = str(out)
    assert "alice" not in flat.lower() and "PC-ALICE" not in flat
    assert out["ip"] == "192.168.x.x" and out["local"] == "127.0.0.1"
    assert "utilisateur1" in out["path"]


# ------------------------------------------------------------------ comparaison de bout en bout

def test_compare_before_after(raw):
    ctx = ScanContext(offline=True, cache_dir=None)
    data(raw, "network")["smb1_enabled"] = True
    data(raw, "encryption")["volumes"][0]["state"] = "off"
    before = process(raw, ctx)

    raw["scan_id"] = "20260102-120000-test02"
    raw["started_at"] = raw["finished_at"] = "2026-01-02T12:00:00-05:00"
    data(raw, "network")["smb1_enabled"] = False                  # corrigé
    data(raw, "accounts")["local_users"][1]["enabled"] = True     # nouveau : Invité activé
    data(raw, "accounts")["administrators"] = None                # devenu non vérifiable
    after = process(raw, ctx)

    c = compare_reports(before, after)
    assert {f["key"] for f in c["corriges"]} == {"NET-001"}
    assert "ENC-001" in {f["key"] for f in c["restants"]}
    assert {f["key"] for f in c["nouveaux"]} == {"ACC-002"}
    assert {f["key"] for f in c["non_verifiables"]} == {"ACC-005"}
    assert c["evolution_scores"]["securite"] == (15) - (10) + (1)
