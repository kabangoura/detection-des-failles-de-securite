"""Noms de fichiers lisibles, dossier de sortie, et lecture des anciens noms par l'API."""

import json

from api.storage import ScanStore
from kmb_library.core.context import ScanContext
from kmb_library.core.runner import process
from kmb_library.reports.json_report import default_output_dir, file_stem, save_scan


def _report(raw, **ctx_args):
    return process(raw, ScanContext(offline=True, cache_dir=None, **ctx_args))


def test_readable_file_names(raw, tmp_path):
    report = _report(raw)
    assert file_stem(report) == "PC-ALICE_2026-01-01_12h00"
    paths = save_scan(raw, report, tmp_path)
    assert paths["rapport"].name == "KMB-rapport_PC-ALICE_2026-01-01_12h00.json"
    assert "lisible" not in paths and not list(tmp_path.glob("*.html"))  # un seul rapport : le JSON
    assert paths["brut"].relative_to(tmp_path).as_posix() == "donnees-brutes/donnees-brutes_PC-ALICE_2026-01-01_12h00.json"


def test_chosen_name_and_model(raw):
    raw["collectors"]["system"]["data"]["hardware"] = {"manufacturer": "HP", "model": "EliteBook 840"}
    report = _report(raw, display_name="  PC de Marie / bureau ")
    assert report.display_name == "PC de Marie / bureau"
    assert report.device_model == "HP EliteBook 840"
    assert file_stem(report) == "PC-de-Marie-bureau_2026-01-01_12h00"


def test_same_minute_does_not_overwrite(raw, tmp_path):
    report = _report(raw)
    first = save_scan(raw, report, tmp_path)["rapport"]
    second = save_scan(raw, report, tmp_path)["rapport"]
    assert first != second and second.name.endswith("_2.json")


def test_output_dir_override(monkeypatch, tmp_path):
    monkeypatch.setenv("KMB_SORTIE", str(tmp_path))
    assert default_output_dir() == tmp_path
    monkeypatch.delenv("KMB_SORTIE")
    assert default_output_dir().name == "KMB Library"


def test_store_reads_new_and_legacy_names(raw, tmp_path):
    a = _report(raw)
    raw["scan_id"] = "20260102-120000-test02"
    raw["started_at"] = raw["finished_at"] = "2026-01-02T12:00:00-05:00"
    b = _report(raw)
    save_scan(raw, a, tmp_path)                                         # nouveau nom, à la racine
    (tmp_path / "processed").mkdir()
    (tmp_path / "processed" / f"scan_{b.scan_id}.json").write_text(b.model_dump_json(), encoding="utf-8")  # ancien nom
    store = ScanStore(tmp_path)
    assert {r.scan_id for r in store.all()} == {a.scan_id, b.scan_id}
    assert store.get(b.scan_id).scan_id == b.scan_id
    assert store.delete(a.scan_id) and not store.exists(a.scan_id)
    assert json.loads((tmp_path / "processed" / f"scan_{b.scan_id}.json").read_text())["scan_id"] == b.scan_id
