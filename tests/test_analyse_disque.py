"""Analyse approfondie du disque et catalogue des commandes de correction."""

import json
import time
from pathlib import Path

from kmb_library.collectors import analyse_disque as ad
from kmb_library.collectors.duplicates import group_by_content
from kmb_library.core.models import Command, Remediation


def _write(path: Path, size: int, byte: bytes = b"a") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(byte * size)
    return path


def test_categories_in_profile():
    zone = ad.Zone(Path("/home/alice"), "Votre profil", "profil")
    assert ad.category_of(("Documents", "cv.pdf"), zone) == "personnel"
    assert ad.category_of(("AppData", "Local", "x.bin"), zone) == "application"
    assert ad.category_of((".gradle", "caches", "a.jar"), zone) == "application"
    assert ad.category_of(("Projets", "site", "node_modules", "lib.js"), zone) == "application"
    disk = ad.Zone(Path("D:/"), "Disque D:", "disque")
    assert ad.category_of(("Program Files", "App", "app.exe"), disk) == "application"
    assert ad.category_of(("Photos", "ete.jpg"), disk) == "personnel"


def test_analyse_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(ad, "LARGE_FILE_MIN", 3000)
    monkeypatch.setattr(ad, "DUP_MIN", 1000)
    _write(tmp_path / "Documents" / "gros.iso", 5000)
    _write(tmp_path / "Documents" / "a.dat", 2000, b"x")
    _write(tmp_path / "Images" / "a-copie.dat", 2000, b"x")
    _write(tmp_path / "AppData" / "Local" / "cache.bin", 4000)
    _write(tmp_path / "AppData" / "Local" / "cache2.bin", 2000, b"x")  # même taille, mais application : pas un doublon proposé
    res = ad.analyse(time.monotonic() + 30, [ad.Zone(tmp_path, "Votre profil", "profil")])
    out = ad.summarize(res, None)
    sizes = {Path(f["path"]).name: (f["size_gb"], f["category"]) for f in out["space_by_folder"]} if out["space_by_folder"] else {}
    assert res.files == 5 and not res.truncated
    assert res.folder_category[str(tmp_path / "AppData")] == "application"
    assert res.folder_category[str(tmp_path / "Documents")] == "personnel"
    large = {Path(f["path"]).name: f for f in out["large_files"]}
    assert large["gros.iso"]["category"] == "personnel" and large["gros.iso"]["kind"] == "image disque / machine virtuelle"
    assert large["cache.bin"]["category"] == "application"
    assert [len(v) for v in res.dup_by_size.values() if len(v) > 1] == [2]   # seulement les 2 fichiers personnels
    groups, hashed, truncated = group_by_content(res.dup_by_size, time.monotonic() + 30)
    assert len(groups) == 1 and groups[0]["count"] == 2 and groups[0]["wasted_bytes"] == 2000
    assert out["zones"][0]["label"] == "Votre profil"
    assert sizes == {} or all(cat in ("personnel", "application", "mixte") for _, cat in sizes.values())


def test_apps_sizes(tmp_path):
    app = tmp_path / "Programs" / "MonApp"
    _write(app / "app.exe", 200 * 1024 * 1024 // 1000 * 1000)  # environ 200 Mo
    apps = [{"name": "MonApp", "install_location": str(app)}, {"name": "Déclarée", "size_mb": 300}, {"name": "Petite", "size_mb": 5}]
    out = ad.apps_sizes(apps, time.monotonic() + 30)
    names = [a["name"] for a in out]
    assert names == ["Déclarée", "MonApp"]
    assert next(a for a in out if a["name"] == "MonApp")["measured"] is True


def test_old_installers(tmp_path):
    import os

    f = _write(tmp_path / "setup.exe", 1000)
    old = time.time() - 60 * 86400
    os.utime(f, (old, old))
    _write(tmp_path / "recent.msi", 500)
    assert ad.old_installers(tmp_path) == (1000, 1)


def test_command_catalogue_is_complete():
    kb = json.loads((Path(__file__).parent.parent / "kmb_library" / "rules" / "knowledge_base.json").read_text(encoding="utf-8"))
    total = 0
    for rule, entry in kb.items():
        if rule.startswith("_"):
            continue
        for key in [k for k in entry if k.startswith("remediation")]:
            rem = Remediation(**entry[key])
            for os_, cmds in rem.commands.items():
                for c in cmds:
                    assert isinstance(c, Command), (rule, os_, c)       # plus aucune commande en simple texte
                    if c.remplacer:
                        for word in c.remplacer:
                            assert word in c.cmd, (rule, word)          # chaque mot à remplacer figure dans la commande
                    total += 1
    assert total > 200
    assert "STO-006" in kb
