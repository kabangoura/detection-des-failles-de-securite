"""Données brutes fictives mais représentatives d'un poste Windows, pour tester les règles sans dépendre de la machine."""

from __future__ import annotations

import copy
from datetime import date

import pytest

BASE_RAW = {
    "scan_id": "20260101-120000-test01",
    "started_at": "2026-01-01T12:00:00-05:00",
    "finished_at": "2026-01-01T12:01:00-05:00",
    "kmb_version": "test",
    "os_family": "windows",
    "is_admin": False,
    "collectors": {
        "system": {"status": "ok", "duration_s": 1, "errors": {}, "data": {
            "hostname": "PC-ALICE", "user": "alice", "is_admin": False,
            "os": {"caption": "Microsoft Windows 11 Pro", "version": "10.0.26100", "build": "26100", "ubr": 100,
                   "display_version": "24H2", "edition": "Professional"},
            "hotfixes": {"count": 10, "latest_date": date.today().isoformat(), "recent": []},
            "pending_updates": [],
            "uac": {"enable_lua": 1, "consent_prompt_admin": 5, "secure_desktop": 1},
            "firmware": "UEFI", "secure_boot": True, "_errors": {}}},
        "accounts": {"status": "ok", "duration_s": 1, "errors": {}, "data": {
            "current_user": "alice",
            "local_users": [
                {"name": "Administrateur", "enabled": False, "password_required": True, "sid": "S-1-5-21-1-2-3-500"},
                {"name": "Invité", "enabled": False, "password_required": False, "sid": "S-1-5-21-1-2-3-501"},
                {"name": "alice", "enabled": True, "password_required": True, "sid": "S-1-5-21-1-2-3-1001"},
            ],
            "administrators": [{"name": "PC-ALICE\\alice", "sid": "S-1-5-21-1-2-3-1001", "is_current_user": True}],
            "_errors": {}}},
        "network": {"status": "ok", "duration_s": 1, "errors": {}, "data": {
            "listening": [{"ip": "127.0.0.1", "port": 5432, "pid": 10, "process": "postgres.exe", "exposed": False}],
            "smb1_enabled": False, "smb_shares": [{"name": "C$", "path": "C:\\", "administrative": True}],
            "rdp": {"enabled": False, "nla": True, "port": 3389}, "dns_servers": [], "interfaces": [], "_errors": {}}},
        "firewall": {"status": "ok", "duration_s": 1, "errors": {}, "data": {
            "profiles": [{"name": n, "enabled": True, "default_inbound": "NotConfigured"} for n in ("Domain", "Private", "Public")],
            "sensitive_inbound_rules": [], "_errors": {}}},
        "antivirus": {"status": "ok", "duration_s": 1, "errors": {}, "data": {
            "products": [{"name": "Windows Defender", "enabled": True, "up_to_date": True}],
            "defender": {"antivirus_enabled": True, "realtime_enabled": True, "signature_age_days": 0}, "_errors": {}}},
        "encryption": {"status": "ok", "duration_s": 1, "errors": {}, "data": {
            "volumes": [{"drive": "C:", "state": "on", "label": "Activé", "method": "shell"}], "system_drive": "C:", "_errors": {}}},
        "software": {"status": "ok", "duration_s": 1, "errors": {}, "data": {
            "installed": [{"name": "Notepad", "version": "1.0", "size_mb": 10}], "cleaning": {}, "_errors": {}}},
        "performance": {"status": "ok", "duration_s": 1, "errors": {}, "data": {
            "cpu": {"usage_percent": 20, "logical_cores": 8}, "memory": {"total_gb": 16, "used_gb": 6, "percent": 40},
            "top_memory": [], "top_cpu": [], "startup": [], "uptime_days": 1, "boot_time": "2026-01-01T00:00", "_errors": {}}},
        "storage": {"status": "ok", "duration_s": 1, "errors": {}, "data": {
            "partitions": [{"mount": "C:\\", "fstype": "NTFS", "total_gb": 500, "used_gb": 200, "free_gb": 300, "percent_used": 40}],
            "physical_disks": [{"name": "SSD1", "media_type": "SSD", "health": "Healthy"}],
            "folders": [{"name": "Téléchargements", "local_gb": 1, "files": 10}], "large_files": [], "_errors": {}}},
        "duplicates": {"status": "ok", "duration_s": 1, "errors": {}, "data": {
            "files_scanned": 100, "group_count": 0, "duplicate_files": 0, "wasted_bytes": 0, "groups": []}},
    },
}

CLEAN_ENRICHMENT = {
    "os_lifecycle": {"status": "supporte", "eol": "2027-10-12", "label": "11 24H2 (W)", "days_to_eol": 400},
    "software_lifecycle": [],
    "sources": [],
}


@pytest.fixture
def raw():
    return copy.deepcopy(BASE_RAW)


@pytest.fixture
def enrichment():
    return copy.deepcopy(CLEAN_ENRICHMENT)


def data(raw: dict, name: str) -> dict:
    return raw["collectors"][name]["data"]
