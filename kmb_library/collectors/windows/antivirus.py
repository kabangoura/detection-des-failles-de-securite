"""Collecte : Microsoft Defender et antivirus déclarés au Centre de sécurité Windows."""

from __future__ import annotations

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, ps_json

NAME = "antivirus"
LABEL = "Antivirus"


def decode_product_state(state: int | None) -> dict:
    """productState (SecurityCenter2) : octet du milieu = activation, octet bas = signatures."""
    if state is None:
        return {"enabled": None, "up_to_date": None}
    state = int(state)
    return {
        "enabled": ((state >> 8) & 0xFF) in (0x10, 0x11),
        "up_to_date": (state & 0xFF) == 0x00,
    }


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    products = attempt(errors, "security_center", lambda: ps_json(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
        "Select-Object displayName,productState"
    ))
    mp = attempt(errors, "defender", lambda: ps_json(
        "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,"
        "AntispywareEnabled,AntivirusSignatureAge,"
        "@{n='SignatureLastUpdated';e={$_.AntivirusSignatureLastUpdated.ToString('o')}},"
        "@{n='LastQuickScan';e={if($_.QuickScanEndTime){$_.QuickScanEndTime.ToString('o')}}}"
    )[0])
    return {
        "products": [
            {"name": p.get("displayName"), "state": p.get("productState"), **decode_product_state(p.get("productState"))}
            for p in products
        ] if products is not None else None,
        "defender": None if mp is None else {
            "service_enabled": mp.get("AMServiceEnabled"),
            "antivirus_enabled": mp.get("AntivirusEnabled"),
            "realtime_enabled": mp.get("RealTimeProtectionEnabled"),
            "signature_age_days": mp.get("AntivirusSignatureAge"),
            "signature_updated": mp.get("SignatureLastUpdated"),
            "last_quick_scan": mp.get("LastQuickScan"),
        },
        "_errors": errors,
    }
