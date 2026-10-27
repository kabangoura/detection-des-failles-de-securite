"""Collecte macOS : protection intégrée XProtect et antivirus tiers installés."""

from __future__ import annotations

import plistlib
import time
from pathlib import Path

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt

NAME = "antivirus"
LABEL = "Antivirus"

XPROTECT = [
    Path("/Library/Apple/System/Library/CoreServices/XProtect.bundle"),  # macOS 10.15+
    Path("/System/Library/CoreServices/XProtect.bundle"),
]
THIRD_PARTY = ("Malwarebytes", "Sophos", "Avast", "AVG", "Norton", "Bitdefender", "ESET", "Intego", "Kaspersky",
               "McAfee", "Trend Micro", "CrowdStrike", "SentinelOne", "Microsoft Defender")


def _xprotect() -> dict | None:
    for bundle in XPROTECT:
        info = bundle / "Contents" / "Info.plist"
        if info.exists():
            plist = plistlib.loads(info.read_bytes())
            age = round((time.time() - info.stat().st_mtime) / 86400)
            return {"name": "XProtect (intégré à macOS)", "enabled": True, "version": plist.get("CFBundleShortVersionString"),
                    "signature_age_days": age, "up_to_date": age <= 45}
    return None


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    products = []
    xp = attempt(errors, "xprotect", _xprotect)
    if xp:
        products.append(xp)
    apps = [p.stem for p in Path("/Applications").glob("*.app")] if Path("/Applications").is_dir() else []
    for app in apps:
        if any(v.lower() in app.lower() for v in THIRD_PARTY):
            products.append({"name": app, "enabled": True, "up_to_date": None})
    return {"products": products, "defender": None, "builtin": xp, "_errors": errors}
