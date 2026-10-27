"""Collecte macOS : pare-feu applicatif (socketfilterfw), blocage total et mode furtif."""

from __future__ import annotations

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, run_cmd

NAME = "firewall"
LABEL = "Pare-feu"
SFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def parse_state(text: str) -> bool:
    t = text.lower()
    return ("enabled" in t or "state = 1" in t or "state = 2" in t) and "disabled" not in t


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    state = attempt(errors, "profiles", lambda: parse_state(run_cmd([SFW, "--getglobalstate"])))
    block_all = attempt(errors, "block_all", lambda: parse_state(run_cmd([SFW, "--getblockall"])))
    stealth = attempt(errors, "stealth", lambda: parse_state(run_cmd([SFW, "--getstealthmode"])))
    return {
        "profiles": None if state is None else [{"name": "Pare-feu applicatif", "enabled": state,
                                                 "default_inbound": "Block" if block_all else None}],
        "stealth_mode": stealth,
        "sensitive_inbound_rules": None,
        "_errors": errors,
    }
