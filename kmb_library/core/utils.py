"""Fonctions utilitaires partagées : exécution de commandes, registre, dates, tailles."""

from __future__ import annotations

import ctypes
import json
import re
import subprocess
import sys
from datetime import date, datetime, timezone
from typing import Any, Callable

IS_WINDOWS = sys.platform == "win32"
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


class CommandError(RuntimeError):
    """Une commande système a échoué (droits insuffisants, commande absente, etc.)."""


def run_cmd(args: list[str], timeout: int = 30, encoding: str | None = None, ok_codes: tuple[int, ...] = (0,)) -> str:
    """Exécute une commande et retourne sa sortie standard décodée.

    `ok_codes` : codes de retour considérés comme normaux (ex. `systemctl is-active` renvoie 3 si inactif).
    """
    enc = encoding or ("oem" if IS_WINDOWS else "utf-8")
    env = None
    if not IS_WINDOWS:
        import os

        env = {**os.environ, "LC_ALL": "C", "LANG": "C"}  # sorties en anglais, stables à analyser
    try:
        proc = subprocess.run(
            args, capture_output=True, timeout=timeout, creationflags=_NO_WINDOW, env=env
        )
    except FileNotFoundError as exc:
        raise CommandError(f"Commande introuvable : {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"Délai dépassé ({timeout} s) : {args[0]}") from exc
    out = proc.stdout.decode(enc, errors="replace")
    if proc.returncode not in ok_codes:
        err = proc.stderr.decode(enc, errors="replace").strip()
        raise CommandError(_first_line(err) or _first_line(out) or f"code {proc.returncode}")
    return out


def _first_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:300]
    return ""


def run_ps(script: str, timeout: int = 60) -> str:
    """Exécute un script PowerShell (sortie forcée en UTF-8)."""
    prefix = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; "
    args = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prefix + script]
    return run_cmd(args, timeout=timeout, encoding="utf-8")


def ps_json(script: str, timeout: int = 60) -> list[Any]:
    """Exécute un script PowerShell et retourne toujours une liste d'objets JSON."""
    wrapped = f"ConvertTo-Json -InputObject @(& {{ {script} }}) -Depth 5 -Compress"
    out = run_ps(wrapped, timeout=timeout).strip()
    if not out:
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def attempt(errors: dict[str, str], key: str, fn: Callable[[], Any], default: Any = None) -> Any:
    """Exécute un sous-contrôle; en cas d'échec, mémorise l'erreur au lieu de planter."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - on veut tout capturer pour ne jamais interrompre le scan
        errors[key] = f"{type(exc).__name__}: {exc}"[:300]
        return default


# --------------------------------------------------------------------------- registre

def read_reg(hive: str, path: str, name: str | None = None) -> Any:
    """Lit une valeur (ou toutes les valeurs si name=None) du registre Windows."""
    import winreg

    root = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[hive]
    with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        if name is not None:
            try:
                return winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                return None
        values = {}
        i = 0
        while True:
            try:
                n, v, _ = winreg.EnumValue(key, i)
            except OSError:
                break
            values[n] = v
            i += 1
        return values


def is_admin() -> bool:
    if not IS_WINDOWS:
        import os

        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- dates

_PS_DATE = re.compile(r"/Date\((-?\d+)")


def parse_date(value: Any) -> datetime | None:
    """Comprend les dates ISO, 'AAAAMMJJ' et le format JSON PowerShell '/Date(ms)/'."""
    if value in (None, "", {}):
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    text = str(value)
    m = _PS_DATE.search(text)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
    if re.fullmatch(r"\d{8}", text):
        try:
            return datetime.strptime(text, "%Y%m%d")
        except ValueError:
            return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def iso(value: Any) -> str | None:
    d = parse_date(value)
    return d.isoformat() if d else None


def days_since(value: Any, now: datetime | None = None) -> int | None:
    d = parse_date(value)
    if d is None:
        return None
    now = now or datetime.now(timezone.utc)
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return (now - d).days


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


# --------------------------------------------------------------------------- tailles

def human_size(num: float | int | None) -> str:
    if num is None:
        return "?"
    num = float(num)
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if abs(num) < 1024 or unit == "To":
            return f"{num:.0f} {unit}" if unit == "o" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} To"


GB = 1024 ** 3
MB = 1024 ** 2


def version_tuple(version: str | None) -> tuple[int, ...]:
    """'3.12.4' -> (3, 12, 4) ; ignore les suffixes non numériques."""
    if not version:
        return ()
    parts = []
    for chunk in re.split(r"[.\-+_ ]", str(version)):
        m = re.match(r"\d+", chunk)
        if not m:
            break
        parts.append(int(m.group()))
    return tuple(parts)
