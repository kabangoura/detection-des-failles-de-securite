"""Mesures identiques sur Windows, Linux et macOS (via psutil et le système de fichiers)."""

from __future__ import annotations

import re
import socket
import sys
import time
from datetime import datetime

import psutil

from kmb_library.core.context import ScanContext
from kmb_library.core.fswalk import user_folders
from kmb_library.core.utils import GB, MB, run_cmd



# --------------------------------------------------------------------------- réseau

def parse_lsof_listen(output: str) -> list[dict]:
    """Sortie de `lsof -nP -iTCP -sTCP:LISTEN` (macOS, où psutil exige les droits root)."""
    ports: dict[tuple, dict] = {}
    for line in output.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 9:
            continue
        m = re.match(r"(.+):(\d+)$", cols[8])
        if not m:
            continue
        ip = m.group(1).strip("[]")
        ip = "0.0.0.0" if ip == "*" else ip
        port = int(m.group(2))
        ports[(ip, port)] = {"ip": ip, "port": port, "pid": int(cols[1]) if cols[1].isdigit() else None,
                             "process": cols[0], "exposed": ip in ("0.0.0.0", "::", "*")}
    return sorted(ports.values(), key=lambda p: (p["port"], p["ip"]))


def listening_ports() -> list[dict]:
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        if sys.platform == "darwin":
            return parse_lsof_listen(run_cmd(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]))
        raise
    seen: dict[tuple, dict] = {}
    names: dict[int, str | None] = {}
    for conn in conns:
        if conn.type != socket.SOCK_STREAM or conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        ip, port = conn.laddr.ip, conn.laddr.port
        if conn.pid and conn.pid not in names:
            try:
                names[conn.pid] = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                names[conn.pid] = None
        seen[(ip, port)] = {"ip": ip, "port": port, "pid": conn.pid,
                            "process": names.get(conn.pid) if conn.pid else None,
                            "exposed": ip in ("0.0.0.0", "::", "")}
    return sorted(seen.values(), key=lambda p: (p["port"], p["ip"]))


def interfaces() -> list[dict]:
    stats = psutil.net_if_stats()
    result = []
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        ipv4 = [a.address for a in addrs if a.family == socket.AF_INET]
        if not ipv4 and not (st and st.isup):
            continue
        result.append({"name": name, "up": bool(st and st.isup), "ipv4": ipv4, "speed_mbps": st.speed if st else None})
    return result


# --------------------------------------------------------------------------- performance

def cpu_and_processes() -> tuple[dict, list[dict]]:
    procs = []
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            p.cpu_percent(None)
            procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    samples = [psutil.cpu_percent(interval=1) for _ in range(3)]
    ncpu = psutil.cpu_count() or 1
    rows = []
    for p in procs:
        try:
            cpu = p.cpu_percent(None) / ncpu
            mem = p.info["memory_info"].rss if p.info.get("memory_info") else 0
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if p.info["name"] in ("System Idle Process", "Idle", "kernel_task") or not p.info["name"]:
            continue
        rows.append({"pid": p.info["pid"], "name": p.info["name"], "cpu_percent": round(cpu, 1), "memory_mb": round(mem / MB)})
    try:
        freq = psutil.cpu_freq()
    except (OSError, NotImplementedError, FileNotFoundError):
        freq = None
    cpu = {
        "logical_cores": psutil.cpu_count(),
        "physical_cores": psutil.cpu_count(logical=False),
        "usage_percent": round(sum(samples) / len(samples), 1),
        "usage_samples": samples,
        "frequency_mhz": round(freq.current) if freq else None,
        "frequency_max_mhz": round(freq.max) if freq and freq.max else None,
    }
    return cpu, rows


def performance_snapshot() -> dict:
    """Partie commune du collecteur de performance (processeur, mémoire, processus, démarrage du système)."""
    cpu, procs = cpu_and_processes()
    vm, sw = psutil.virtual_memory(), psutil.swap_memory()
    groups: dict[str, dict] = {}
    for p in procs:
        g = groups.setdefault(p["name"], {"name": p["name"], "count": 0, "memory_mb": 0, "cpu_percent": 0.0})
        g["count"] += 1
        g["memory_mb"] += p["memory_mb"]
        g["cpu_percent"] = round(g["cpu_percent"] + p["cpu_percent"], 1)
    battery = None
    try:
        b = psutil.sensors_battery()
        battery = {"percent": round(b.percent), "plugged": b.power_plugged} if b else None
    except (AttributeError, OSError, NotImplementedError):
        pass
    boot = datetime.fromtimestamp(psutil.boot_time())
    return {
        "cpu": cpu,
        "memory": {
            "total_gb": round(vm.total / GB, 1), "used_gb": round(vm.used / GB, 1),
            "available_gb": round(vm.available / GB, 1), "percent": vm.percent,
            "swap_total_gb": round(sw.total / GB, 1), "swap_percent": sw.percent,
        },
        "top_memory": sorted(groups.values(), key=lambda g: g["memory_mb"], reverse=True)[:10],
        "top_cpu": sorted(groups.values(), key=lambda g: g["cpu_percent"], reverse=True)[:10],
        "process_count": len(procs),
        "boot_time": boot.astimezone().isoformat(timespec="seconds"),
        "uptime_days": round((time.time() - psutil.boot_time()) / 86400, 1),
        "battery": battery,
    }


# --------------------------------------------------------------------------- stockage

_SKIP_MOUNTS = re.compile(r"^/(snap|boot/efi|System/Volumes/(?!Data$)|private/var/vm|dev|run|sys|proc)")


def partitions() -> list[dict]:
    parts = []
    for p in psutil.disk_partitions(all=False):
        if "cdrom" in p.opts or not p.fstype or p.fstype in ("squashfs", "tmpfs", "devtmpfs", "overlay", "autofs"):
            continue
        if _SKIP_MOUNTS.match(p.mountpoint):
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
        except OSError:
            continue
        if u.total < 1 * GB:
            continue
        parts.append({"mount": p.mountpoint, "fstype": p.fstype, "total_gb": round(u.total / GB, 1),
                      "used_gb": round(u.used / GB, 1), "free_gb": round(u.free / GB, 1), "percent_used": u.percent})
    return parts


def storage_common(ctx: ScanContext, errors: dict) -> dict:
    """Analyse approfondie de tout ce qui appartient à l'utilisateur (voir analyse_disque.py).

    Répartition du temps : environ 55 % pour le parcours, 10 % pour l'espace récupérable ;
    le reste sert aux doublons (collecteur « duplicates ») et à la taille des applications.
    """
    from kmb_library.collectors import analyse_disque as ad
    from kmb_library.core.utils import attempt

    budget = ctx.storage_time_budget_s
    data = {"partitions": attempt(errors, "partitions", partitions)}
    res = attempt(errors, "analyse", lambda: ad.analyse(time.monotonic() + budget * 0.55))
    if res is not None:
        data.update(ad.summarize(res, data["partitions"]))
        ctx.shared.update({
            "dup_candidates": {size: files for size, files in res.dup_by_size.items() if len(files) > 1},
            "files_scanned": res.files, "walk_truncated": res.truncated, "cloud_only": res.cloud_only,
            "zones": list(res.zone_roots),
        })
        # tailles des dossiers personnels habituels (graphique « Dossiers personnels »)
        data["folders"] = sorted(
            ({"name": label, "path": str(path), "local_gb": round(res.folder_sizes.get(str(path), 0) / GB, 2),
              "files": res.folder_files.get(str(path), 0)} for label, path in user_folders().items()),
            key=lambda f: f["local_gb"], reverse=True)
    data["recoverable"] = attempt(errors, "recoverable", lambda: ad.recoverable(time.monotonic() + budget * 0.1), [])
    data["apps"] = attempt(errors, "apps", lambda: ad.apps_sizes(ctx.shared.get("installed_apps", []), time.monotonic() + budget * 0.1), [])
    return data
