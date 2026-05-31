#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RecentTracker v1.0
=========================
Ethical Windows 11 forensic tool — identifies recently installed programs,
files, and directories within a fully configurable time window.

Scanners:
  · Registry   — HKLM/HKCU Uninstall keys (installed programs)
  · Filesystem — Key system/user directories (files & dirs by creation time)
  · Event Log  — MSI installer events (Event IDs 1033, 11707) [pywin32]
  · AppX       — UWP/MSIX Store packages via PowerShell
  · Prefetch   — Recently executed binaries via C:\\Windows\\Prefetch

Usage:
  python recent_tracker.py --preset 1h
  python recent_tracker.py --minutes 30
  python recent_tracker.py --hours 6  --export json
  python recent_tracker.py --days 3   --no-fs
  python recent_tracker.py --weeks 1  --export both --output report
  python recent_tracker.py --minutes 10 --scan-paths C:\\Downloads C:\\Temp
  python recent_tracker.py --preset 1d --category PROGRAM FILE
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import json
import logging
import os
import subprocess
import sys
import winreg
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, List, Optional

# ── Optional: rich output ─────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ── Optional: pywin32 (Event Log) ─────────────────────────────────────────────
try:
    import win32evtlog  # type: ignore
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


# ═════════════════════════════════════════════════════════════════════════════
# DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """Single detected item from any scanner."""
    category: str        # PROGRAM | FILE | DIRECTORY | EVENT | APPX | PREFETCH
    name: str
    path: str
    timestamp: datetime
    extra: dict = field(default_factory=dict)

    @property
    def age_str(self) -> str:
        delta = datetime.now(timezone.utc) - self.timestamp.astimezone(timezone.utc)
        s = int(delta.total_seconds())
        if s < 60:
            return f"{s}s ago"
        if s < 3600:
            return f"{s // 60}m ago"
        if s < 86400:
            return f"{s // 3600}h ago"
        return f"{s // 86400}d ago"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


# ═════════════════════════════════════════════════════════════════════════════
# BASE SCANNER
# ═════════════════════════════════════════════════════════════════════════════

class BaseScanner(ABC):
    """Abstract plugin base — all scanners inherit from this."""
    name: str = "BaseScanner"
    description: str = ""

    def __init__(self, since: datetime) -> None:
        self.since = (
            since.astimezone(timezone.utc)
            if since.tzinfo else since.replace(tzinfo=timezone.utc)
        )
        self.logger = logging.getLogger(self.__class__.__name__)

    def _is_recent(self, dt: datetime) -> bool:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt >= self.since

    @abstractmethod
    def scan(self) -> List[Finding]: ...


# ═════════════════════════════════════════════════════════════════════════════
# SCANNER 1 — REGISTRY (installed programs)
# ═════════════════════════════════════════════════════════════════════════════

class RegistryScanner(BaseScanner):
    """
    Queries HKLM and HKCU Uninstall registry hives.
    Uses key last-write time when InstallDate is absent or date-only.
    """
    name = "Registry Programs"
    description = "HKLM/HKCU Uninstall keys"

    _HIVES = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         winreg.KEY_READ | winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
         winreg.KEY_READ | winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         winreg.KEY_READ),
    ]

    @staticmethod
    def _key_write_time(key_handle) -> Optional[datetime]:
        """Convert FILETIME from QueryInfoKey to UTC datetime."""
        try:
            info = winreg.QueryInfoKey(key_handle)
            filetime = info[2]
            EPOCH_DIFF = 116_444_736_000_000_000  # 100 ns intervals 1601→1970
            unix_ts = (filetime - EPOCH_DIFF) / 10_000_000
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        except Exception:
            return None

    @staticmethod
    def _parse_install_date(raw: str) -> Optional[datetime]:
        try:
            return datetime.strptime(raw.strip(), "%Y%m%d").replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            return None

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()

        for hive, subkey_path, flags in self._HIVES:
            try:
                hive_key = winreg.OpenKey(hive, subkey_path, 0, flags)
            except OSError:
                continue

            with hive_key:
                idx = 0
                while True:
                    try:
                        sub_name = winreg.EnumKey(hive_key, idx)
                        idx += 1
                    except OSError:
                        break

                    try:
                        sub_key = winreg.OpenKey(hive_key, sub_name, 0, flags)
                    except OSError:
                        continue

                    with sub_key:
                        try:
                            display_name = winreg.QueryValueEx(sub_key, "DisplayName")[0]
                        except OSError:
                            continue

                        if not display_name or display_name in seen:
                            continue

                        # Prefer key write time (precise); fall back to InstallDate
                        effective_dt: Optional[datetime] = self._key_write_time(sub_key)
                        if effective_dt is None:
                            try:
                                raw_date = winreg.QueryValueEx(sub_key, "InstallDate")[0]
                                effective_dt = self._parse_install_date(raw_date)
                            except OSError:
                                pass

                        if effective_dt is None or not self._is_recent(effective_dt):
                            continue

                        extra: dict = {}
                        for field_name in ("DisplayVersion", "Publisher",
                                           "InstallLocation", "InstallDate"):
                            try:
                                extra[field_name] = winreg.QueryValueEx(sub_key, field_name)[0]
                            except OSError:
                                pass

                        findings.append(Finding(
                            category="PROGRAM",
                            name=display_name,
                            path=extra.get("InstallLocation", subkey_path),
                            timestamp=effective_dt,
                            extra=extra,
                        ))
                        seen.add(display_name)

        return findings


# ═════════════════════════════════════════════════════════════════════════════
# SCANNER 2 — FILESYSTEM (files & directories)
# ═════════════════════════════════════════════════════════════════════════════

class FilesystemScanner(BaseScanner):
    """
    Walks monitored directories for recently created files and directories.
    Uses os.scandir for minimal overhead; parallelised with ThreadPoolExecutor.
    On Windows, st_ctime = creation time (not Linux-style ctime).
    """
    name = "Filesystem"
    description = "Files / dirs created in monitored paths"

    _SYSTEM_PATHS = [
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\ProgramData",
        r"C:\Windows\System32\drivers",
        r"C:\Windows\SysWOW64",
    ]
    _USER_PATHS = [
        "AppData\\Local\\Programs",
        "AppData\\Roaming",
        "AppData\\Local\\Temp",
        "Downloads",
        "Desktop",
        "Documents",
    ]
    HIGH_INTEREST_EXT = {
        ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".msi", ".cab", ".inf", ".reg", ".scr", ".jar",
        ".py", ".sh", ".com", ".hta",
    }

    def __init__(
        self,
        since: datetime,
        extra_paths: Optional[List[str]] = None,
        max_depth: int = 6,
        workers: int = 4,
    ) -> None:
        super().__init__(since)
        self.max_depth = max_depth
        self.workers = workers
        self.scan_roots = self._build_roots(extra_paths or [])

    def _build_roots(self, extra: List[str]) -> List[str]:
        paths = list(self._SYSTEM_PATHS)
        home = Path(os.path.expanduser("~"))
        for rel in self._USER_PATHS:
            p = home / rel
            if p.exists():
                paths.append(str(p))
        paths.extend(extra)
        return [p for p in dict.fromkeys(paths) if os.path.isdir(p)]

    def _walk(self, root: str, depth: int) -> Iterator[os.DirEntry]:
        if depth < 0:
            return
        try:
            with os.scandir(root) as it:
                for entry in it:
                    yield entry
                    if entry.is_dir(follow_symlinks=False):
                        yield from self._walk(entry.path, depth - 1)
        except (PermissionError, OSError):
            pass

    def _scan_root(self, root: str) -> List[Finding]:
        results: List[Finding] = []
        for entry in self._walk(root, self.max_depth):
            try:
                stat = entry.stat(follow_symlinks=False)
                ctime = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc)
                if not self._is_recent(ctime):
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
                ext = Path(entry.name).suffix.lower()
                results.append(Finding(
                    category="DIRECTORY" if is_dir else "FILE",
                    name=entry.name,
                    path=entry.path,
                    timestamp=ctime,
                    extra={
                        "size_bytes": 0 if is_dir else stat.st_size,
                        "extension": ext,
                        "high_interest": ext in self.HIGH_INTEREST_EXT,
                    },
                ))
            except (PermissionError, OSError):
                continue
        return results

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._scan_root, p): p for p in self.scan_roots}
            for fut in as_completed(futures):
                try:
                    findings.extend(fut.result())
                except Exception as exc:
                    self.logger.warning("Scan error in %s: %s", futures[fut], exc)
        return findings


# ═════════════════════════════════════════════════════════════════════════════
# SCANNER 3 — WINDOWS EVENT LOG (MSI install events)
# ═════════════════════════════════════════════════════════════════════════════

class EventLogScanner(BaseScanner):
    """
    Reads Application Event Log for MsiInstaller events.
    EventID 1033 = product installed; 11707 = install success.
    Requires pywin32.
    """
    name = "Event Log"
    description = "MSI install events from Application Event Log"

    _MSI_EVENT_IDS = {1033, 11707}

    def scan(self) -> List[Finding]:
        if not HAS_PYWIN32:
            self.logger.warning("pywin32 not installed — skipping Event Log scan")
            return []

        findings: List[Finding] = []
        try:
            handle = win32evtlog.OpenEventLog(None, "Application")
            flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                     win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            while True:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break
                for event in events:
                    try:
                        event_time = datetime.fromtimestamp(
                            int(event.TimeGenerated), tz=timezone.utc
                        )
                    except Exception:
                        continue
                    if not self._is_recent(event_time):
                        continue
                    eid = event.EventID & 0xFFFF
                    if eid not in self._MSI_EVENT_IDS:
                        continue
                    if event.SourceName != "MsiInstaller":
                        continue
                    strings = list(event.StringInserts or [])
                    name = strings[0] if strings else "Unknown"
                    findings.append(Finding(
                        category="EVENT",
                        name=f"[MSI] {name}",
                        path="EventLog:Application",
                        timestamp=event_time,
                        extra={
                            "event_id": eid,
                            "source": event.SourceName,
                            "strings": strings[:5],
                        },
                    ))
            win32evtlog.CloseEventLog(handle)
        except Exception as exc:
            self.logger.warning("Event Log error: %s", exc)
        return findings


# ═════════════════════════════════════════════════════════════════════════════
# SCANNER 4 — APPX / Microsoft Store
# ═════════════════════════════════════════════════════════════════════════════

class AppxScanner(BaseScanner):
    """
    Detects recently installed UWP/MSIX packages by querying PowerShell
    Get-AppxPackage and checking InstallLocation creation time.
    """
    name = "AppX / Store"
    description = "UWP/MSIX packages via PowerShell Get-AppxPackage"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Get-AppxPackage | Select-Object Name,Version,InstallLocation"
                    " | ConvertTo-Json -Depth 2",
                ],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return findings

            packages = json.loads(result.stdout)
            if isinstance(packages, dict):
                packages = [packages]

            for pkg in packages:
                loc = pkg.get("InstallLocation", "")
                if not loc or not Path(loc).exists():
                    continue
                try:
                    ctime = datetime.fromtimestamp(
                        Path(loc).stat().st_ctime, tz=timezone.utc
                    )
                    if not self._is_recent(ctime):
                        continue
                    findings.append(Finding(
                        category="APPX",
                        name=pkg.get("Name", "Unknown"),
                        path=loc,
                        timestamp=ctime,
                        extra={"version": pkg.get("Version", "")},
                    ))
                except OSError:
                    continue
        except (subprocess.TimeoutExpired, json.JSONDecodeError,
                FileNotFoundError, Exception) as exc:
            self.logger.warning("AppX scan error: %s", exc)
        return findings


# ═════════════════════════════════════════════════════════════════════════════
# SCANNER 5 — PREFETCH (recently executed binaries)
# ═════════════════════════════════════════════════════════════════════════════

class PrefetchScanner(BaseScanner):
    """
    Checks C:\\Windows\\Prefetch for .pf files modified within the window.
    Prefetch mtime ≈ last execution time; new .pf files signal first runs.
    Requires Administrator for Prefetch directory access.
    """
    name = "Prefetch"
    description = "Recently executed binaries via Prefetch files"

    _PREFETCH_DIR = Path(r"C:\Windows\Prefetch")

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self._PREFETCH_DIR.exists():
            return findings
        try:
            for entry in os.scandir(str(self._PREFETCH_DIR)):
                if not entry.name.lower().endswith(".pf"):
                    continue
                try:
                    stat = entry.stat()
                    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                    if not self._is_recent(mtime):
                        continue
                    # PROGRAM.EXE-AABBCCDD.pf → PROGRAM.EXE
                    clean = entry.name.rsplit("-", 1)[0] if "-" in entry.name else entry.name
                    findings.append(Finding(
                        category="PREFETCH",
                        name=clean,
                        path=entry.path,
                        timestamp=mtime,
                        extra={"size_bytes": stat.st_size},
                    ))
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError) as exc:
            self.logger.warning("Prefetch scan error: %s", exc)
        return findings


# ═════════════════════════════════════════════════════════════════════════════
# OUTPUT ENGINE
# ═════════════════════════════════════════════════════════════════════════════

_CAT_COLOR = {
    "PROGRAM":   "bold green",
    "FILE":      "cyan",
    "DIRECTORY": "yellow",
    "EVENT":     "bold red",
    "APPX":      "magenta",
    "PREFETCH":  "blue",
}


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} TB"


def _build_detail(f: Finding) -> str:
    cat = f.category
    if cat == "FILE":
        hi = " ⚠ HIGH-INTEREST" if f.extra.get("high_interest") else ""
        return f"{_human_size(f.extra.get('size_bytes', 0))}{hi}"
    if cat == "PROGRAM":
        ver = f.extra.get("DisplayVersion", "")
        pub = f.extra.get("Publisher", "")
        parts = [x for x in [f"v{ver}" if ver else "", pub] if x]
        return " | ".join(parts)
    if cat == "APPX":
        ver = f.extra.get("version", "")
        return f"v{ver}" if ver else ""
    if cat == "EVENT":
        return f"EventID={f.extra.get('event_id', '')}"
    if cat == "PREFETCH":
        return _human_size(f.extra.get("size_bytes", 0))
    return ""


def render_rich(findings: List[Finding], since: datetime) -> None:
    console = Console()
    since_str = since.strftime("%Y-%m-%d %H:%M:%S UTC")
    console.print(
        f"\n[bold white]RecentInstallTracker[/]  "
        f"[dim]— since {since_str}[/]  "
        f"[bold yellow]{len(findings)} total finding(s)[/]\n"
    )

    by_cat: dict[str, List[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    for cat, items in sorted(by_cat.items()):
        color = _CAT_COLOR.get(cat, "white")
        tbl = Table(
            title=f"[{color}]{cat}[/]  [{color}]({len(items)})[/]",
            show_lines=True,
            header_style="bold",
        )
        tbl.add_column("Name", style="bold", max_width=45)
        tbl.add_column("Path", max_width=55, no_wrap=False)
        tbl.add_column("Timestamp (UTC)", style="dim", width=22)
        tbl.add_column("Age", style="italic", width=12)
        tbl.add_column("Details", max_width=40)

        for item in sorted(items, key=lambda x: x.timestamp, reverse=True):
            ts_str = item.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            detail = _build_detail(item)
            tbl.add_row(item.name, item.path, ts_str, item.age_str, detail)

        console.print(tbl)
        console.print()


def render_plain(findings: List[Finding], since: datetime) -> None:
    sep = "=" * 80
    print(f"\nRecentInstallTracker — findings since "
          f"{since.strftime('%Y-%m-%d %H:%M:%S UTC')}  [{len(findings)} total]")
    print(sep)
    by_cat: dict[str, List[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)
    for cat, items in sorted(by_cat.items()):
        print(f"\n[ {cat} ]  ({len(items)} item(s))")
        print("-" * 60)
        for item in sorted(items, key=lambda x: x.timestamp, reverse=True):
            ts = item.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            det = _build_detail(item)
            print(f"  {ts} UTC | {item.age_str:>10} | {item.name}")
            print(f"    Path : {item.path}")
            if det:
                print(f"    Info : {det}")


def export_json(findings: List[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=2, ensure_ascii=False)
    print(f"[+] JSON → {path}")


def export_csv(findings: List[Finding], path: str) -> None:
    if not findings:
        return
    fieldnames = ["category", "name", "path", "timestamp", "age", "details"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for f in findings:
            w.writerow({
                "category": f.category,
                "name": f.name,
                "path": f.path,
                "timestamp": f.timestamp.isoformat(),
                "age": f.age_str,
                "details": _build_detail(f),
            })
    print(f"[+] CSV  → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

_PRESETS: dict[str, timedelta] = {
    "1m": timedelta(minutes=1),
    "1h": timedelta(hours=1),
    "1d": timedelta(days=1),
    "1w": timedelta(weeks=1),
}

_ALL_CATEGORIES = {"PROGRAM", "FILE", "DIRECTORY", "EVENT", "APPX", "PREFETCH"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recent_tracker",
        description="RecentInstallTracker — Windows 11 recent installation monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recent_tracker.py --preset 1h
  python recent_tracker.py --preset 1m
  python recent_tracker.py --minutes 30
  python recent_tracker.py --hours 6   --export json
  python recent_tracker.py --days 3    --no-fs
  python recent_tracker.py --weeks 1   --export both --output report
  python recent_tracker.py --minutes 10 --scan-paths C:\\Downloads C:\\Temp
  python recent_tracker.py --preset 1d  --category PROGRAM FILE
        """,
    )

    # ── Time window ───────────────────────────────────────────────────────────
    tg = p.add_argument_group("Time window  (exactly one required)")
    te = tg.add_mutually_exclusive_group(required=True)
    te.add_argument("--preset", choices=list(_PRESETS),
                    help="Quick preset: 1m | 1h | 1d | 1w")
    te.add_argument("--minutes", type=float, metavar="N",
                    help="Look back N minutes")
    te.add_argument("--hours",   type=float, metavar="N",
                    help="Look back N hours")
    te.add_argument("--days",    type=float, metavar="N",
                    help="Look back N days")
    te.add_argument("--weeks",   type=float, metavar="N",
                    help="Look back N weeks")

    # ── Scanners ──────────────────────────────────────────────────────────────
    sg = p.add_argument_group("Scanner control")
    sg.add_argument("--no-registry",  action="store_true", help="Skip Registry scan")
    sg.add_argument("--no-fs",        action="store_true", help="Skip Filesystem scan")
    sg.add_argument("--no-events",    action="store_true", help="Skip Event Log scan")
    sg.add_argument("--no-appx",      action="store_true", help="Skip AppX scan")
    sg.add_argument("--no-prefetch",  action="store_true", help="Skip Prefetch scan")
    sg.add_argument("--scan-paths",   nargs="+", metavar="PATH",
                    help="Extra directories for filesystem scan")
    sg.add_argument("--max-depth",    type=int, default=6, metavar="N",
                    help="Max filesystem recursion depth (default: 6)")
    sg.add_argument("--workers",      type=int, default=4, metavar="N",
                    help="Parallel worker threads (default: 4)")

    # ── Filtering ─────────────────────────────────────────────────────────────
    fg = p.add_argument_group("Filtering")
    fg.add_argument("--category", nargs="+",
                    choices=sorted(_ALL_CATEGORIES), metavar="CAT",
                    help="Show only these categories (e.g. PROGRAM FILE)")
    fg.add_argument("--high-interest-only", action="store_true",
                    help="For FILE results, show only high-interest extensions")

    # ── Output ────────────────────────────────────────────────────────────────
    og = p.add_argument_group("Output")
    og.add_argument("--export",  choices=["json", "csv", "both"],
                    help="Export results to file")
    og.add_argument("--output",  metavar="BASENAME",
                    help="Output filename base (default: auto-generated timestamp)")
    og.add_argument("--plain",   action="store_true",
                    help="Plain text output (skips rich formatting)")
    og.add_argument("--quiet",   "-q", action="store_true",
                    help="Suppress console output (combine with --export)")
    og.add_argument("--verbose", "-v", action="store_true",
                    help="Debug-level logging")

    return p


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s [%(name)s] %(message)s",
    )

    # ── Resolve time window ───────────────────────────────────────────────────
    if args.preset:
        delta = _PRESETS[args.preset]
    elif args.minutes is not None:
        delta = timedelta(minutes=args.minutes)
    elif args.hours is not None:
        delta = timedelta(hours=args.hours)
    elif args.days is not None:
        delta = timedelta(days=args.days)
    else:
        delta = timedelta(weeks=args.weeks)

    since = datetime.now(timezone.utc) - delta

    # ── Build scanner list ────────────────────────────────────────────────────
    scanners: List[BaseScanner] = []
    if not args.no_registry:
        scanners.append(RegistryScanner(since))
    if not args.no_fs:
        scanners.append(FilesystemScanner(
            since,
            extra_paths=args.scan_paths,
            max_depth=args.max_depth,
            workers=args.workers,
        ))
    if not args.no_events:
        scanners.append(EventLogScanner(since))
    if not args.no_appx:
        scanners.append(AppxScanner(since))
    if not args.no_prefetch:
        scanners.append(PrefetchScanner(since))

    if not scanners:
        print("[-] All scanners disabled. Nothing to do.")
        return 1

    # ── Run scans ─────────────────────────────────────────────────────────────
    all_findings: List[Finding] = []

    if HAS_RICH and not args.plain and not args.quiet:
        console = Console()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as prog:
            for scanner in scanners:
                task = prog.add_task(f"Scanning: {scanner.name} …", total=None)
                all_findings.extend(scanner.scan())
                prog.remove_task(task)
    else:
        for scanner in scanners:
            if not args.quiet:
                print(f"[*] Scanning: {scanner.name} …", flush=True)
            all_findings.extend(scanner.scan())

    # ── Apply filters ─────────────────────────────────────────────────────────
    if args.category:
        wanted = set(args.category)
        all_findings = [f for f in all_findings if f.category in wanted]

    if args.high_interest_only:
        all_findings = [
            f for f in all_findings
            if f.category != "FILE" or f.extra.get("high_interest")
        ]

    # ── Console output ────────────────────────────────────────────────────────
    if not args.quiet:
        if HAS_RICH and not args.plain:
            render_rich(all_findings, since)
        else:
            render_plain(all_findings, since)

    # ── File export ───────────────────────────────────────────────────────────
    if args.export:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = str(Path(args.output or f"recent_install_{ts}").with_suffix(""))
        if args.export in ("json", "both"):
            export_json(all_findings, f"{base}.json")
        if args.export in ("csv", "both"):
            export_csv(all_findings, f"{base}.csv")

    # ── Summary ───────────────────────────────────────────────────────────────
    if not args.quiet:
        by_cat = {}
        for f in all_findings:
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
        summary = "  ".join(f"{cat}:{n}" for cat, n in sorted(by_cat.items()))
        print(f"\n[+] Total: {len(all_findings)}  ({summary})\n")

    return 0


if __name__ == "__main__":
    if sys.platform != "win32":
        print("[-] RecentInstallTracker requires Windows 11.")
        sys.exit(1)

    # Non-blocking elevation warning
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False

    if not is_admin:
        print(
            "[!] Warning: not running as Administrator.\n"
            "    Prefetch and some registry keys may be inaccessible.\n"
            "    Re-run from an elevated prompt for full coverage.\n"
        )

    sys.exit(main())
