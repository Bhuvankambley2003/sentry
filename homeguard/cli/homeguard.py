#!/usr/bin/env python3
"""HomeGuard CLI — start | stop | status | scan | devices | changes"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from rich.markup import escape

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from libs.common.config import get_settings
from services.api_gateway.auth import get_or_create_token

app = typer.Typer(name="homeguard", help="HomeGuard — who's on my Wi-Fi?", add_completion=False)
console = Console()
settings = get_settings()

PID_DIR = Path("~/.homeguard").expanduser()
TOKEN_PATH = settings.token_file.expanduser()


def _api(token: str) -> httpx.Client:
    base = f"http://{settings.api_host}:{settings.api_port}"
    return httpx.Client(base_url=base, headers={"X-HomeGuard-Token": token}, timeout=10.0)


def _load_token() -> str | None:
    if TOKEN_PATH.exists():
        t = TOKEN_PATH.read_text().strip()
        return t or None
    return None


def _pid_file(svc: str) -> Path:
    return PID_DIR / f"{svc}.pid"


def _write_pid(svc: str, pid: int) -> None:
    PID_DIR.mkdir(parents=True, exist_ok=True)
    _pid_file(svc).write_text(str(pid))


def _read_pid(svc: str) -> int | None:
    p = _pid_file(svc)
    if p.exists():
        try:
            return int(p.read_text().strip())
        except Exception:
            return None
    return None


def _is_running(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


# In order of startup dependencies
SERVICES_ORDER = [
    ("inventory",   settings.inventory_port,  False),
    ("scanner",     settings.scanner_port,    True),   # may need sudo for raw sockets
    ("api_gateway", settings.api_port,        False),
]


def _start_service(name: str, port: int, use_sudo: bool, no_sudo: bool) -> subprocess.Popen:  # type: ignore[type-arg]
    module = f"services.{name}.main"
    cmd = [sys.executable, "-m", module]

    if name == "scanner" and no_sudo:
        cmd.append("--no-sudo")

    if use_sudo and not no_sudo:
        cmd = ["sudo", "-E"] + cmd

    repo_root = str(Path(__file__).resolve().parents[1])
    proc = subprocess.Popen(
        cmd,
        cwd=repo_root,
        env={**os.environ, "PYTHONPATH": repo_root},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _write_pid(name, proc.pid)
    return proc


def _wait_for_service(port: int, timeout: int = 15) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = httpx.get(f"http://127.0.0.1:{port}/health", timeout=1.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


@app.command()
def start(no_sudo: bool = typer.Option(False, "--no-sudo", help="Don't use sudo for ARP scanner")) -> None:
    """Start Redis check and all HomeGuard services."""
    # Check Redis first so services don't immediately crash on bus connect
    try:
        import redis
        r = redis.from_url(settings.redis_url)
        r.ping()
        r.close()
        console.print("[green]✓ Redis is running[/green]")
    except Exception:
        console.print("[red]✗ Redis is not running. Run: brew install redis && brew services start redis[/red]")
        raise typer.Exit(1)

    token = get_or_create_token()
    console.print(f"[bold]API Token:[/bold] {token}")

    for name, port, needs_sudo in SERVICES_ORDER:
        pid = _read_pid(name)
        if _is_running(pid):
            console.print(f"[yellow]⚠ {name} already running (pid {pid})[/yellow]")
            continue

        console.print(f"[blue]→ Starting {name}...[/blue]", end=" ")
        proc = _start_service(name, port, needs_sudo, no_sudo)
        if _wait_for_service(port):
            console.print(f"[green]✓ (pid {proc.pid})[/green]")
        else:
            console.print(f"[red]✗ (pid {proc.pid}, may still be starting)[/red]")

    console.print(f"\n[bold green]HomeGuard running![/bold green]")
    console.print(f"  API:  http://{settings.api_host}:{settings.api_port}/docs")
    console.print(f"  Token: {token}")
    console.print(f"\nUse [bold]homeguard scan[/bold] to discover devices.")


@app.command()
def stop() -> None:
    """Gracefully stop all HomeGuard services."""
    # Record timestamp so next session diff can compute delta
    token = _load_token()
    if token:
        try:
            with _api(token) as client:
                client.put(
                    f"/api/v1/settings/last_session_end",
                    json={"value": datetime.now(timezone.utc).isoformat()},
                )
        except Exception:
            pass

    for name, port, _ in reversed(SERVICES_ORDER):
        pid = _read_pid(name)
        if _is_running(pid):
            assert pid is not None
            try:
                os.kill(pid, signal.SIGTERM)
                console.print(f"[green]✓ Stopped {name} (pid {pid})[/green]")
            except Exception as exc:
                console.print(f"[red]✗ Could not stop {name}: {exc}[/red]")
            _pid_file(name).unlink(missing_ok=True)
        else:
            console.print(f"[dim]{name} not running[/dim]")


@app.command()
def status() -> None:
    """Show health status of all services."""
    table = Table(title="HomeGuard Service Status", show_header=True)
    table.add_column("Service", style="bold")
    table.add_column("Port")
    table.add_column("PID")
    table.add_column("Process")
    table.add_column("HTTP Health")

    all_services = [
        ("inventory",   settings.inventory_port),
        ("scanner",     settings.scanner_port),
        ("api_gateway", settings.api_port),
        ("discovery",   settings.discovery_port),
        ("identity",    settings.identity_port),
        ("trust",       settings.trust_port),
        ("notifier",    settings.notifier_port),
    ]

    for name, port in all_services:
        pid = _read_pid(name)
        proc_status = "[green]running[/green]" if _is_running(pid) else "[red]stopped[/red]"
        pid_str = str(pid) if pid else "-"
        try:
            r = httpx.get(f"http://127.0.0.1:{port}/health", timeout=1.0)
            http_status = f"[green]OK {r.status_code}[/green]"
        except Exception:
            http_status = "[red]unreachable[/red]"
        table.add_row(name, str(port), pid_str, proc_status, http_status)

    console.print(table)


@app.command()
def scan(full: bool = typer.Option(False, "--full", help="Full scan (same as quick for now)")) -> None:
    """Trigger a network scan and stream progress."""
    token = _load_token()
    if not token:
        console.print("[red]HomeGuard is not running. Run: homeguard start[/red]")
        raise typer.Exit(1)

    scan_type = "full" if full else "quick"
    with _api(token) as client:
        resp = client.post(f"/api/v1/scans", json={"type": scan_type})
        if resp.status_code not in (200, 201, 202):
            console.print(f"[red]Scan failed: {resp.text}[/red]")
            raise typer.Exit(1)
        scan_data = resp.json()
        scan_id = scan_data.get("id")
        console.print(f"[blue]Scan {scan_id} started...[/blue]")

        # Poll scan progress until completed or timed out
        for _ in range(60):
            time.sleep(2)
            r = client.get(f"/api/v1/scans/{scan_id}")
            if r.status_code == 200:
                data = r.json()
                if data.get("status") in ("completed", "failed"):
                    console.print(f"[green]✓ Scan complete: {data.get('devices_found', 0)} devices found[/green]")
                    break
                console.print(f"[dim]  status: {data.get('status')}...[/dim]")
        else:
            console.print("[yellow]Scan still running (timed out waiting). Use 'homeguard devices' to see results.[/yellow]")


@app.command()
def devices() -> None:
    """List all known devices with trust scores."""
    token = _load_token()
    if not token:
        console.print("[red]HomeGuard is not running. Run: homeguard start[/red]")
        raise typer.Exit(1)

    with _api(token) as client:
        resp = client.get("/api/v1/devices")
        if resp.status_code != 200:
            console.print(f"[red]Failed: {resp.text}[/red]")
            raise typer.Exit(1)
        devs = resp.json()

    table = Table(title=f"HomeGuard Devices ({len(devs)} found)", show_header=True)
    table.add_column("IP", style="cyan")
    table.add_column("MAC")
    table.add_column("Vendor")
    table.add_column("Type")
    table.add_column("Hostname / Label")
    table.add_column("Score", justify="right")
    table.add_column("Band")
    table.add_column("Status")
    table.add_column("Online")

    def _band_color(score: int) -> str:
        if score >= 80:
            return f"[green]{score}[/green]"
        if score >= 50:
            return f"[yellow]{score}[/yellow]"
        if score >= 25:
            return f"[orange3]{score}[/orange3]"
        return f"[red]{score}[/red]"

    def _band_label(score: int) -> str:
        if score >= 80:
            return "Trusted"
        if score >= 50:
            return "Prob. fine"
        if score >= 25:
            return "Attention"
        return "Suspicious"

    for d in sorted(devs, key=lambda x: x.get("trust_score", 50)):
        score = d.get("trust_score", 50)
        label = d.get("user_label") or d.get("hostname") or "-"
        online_str = "[green]●[/green]" if d.get("online") else "[dim]○[/dim]"
        table.add_row(
            d.get("current_ip") or "-",
            escape(d.get("current_mac", "")),
            (d.get("vendor") or "Unknown")[:20],
            d.get("device_type", "unknown"),
            escape(label[:30]),
            _band_color(score),
            _band_label(score),
            d.get("status", "unknown"),
            online_str,
        )

    console.print(table)


@app.command()
def changes() -> None:
    """Show what changed since the last HomeGuard session."""
    token = _load_token()
    if not token:
        console.print("[red]HomeGuard is not running. Run: homeguard start[/red]")
        raise typer.Exit(1)

    with _api(token) as client:
        # Check when last session stopped
        resp = client.get("/api/v1/settings/last_session_end")
        since_str = None
        if resp.status_code == 200:
            since_str = resp.json().get("value")

        if not since_str:
            console.print("[yellow]No previous session recorded. Starting from 24h ago.[/yellow]")
            from datetime import timedelta
            since = datetime.now(timezone.utc) - timedelta(hours=24)
        else:
            since = datetime.fromisoformat(since_str)

        console.print(f"[dim]Changes since {since.isoformat()}[/dim]\n")

        resp = client.get("/api/v1/changes", params={"since": since.isoformat()})
        if resp.status_code != 200:
            console.print(f"[red]Failed: {resp.text}[/red]")
            raise typer.Exit(1)
        data = resp.json()

    def _print_section(title: str, devs: list[dict[str, Any]], color: str) -> None:
        if not devs:
            return
        console.print(f"\n[{color}]{title} ({len(devs)})[/{color}]")
        for d in devs:
            label = d.get("user_label") or d.get("hostname") or d.get("current_mac", "?")
            console.print(f"  • {label} — {d.get('current_ip', '?')} — score {d.get('trust_score', '?')}")

    _print_section("🆕 New devices", data.get("new_devices", []), "green")
    _print_section("👻 Gone devices", data.get("gone_devices", []), "yellow")
    _print_section("🔄 Changed devices", data.get("changed_devices", []), "blue")

    if not any(data.get(k) for k in ("new_devices", "gone_devices", "changed_devices")):
        console.print("[green]No changes since last session.[/green]")


if __name__ == "__main__":
    app()
