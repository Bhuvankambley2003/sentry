"""Detect local subnet, gateway, and active interface on macOS."""
from __future__ import annotations

import re
import socket
import subprocess
from dataclasses import dataclass

from libs.common.logging import get_logger

logger = get_logger(__name__, service="scanner")


@dataclass
class NetworkInfo:
    interface: str
    local_ip: str
    subnet: str  # CIDR notation, e.g. 192.168.1.0/24
    gateway_ip: str | None = None
    ssid: str | None = None


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=5).decode()
    except Exception:
        return ""


def get_network_info() -> NetworkInfo | None:
    """Detect the active Wi-Fi / Ethernet interface and derive subnet."""
    # Try to find default route interface
    route_output = _run(["route", "-n", "get", "default"])
    iface = None
    gateway = None
    for line in route_output.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            iface = line.split()[-1]
        if line.startswith("gateway:"):
            gateway = line.split()[-1]

    if not iface:
        # Fallback: pick first non-loopback with an IP
        import netifaces
        for name in netifaces.interfaces():
            if name.startswith("lo"):
                continue
            addrs = netifaces.ifaddresses(name)
            if netifaces.AF_INET in addrs:
                iface = name
                break

    if not iface:
        logger.error("Could not detect network interface")
        return None

    # Get IP and netmask via ifconfig
    ifconfig = _run(["ifconfig", iface])
    local_ip = None
    netmask = None
    for line in ifconfig.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            parts = line.split()
            local_ip = parts[1]
            # netmask may be hex (0xffffff00) or dotted
            nm_idx = parts.index("netmask") + 1 if "netmask" in parts else None
            if nm_idx:
                nm = parts[nm_idx]
                if nm.startswith("0x"):
                    nm_int = int(nm, 16)
                    netmask = ".".join(str((nm_int >> (8 * i)) & 0xFF) for i in reversed(range(4)))
                else:
                    netmask = nm
            break

    if not local_ip:
        logger.error("Could not determine local IP", extra={"interface": iface})
        return None

    subnet = _ip_netmask_to_cidr(local_ip, netmask or "255.255.255.0")

    # SSID (best-effort, may need permissions on newer macOS)
    ssid: str | None = None
    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    airport_out = _run([airport_path, "-I"])
    for line in airport_out.splitlines():
        if " SSID:" in line:
            ssid = line.split("SSID:")[-1].strip()
            break

    return NetworkInfo(
        interface=iface,
        local_ip=local_ip,
        subnet=subnet,
        gateway_ip=gateway,
        ssid=ssid,
    )


def _ip_netmask_to_cidr(ip: str, netmask: str) -> str:
    """Convert IP + netmask to CIDR network address (e.g. 192.168.1.0/24)."""
    import ipaddress
    try:
        net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(net)
    except Exception:
        return f"{ip}/24"
