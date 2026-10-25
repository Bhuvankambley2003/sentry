"""ARP sweep using Scapy (requires root) with a native sysctl / ping-sweep fallback."""
from __future__ import annotations

import asyncio
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

from libs.common.logging import get_logger

logger = get_logger(__name__, service="scanner")
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="arp")


@dataclass
class HostResult:
    ip: str
    mac: str
    hostname: str | None = None


# Privileged ARP sweep via Scapy raw sockets (requires root/sudo)
def _scapy_arp_sweep(subnet: str) -> list[HostResult]:
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
        import scapy.config

        scapy.config.conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(pkt, timeout=3, iface_hint=None, inter=0.01)

        results = []
        for sent, received in answered:
            results.append(HostResult(ip=received.psrc, mac=received.hwsrc.upper()))
        logger.info("ARP sweep done", extra={"subnet": subnet, "found": len(results)})
        return results
    except Exception as exc:
        logger.warning("Scapy ARP sweep failed", extra={"exc": str(exc)})
        return []


# macOS single-digit hex formatter (e.g. 3e:64:cf:f:7:a5 -> 3E:64:CF:0F:07:A5)
def _normalize_mac(raw: str) -> str:
    return ":".join(f"{int(part, 16):02X}" for part in raw.split(":"))


def _ping_one(ip: str) -> bool:
    try:
        # 500ms timeout is plenty for local LAN; forces kernel to generate ARP request
        subprocess.run(
            ["ping", "-c", "1", "-W", "500", ip],
            capture_output=True,
            timeout=2,
        )
        return True
    except Exception:
        return False


def _read_arp_table() -> list[HostResult]:
    """Read macOS ARP entries natively via BSD sysctl, falling back to CLI if needed."""
    results: list[HostResult] = []
    seen_ips: set[str] = set()

    # 1. Native macOS sysctl (NET_RT_FLAGS, RTF_LLINFO) — works without sudo
    try:
        import ctypes
        import socket
        import struct

        libc = ctypes.CDLL("/usr/lib/libc.dylib")
        # CTL_NET=4, PF_ROUTE=17, AF_INET=2, NET_RT_FLAGS=2, RTF_LLINFO=0x400
        mib = (ctypes.c_int * 6)(4, 17, 0, 2, 2, 0x400)
        needed = ctypes.c_size_t(0)

        if libc.sysctl(mib, 6, None, ctypes.byref(needed), None, 0) == 0 and needed.value > 0:
            buf = ctypes.create_string_buffer(needed.value)
            if libc.sysctl(mib, 6, buf, ctypes.byref(needed), None, 0) == 0:
                raw = buf.raw[:needed.value]
                offset = 0

                while offset < len(raw):
                    if offset + 2 > len(raw):
                        break
                    msglen, = struct.unpack_from("=H", raw, offset)
                    if msglen == 0 or offset + msglen > len(raw):
                        break
                    msg = raw[offset:offset+msglen]
                    offset += msglen

                    # macOS Darwin rt_msghdr alignment (varies between 92 and 96 on arm64/x86_64)
                    for hdr_size in (92, 96, 136):
                        if len(msg) > hdr_size + 16:
                            sa_len, sa_family = struct.unpack_from("=BB", msg, hdr_size)
                            if sa_len == 16 and sa_family == 2:
                                ip = socket.inet_ntoa(msg[hdr_size+4:hdr_size+8])
                                dl_off = hdr_size + 16
                                if len(msg) > dl_off + 8:
                                    sdl_len, sdl_family = struct.unpack_from("=BB", msg, dl_off)
                                    if sdl_family == 18 and sdl_len >= 8:
                                        _, _, sdl_nlen, sdl_alen, _ = struct.unpack_from("=HBBBB", msg, dl_off + 2)
                                        if sdl_alen == 6 and len(msg) >= dl_off + 8 + sdl_nlen + 6:
                                            mac_bytes = msg[dl_off + 8 + sdl_nlen : dl_off + 8 + sdl_nlen + 6]
                                            norm_mac = ":".join(f"{b:02X}" for b in mac_bytes)
                                            # Filter out broadcast and multicast
                                            if (
                                                norm_mac != "FF:FF:FF:FF:FF:FF"
                                                and not norm_mac.startswith("01:00:5E")
                                                and not ip.startswith("224.")
                                                and not ip.startswith("239.")
                                                and not ip.endswith(".255")
                                                and ip not in seen_ips
                                            ):
                                                seen_ips.add(ip)
                                                results.append(HostResult(ip=ip, mac=norm_mac))
                                break
        if results:
            return results
    except Exception as exc:
        logger.debug("Native sysctl ARP lookup failed, trying CLI fallback", extra={"exc": str(exc)})

    # 2. Fallback: parse `arp -an` output
    try:
        out = subprocess.check_output(["arp", "-an"], stderr=subprocess.DEVNULL, timeout=5).decode()
        for line in out.splitlines():
            import re
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", line)
            if m:
                ip, raw_mac = m.group(1), m.group(2)
                norm_mac = _normalize_mac(raw_mac)
                if (
                    norm_mac != "FF:FF:FF:FF:FF:FF"
                    and not norm_mac.startswith("01:00:5E")
                    and not ip.startswith("224.")
                    and not ip.startswith("239.")
                    and not ip.endswith(".255")
                    and ip not in seen_ips
                ):
                    seen_ips.add(ip)
                    results.append(HostResult(ip=ip, mac=norm_mac))
    except Exception as exc:
        logger.warning("arp -an failed", extra={"exc": str(exc)})

    return results


def _ping_sweep(subnet: str) -> list[HostResult]:
    """Ping subnet concurrently to excite kernel ARP cache, then read tables."""
    import ipaddress
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        hosts = list(net.hosts())
        # Cap to /24 to keep latency manageable
        if len(hosts) > 512:
            logger.warning("Subnet too large for ping sweep, trimming to /24", extra={"subnet": subnet})
            hosts = hosts[:254]
        with ThreadPoolExecutor(max_workers=50, thread_name_prefix="ping") as pool:
            list(pool.map(_ping_one, [str(h) for h in hosts]))
    except Exception as exc:
        logger.error("Ping sweep error", extra={"exc": str(exc)})

    return _read_arp_table()


# Public entrypoint
async def arp_sweep(subnet: str, privileged: bool = True) -> list[HostResult]:
    """Run ARP sweep (Scapy) or fallback unprivileged sysctl ping sweep."""
    loop = asyncio.get_event_loop()
    if privileged:
        results = await loop.run_in_executor(_executor, _scapy_arp_sweep, subnet)
        if results:
            return results
    # Fall back to unprivileged sysctl if Scapy returns nothing or non-root
    logger.info("Using ping sweep fallback")
    return await loop.run_in_executor(_executor, _ping_sweep, subnet)
