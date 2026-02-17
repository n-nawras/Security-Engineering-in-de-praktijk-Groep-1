#!/usr/bin/env python3
"""
Network Scanner

Scans a single host or a subnet to discover active hosts, open TCP ports,
associated services, MAC addresses, and optional service banners.

This implementation does not rely on external scanning libraries such as nmap
and follows PEP 8 coding standards.

Author: Student
"""

import argparse
import ipaddress
import json
import platform
import re
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Dict


# -----------------------------
# Command-line interface
# -----------------------------
def parse_args() -> argparse.Namespace:
    """
    Parse and validate command-line arguments.

    :return: Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(description="Custom Network Scanner")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Scan a single host (e.g. 192.168.0.1)")
    group.add_argument("--subnet", help="Scan a subnet in CIDR notation (e.g. 192.168.0.0/24)")

    parser.add_argument("--limit", type=int, default=49,
                        help="Maximum number of hosts to scan in subnet mode")
    parser.add_argument("--ports", default="",
                        help="Ports to scan (e.g. 22,80,443 or 1-1024)")
    parser.add_argument("--top-ports", type=int, default=0,
                        help="Scan top N common ports (0 disables)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Timeout in seconds for ping and TCP connections")
    parser.add_argument("--workers", type=int, default=200,
                        help="Number of threads used for port scanning")
    parser.add_argument("--banner", action="store_true",
                        help="Attempt to grab service banners from open ports")
    parser.add_argument("--output", default="",
                        help="Write scan results to a JSON file")

    return parser.parse_args()


# -----------------------------
# Target selection and discovery
# -----------------------------
def build_targets(args: argparse.Namespace) -> List[str]:
    """
    Build a list of target IP addresses based on user input.

    :param args: Parsed command-line arguments
    :return: List of target IP addresses
    """
    if args.host:
        return [args.host]

    network = ipaddress.ip_network(args.subnet, strict=False)
    targets: List[str] = []

    for ip in network.hosts():
        targets.append(str(ip))
        if len(targets) >= args.limit:
            break

    return targets


def ping_once(ip: str, timeout: float) -> bool:
    """
    Perform a single ICMP echo request to test host availability.

    :param ip: Target IP address
    :param timeout: Timeout in seconds
    :return: True if host responds, False otherwise
    """
    system = platform.system().lower()

    if system.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]

    result = subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def discover_alive(targets: List[str], timeout: float) -> List[str]:
    """
    Perform host discovery on a list of targets.

    :param targets: List of IP addresses
    :param timeout: Ping timeout in seconds
    :return: List of responsive hosts
    """
    alive: List[str] = []

    for index, ip in enumerate(targets, start=1):
        is_alive = ping_once(ip, timeout)
        print(f"[DISCOVERY] {index}/{len(targets)} ping {ip} ... "
              f"{'OK' if is_alive else 'no reply'}")

        if is_alive:
            alive.append(ip)

    return alive


# -----------------------------
# Port scanning
# -----------------------------
COMMON_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 8080
]


def parse_ports(port_string: str) -> List[int]:
    """
    Parse a port specification string.

    :param port_string: Port list or range string
    :return: List of ports
    """
    if not port_string:
        return []

    port_string = port_string.strip()

    def to_int(value: str) -> int:
        if not value.isdigit():
            raise ValueError(f"Invalid port '{value}'")
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError(f"Port '{value}' out of range")
        return port

    if "-" in port_string:
        start, end = port_string.split("-", 1)
        start_port = to_int(start)
        end_port = to_int(end)
        return list(range(min(start_port, end_port), max(start_port, end_port) + 1))

    return [to_int(p.strip()) for p in port_string.split(",") if p.strip()]


def select_ports(args: argparse.Namespace) -> List[int]:
    """
    Select ports to scan based on user input.

    :param args: Parsed arguments
    :return: List of ports to scan
    """
    explicit_ports = parse_ports(args.ports)
    if explicit_ports:
        return explicit_ports

    if args.top_ports > 0:
        if args.top_ports <= len(COMMON_TOP_PORTS):
            return COMMON_TOP_PORTS[:args.top_ports]
        return list(range(1, args.top_ports + 1))

    return [22, 80, 443, 445, 3389]


def scan_ports(ip: str, ports: List[int], timeout: float,
               workers: int) -> List[int]:
    """
    Perform a TCP connect scan on a list of ports.

    :param ip: Target IP address
    :param ports: Ports to scan
    :param timeout: Socket timeout
    :param workers: Number of threads
    :return: List of open ports
    """
    def check(port: int) -> Optional[int]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                return port if sock.connect_ex((ip, port)) == 0 else None
        except OSError:
            return None

    if not ports:
        return []

    open_ports: List[int] = []
    max_workers = min(workers, len(ports))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for result in executor.map(check, ports):
            if result is not None:
                open_ports.append(result)

    return sorted(open_ports)


def service_name(port: int) -> str:
    """
    Resolve the service name for a TCP port.

    :param port: TCP port number
    :return: Service name or 'unknown'
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# -----------------------------
# MAC address resolution
# -----------------------------
def get_mac(ip: str) -> Optional[str]:
    """
    Retrieve the MAC address of a host from the local ARP cache.

    :param ip: Target IP address
    :return: MAC address or None
    """
    system = platform.system().lower()

    try:
        if system.startswith("win"):
            output = subprocess.check_output(
                ["arp", "-a", ip], text=True, errors="ignore"
            )
            match = re.search(
                rf"^\s*{re.escape(ip)}\s+([0-9a-fA-F-]{{17}})\s",
                output,
                re.MULTILINE
            )
            return match.group(1).lower() if match else None

        output = subprocess.check_output(
            ["ip", "neigh", "show", ip], text=True, errors="ignore"
        )
        match = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", output)
        return match.group(1).lower() if match else None

    except Exception:
        return None


# -----------------------------
# Banner grabbing (optional)
# -----------------------------
def clean_banner(text: str, limit: int = 90) -> str:
    """
    Sanitize and truncate banner text.

    :param text: Raw banner text
    :param limit: Maximum length
    :return: Cleaned banner string
    """
    printable = "".join(ch for ch in text if ch.isprintable())
    return " ".join(printable.split())[:limit]


def grab_banner(ip: str, port: int, timeout: float) -> Optional[str]:
    """
    Attempt to retrieve a service banner from an open port.

    :param ip: Target IP address
    :param port: TCP port
    :param timeout: Socket timeout
    :return: Banner string or None
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
            except OSError:
                data = b""

            if not data:
                try:
                    sock.sendall(b"\r\n")
                    data = sock.recv(256)
                except OSError:
                    return None

            return clean_banner(data.decode(errors="ignore")) if data else None

    except OSError:
        return None


# -----------------------------
# Main program
# -----------------------------
def main() -> int:
    """
    Entry point of the network scanner.

    :return: Exit status code
    """
    args = parse_args()
    start_time = time.perf_counter()

    results: Dict[str, object] = {"hosts": []}

    targets = build_targets(args)
    print(f"Targets count: {len(targets)}")

    alive_hosts = discover_alive(targets, args.timeout)
    ports = select_ports(args)

    for ip in alive_hosts:
        mac = get_mac(ip) or "unknown"
        open_ports = scan_ports(ip, ports, args.timeout, args.workers)

        details: List[str] = []
        for port in open_ports:
            svc = service_name(port)
            if args.banner:
                banner = grab_banner(ip, port, args.timeout)
                if banner:
                    details.append(f"{port}({svc}) banner='{banner}'")
                else:
                    details.append(f"{port}({svc})")
            else:
                details.append(f"{port}({svc})")

        print(f"- {ip:<15} MAC={mac:<17} open TCP: "
              f"{', '.join(details) if details else '-'}")

        results["hosts"].append({
            "ip": ip,
            "mac": mac,
            "open_tcp_ports": open_ports
        })

    runtime = time.perf_counter() - start_time
    results["runtime_seconds"] = round(runtime, 2)

    print(f"\nRuntime: {runtime:.2f}s")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as file:
            json.dump(results, file, indent=2)
        print(f"[OK] Results written to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
