#!/usr/bin/env python3
"""
Network Scanner
Scans a single host or a subnet to discover IP, MAC, open ports,
services and operating system.

Author: Student
"""

import argparse
import socket
from scapy.all import ARP, Ether, srp
import nmap


def parse_arguments():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Simple Network Scanner")
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP or subnet (e.g. 192.168.0.10 or 192.168.0.0/24)"
    )
    return parser.parse_args()


def arp_scan(target):
    """
    Perform an ARP scan to discover live hosts.

    :param target: IP address or subnet
    :return: list of dictionaries with ip and mac
    """
    arp_request = ARP(pdst=target)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered = srp(packet, timeout=2, verbose=False)[0]

    hosts = []
    for sent, received in answered:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return hosts


def scan_ports(ip, ports):
    """
    Scan TCP ports on a host.

    :param ip: IP address
    :param ports: list of ports
    :return: list of open ports
    """
    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                open_ports.append(port)
        except socket.error:
            pass

    return open_ports


def nmap_scan(ip):
    """
    Use nmap to detect OS and services.

    :param ip: IP address
    :return: tuple (os, services)
    """
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-O -sV")

    os_name = "Unknown"
    services = {}

    if "osmatch" in nm[ip] and nm[ip]["osmatch"]:
        os_name = nm[ip]["osmatch"][0]["name"]

    if "tcp" in nm[ip]:
        for port in nm[ip]["tcp"]:
            service = nm[ip]["tcp"][port]["name"]
            services[port] = service

    return os_name, services


def resolve_hostname(ip):
    """
    Resolve hostname for an IP address.

    :param ip: IP address
    :return: hostname or 'Unknown'
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"


def main():
    """
    Main function.
    """
    args = parse_arguments()
    target = args.target

    print(f"\nScanning target: {target}\n")

    hosts = arp_scan(target)

    if not hosts:
        print("No hosts found.")
        return

    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]

    for host in hosts:
        ip = host["ip"]
        mac = host["mac"]
        hostname = resolve_hostname(ip)

        print("-" * 50)
        print(f"IP Address : {ip}")
        print(f"MAC Address: {mac}")
        print(f"Hostname   : {hostname}")

        open_ports = scan_ports(ip, ports_to_scan)
        print(f"Open Ports : {open_ports if open_ports else 'None'}")

        os_name, services = nmap_scan(ip)
        print(f"OS         : {os_name}")

        if services:
            print("Services:")
            for port, service in services.items():
                print(f"  Port {port}: {service}")
        else:
            print("Services   : None")

    print("\nScan completed.\n")


if __name__ == "__main__":
    main()
