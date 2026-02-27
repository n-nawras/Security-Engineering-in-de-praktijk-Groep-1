import argparse
import socket
from scapy.all import ARP, Ether, srp
import nmap

def parse_command_line_arguments():
    """
    Parse command-line arguments provided by the user.

    The user must provide a target:
    - a single IP address (e.g. 192.168.0.10)
    - or a subnet (e.g. 192.168.0.0/24)

    Returns:
        argparse.Namespace containing the target
    """
    # Create the argument parser object
    argument_parser = argparse.ArgumentParser(
        description="Simple Network Scanner"
    )

    # Add required target argument
    argument_parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP address or subnet"
    )

    # Parse and return the arguments
    return argument_parser.parse_args()

def perform_arp_scan(target_network):
    """
    Perform an ARP scan to discover live hosts on the network.

    How it works:
    - Sends an ARP request to all IPs in the target network
    - Uses a broadcast MAC address
    - Devices that reply are considered online

    Args:
        target_network (str): IP address or subnet

    Returns:
        list: list of dictionaries with IP and MAC addresses
    """
    # Create an ARP request packet for the target network
    arp_request_packet = ARP(pdst=target_network)

    # Create an Ethernet frame with broadcast MAC address
    ethernet_broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine Ethernet frame and ARP request
    combined_packet = ethernet_broadcast_frame / arp_request_packet

    # Send the packet and receive responses
    answered_packets = srp(
        combined_packet,
        timeout=2,
        verbose=False
    )[0]

    # List to store discovered hosts
    discovered_hosts = []

    # Loop through all answered packets
    for sent_packet, received_packet in answered_packets:
        # Store IP and MAC address of each responding host
        discovered_hosts.append({
            "ip_address": received_packet.psrc,
            "mac_address": received_packet.hwsrc
        })

    return discovered_hosts

def scan_tcp_ports(target_ip, port_list):
    """
    Scan a list of TCP ports on a target host.

    How it works:
    - Tries to establish a TCP connection to each port
    - If connect_ex returns 0, the port is open

    Args:
        target_ip (str): IP address of the host
        port_list (list): list of port numbers

    Returns:
        list: open TCP ports
    """
    # List to store open ports
    open_tcp_ports = []

    # Loop through all ports to scan
    for port_number in port_list:
        try:
            # Create a TCP socket
            tcp_socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            # Set timeout to avoid long waits
            tcp_socket.settimeout(0.5)

            # Try to connect to the target IP and port
            connection_result = tcp_socket.connect_ex(
                (target_ip, port_number)
            )

            # Close the socket after the attempt
            tcp_socket.close()

            # If result is 0, the port is open
            if connection_result == 0:
                open_tcp_ports.append(port_number)

        except socket.error:
            # Ignore socket errors and continue scanning
            pass

    return open_tcp_ports

def perform_nmap_scan(target_ip):
    """
    Use nmap to detect the operating system and running services.

    Args:
        target_ip (str): IP address of the host

    Returns:
        tuple:
            - operating_system (str)
            - services (dict)
    """
    # Create nmap scanner object
    nmap_scanner = nmap.PortScanner()

    # Run OS detection and service version scan
    nmap_scanner.scan(
        target_ip,
        arguments="-O -sV"
    )

    # Default values
    operating_system = "Unknown"
    detected_services = {}

    # Try to detect operating system
    if "osmatch" in nmap_scanner[target_ip] and nmap_scanner[target_ip]["osmatch"]:
        operating_system = nmap_scanner[target_ip]["osmatch"][0]["name"]

    # Detect services running on TCP ports
    if "tcp" in nmap_scanner[target_ip]:
        for port_number in nmap_scanner[target_ip]["tcp"]:
            service_name = nmap_scanner[target_ip]["tcp"][port_number]["name"]
            detected_services[port_number] = service_name

    return operating_system, detected_services

def resolve_dns_hostname(ip_address):
    """
    Resolve the hostname for a given IP address using DNS.

    Args:
        ip_address (str)

    Returns:
        str: hostname or 'Unknown'
    """
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "Unknown"

def main():
    """
    Main program logic:
    - Read user input
    - Perform ARP scan
    - Scan ports
    - Detect OS and services
    - Display results
    """
    # Parse command-line arguments
    arguments = parse_command_line_arguments()

    # Extract target from arguments
    target_network = arguments.target

    print("\nScanning target:", target_network, "\n")

    # Perform ARP scan to find active hosts
    hosts = perform_arp_scan(target_network)

    # If no hosts are found, stop the program
    if not hosts:
        print("No active hosts found.")
        return

    # Define commonly used ports to scan
    common_ports = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        139,   # NetBIOS
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        3389   # RDP
    ]

    # Loop through each discovered host
    for host in hosts:
        # Extract IP and MAC address from host dictionary
        ip_address = host["ip_address"]
        mac_address = host["mac_address"]

        # Resolve hostname using DNS
        hostname = resolve_dns_hostname(ip_address)

        print("-" * 50)
        print("IP Address :", ip_address)
        print("MAC Address:", mac_address)
        print("Hostname   :", hostname)

        # Scan TCP ports on the host
        open_ports = scan_tcp_ports(ip_address, common_ports)
        print("Open Ports :", open_ports if open_ports else "None")

        # Perform nmap scan for OS and services
        operating_system, services = perform_nmap_scan(ip_address)
        print("Operating System:", operating_system)

        # Display detected services
        if services:
            print("Services:")
            for port, service in services.items():
                print(f"  Port {port}: {service}")
        else:
            print("Services: None")

    print("\nScan completed.\n")

# Run the program only if this file is executed directly
if __name__ == "__main__":
    main()