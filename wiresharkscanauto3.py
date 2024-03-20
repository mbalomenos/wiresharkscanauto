import pyshark
import tkinter as tk
from tkinter import filedialog
import logging

def suppress_pyshark_logs():
    """Suppresses pyshark logs."""
    logging.getLogger("pyshark").setLevel(logging.ERROR)

def extract_credentials(packet):
    """Extracts username and password from packet payload."""
    if 'FTP' in packet:
        if 'User' in packet.ftp.request_command:
            return packet.ftp.request_command.split()[1], None
        elif 'PASS' in packet.ftp.request_command:
            return None, packet.ftp.request_command.split()[1]
    elif 'HTTP' in packet:
        return None, None  # Adjust for HTTP payloads
    elif 'Telnet' in packet:
        if 'password' in str(packet):
            return None, packet.telnet.data.split()[1]
        elif 'login' in str(packet):
            return packet.telnet.data.split()[1], None
    return None, None

def analyze_packets(pcap_file):
    """Analyzes packets in the given packet capture file."""
    handshake_attempts = {}
    login_attempts = {}
    attacker_ips = set()
    victim_ips = set()
    downloaded_executables = []
    shell_commands = []

    filter_expression = 'tcp'

    for packet in pyshark.FileCapture(pcap_file, display_filter=filter_expression):
        if 'TCP' in packet:
            src_ip, src_mac, dst_ip, dst_mac = extract_addresses(packet)

            if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                handshake_key = (src_ip, dst_ip, src_mac, dst_mac)
                handshake_attempts[handshake_key] = handshake_attempts.get(handshake_key, []) + [packet]
            elif packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '1':
                username, password = extract_credentials(packet)
                if username and password:
                    login_key = (src_ip, dst_ip, src_mac, dst_mac, username, password)
                    login_attempts[login_key] = login_attempts.get(login_key, []) + [packet]

            attacker_ips.add(src_ip)
            victim_ips.add(dst_ip)

            # Check for executable downloads
            if hasattr(packet.tcp, 'payload') and packet.tcp.payload and ".exe" in str(packet.tcp.payload):
                downloaded_executables.append((packet.ip.src, packet.tcp.srcport, packet.tcp.payload, packet.transport_layer))

            # Check for shell commands
            if hasattr(packet.tcp, 'payload') and packet.tcp.payload:
                shell_commands.append(packet.tcp.payload)

    # Analyze handshake attempts and login attempts for attack types
    # Adjust this part based on specific attack detection logic

    # Generate report
    print("Report on Network Traffic Analysis:")
    print("Attacker IP(s) and MAC address(es):")
    for ip in attacker_ips:
        print(f"  IP: {ip}, MAC: {src_mac}")  

    print("\nVictim IP(s) and MAC address(es):")
    for ip in victim_ips:
        print(f"  IP: {ip}, MAC: {dst_mac}")  

    print("\nIdentified compromised usernames:")
    for key in login_attempts:
        print(f"  Username: {key[4]}")

    print("\nSuccessful login attempts:")
    for key in login_attempts:
        print(f"  Username: {key[4]}, Password: {key[5]}")

    print("\nMalicious executable downloads:")
    for ip, port, payload, protocol in downloaded_executables:
        print(f"  IP: {ip}, Port: {port}, Protocol: {protocol}, Payload: {payload}")

    print("\nCommands issued during remote shell access:")
    for command in shell_commands:
        print(f"  {command}")

def extract_addresses(packet):
    """Extracts source and destination IP addresses and MAC addresses from packet."""
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    src_mac = packet.eth.src
    dst_mac = packet.eth.dst
    return src_ip, src_mac, dst_ip, dst_mac

def select_file():
    """Opens file dialog to select a .pcap or .pcapng file."""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    file_path = filedialog.askopenfilename(title="Select .pcap or .pcapng file", filetypes=[("PCAP files", "*.pcap *.pcapng")])
    if file_path:
        analyze_packets(file_path)

if __name__ == "__main__":
    select_file()
