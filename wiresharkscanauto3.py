import pyshark
import tkinter as tk
from tkinter import filedialog
import logging
import re

def suppress_pyshark_logs():
    """Suppresses pyshark logs."""
    logging.getLogger("pyshark").setLevel(logging.ERROR)

def extract_credentials(packet):
    """Extracts username and password from packet payload."""
    credentials = re.findall(r'username=(\w+)&password=(\w+)', str(packet))
    if credentials:
        return credentials[0]
    else:
        return None, None

def extract_shell_command(packet):
    """Extracts shell commands from packet payload."""
    # Placeholder function for extracting shell commands
    # Modify according to the specific protocol and payload format
    return "shell command"

def analyze_packets(pcap_file):
    """Analyzes packets in the given packet capture file."""
    attacker_ips = set()
    victim_ips = set()
    usernames = set()
    handshake_attempts = {}
    login_attempts = {}
    downloaded_executables = []

    filter_expression = 'tcp'

    for packet in pyshark.FileCapture(pcap_file, display_filter=filter_expression):
        if 'TCP' in packet:
            src_ip, src_mac, dst_ip, dst_mac = extract_addresses(packet)

            if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                # Flagging packets with only SYN flag set
                # Follow TCP stream to look for usernames and passwords
                if hasattr(packet.tcp, 'payload') and packet.tcp.payload:
                    # Extracting credentials from TCP stream
                    username, password = extract_credentials(packet)
                    if username and password:
                        usernames.add(username)
            elif packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '1':
                # Flagging packets with both SYN and ACK flags set
                # Follow TCP stream to look for usernames and passwords
                if hasattr(packet.tcp, 'payload') and packet.tcp.payload:
                    # Extracting credentials from TCP stream
                    username, password = extract_credentials(packet)
                    if username and password:
                        usernames.add(username)

            # Check for repeated handshake attempts
            if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                handshake_key = (src_ip, dst_ip, src_mac, dst_mac)
                handshake_attempts[handshake_key] = handshake_attempts.get(handshake_key, []) + [packet]
            else:
                # Check for repeated login attempts
                username, password = extract_credentials(packet)
                if username and password:
                    login_key = (src_ip, dst_ip, src_mac, dst_mac, username, password)
                    login_attempts[login_key] = login_attempts.get(login_key, []) + [packet]

            attacker_ips.add(src_ip)
            victim_ips.add(dst_ip)

            # Check for executable downloads
            if hasattr(packet.tcp, 'payload') and packet.tcp.payload and ".exe" in str(packet.tcp.payload):
                downloaded_executables.append((packet.ip.src, packet.tcp.srcport, packet.tcp.payload))

    # Generating the short paragraph reporting the findings
    report = "Report on Network Traffic Analysis:\n"
    report += f"Attacker IP(s) and MAC address(es): {', '.join([f'IP: {ip}, MAC: {src_mac}' for ip in attacker_ips])}\n"
    report += f"Victim IP(s) and MAC address(es): {', '.join([f'IP: {ip}, MAC: {dst_mac}' for ip in victim_ips])}\n"
    report += f"Identified compromised usernames: {', '.join(usernames)}\n"
    if login_attempts:
        report += "Successful login attempts detected:\n"
        for key, _ in login_attempts.items():
            report += f"  IP: {key[0]}, Username: {key[4]}, Password: {key[5]}\n"
    else:
        report += "No successful login attempts detected.\n"
    if downloaded_executables:
        report += "Malicious executable downloads detected:\n"
        for ip, port, payload in downloaded_executables:
            report += f"  IP: {ip}, Port: {port}, Payload: {payload}\n"
    else:
        report += "No malicious executable downloads detected.\n"

    print(report)

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
