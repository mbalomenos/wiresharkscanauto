import pyshark
import tkinter as tk
from tkinter import filedialog
import logging

def suppress_pyshark_logs():
    """Suppresses pyshark logs."""
    logging.getLogger("pyshark").setLevel(logging.ERROR)

def extract_credentials(packet):
    """Extracts username and password from packet payload."""
    # Placeholder function for extracting credentials
    # Modify according to the specific protocol and payload format
    return "username", "password"

def extract_shell_command(packet):
    """Extracts shell commands from packet payload."""
    # Placeholder function for extracting shell commands
    # Modify according to the specific protocol and payload format
    return "shell command"

def analyze_packets(pcap_file):
    """Analyzes packets in the given packet capture file."""
    handshake_attempts = {}
    login_attempts = {}
    attacker_ips = set()
    victim_ips = set()
    downloaded_executables = []

    filter_expression = 'tcp'

    for packet in pyshark.FileCapture(pcap_file, display_filter=filter_expression):
        if 'TCP' in packet:
            src_ip, src_mac, dst_ip, dst_mac = extract_addresses(packet)

            if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                # Flagging packets with only SYN flag set
                print("Flagged [SYN] packet:")
                print(packet)

                # Follow TCP stream to look for usernames and passwords
                if hasattr(packet.tcp, 'payload') and packet.tcp.payload:
                    print("Following TCP Stream:")
                    print(packet.tcp.payload)

                    # Extracting credentials from TCP stream
                    username, password = extract_credentials(packet)
                    if username and password:
                        print(f"Extracted credentials: Username - {username}, Password - {password}")
            elif packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '1':
                # Flagging packets with both SYN and ACK flags set
                print("Flagged [SYN, ACK] packet:")
                print(packet)

                # Follow TCP stream to look for usernames and passwords
                if hasattr(packet.tcp, 'payload') and packet.tcp.payload:
                    print("Following TCP Stream:")
                    print(packet.tcp.payload)

                    # Extracting credentials from TCP stream
                    username, password = extract_credentials(packet)
                    if username and password:
                        print(f"Extracted credentials: Username - {username}, Password - {password}")

            if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                handshake_key = (src_ip, dst_ip, src_mac, dst_mac)
                handshake_attempts[handshake_key] = handshake_attempts.get(handshake_key, []) + [packet]
            else:
                username, password = extract_credentials(packet)
                if username and password:
                    login_key = (src_ip, dst_ip, src_mac, dst_mac, username, password)
                    login_attempts[login_key] = login_attempts.get(login_key, []) + [packet]

            attacker_ips.add(src_ip)
            victim_ips.add(dst_ip)

            # Check for executable downloads
            if hasattr(packet.tcp, 'payload') and packet.tcp.payload and ".exe" in str(packet.tcp.payload):
                downloaded_executables.append((packet.ip.src, packet.tcp.srcport, packet.tcp.payload))

    attack_type = determine_attack(handshake_attempts.values(), login_attempts.values())
    print(f"Attack Type: {attack_type}")

    print("Attacker IP(s) and MAC address(es):")
    for ip in attacker_ips:
        print(f"  IP: {ip}, MAC: {src_mac}")  

    print("\nVictim IP(s) and MAC address(es):")
    for ip in victim_ips:
        print(f"  IP: {ip}, MAC: {dst_mac}")  

    for key, packets in handshake_attempts.items():
        if len(packets) > 1:
            print(f"\nRepeated TCP handshake attempt detected:")
            print(f"  Source IP: {key[0]}, Destination IP: {key[1]}")
            print(f"  Source MAC: {key[2]}, Destination MAC: {key[3]}")

    for key, packets in login_attempts.items():
        if len(packets) > 1:
            print(f"\nRepeated login attempt detected:")
            print(f"  Source IP: {key[0]}, Destination IP: {key[1]}")
            print(f"  Source MAC: {key[2]}, Destination MAC: {key[3]}")
            print(f"  Username: {key[4]}, Password: {key[5]}")

    if downloaded_executables:
        print("\nDownloaded executables:")
        for ip, port, payload in downloaded_executables:
            print(f"  IP: {ip}, Port: {port}, Payload: {payload}")

def extract_addresses(packet):
    """Extracts source and destination IP addresses and MAC addresses from packet."""
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    src_mac = packet.eth.src
    dst_mac = packet.eth.dst
    return src_ip, src_mac, dst_ip, dst_mac

def determine_attack(handshake_attempts, login_attempts):
    """Determines the type of attack based on observed behavior."""
    # Placeholder function to determine attack type
    return "No Attack Detected"

def select_file():
    """Opens file dialog to select a .pcap or .pcapng file."""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    file_path = filedialog.askopenfilename(title="Select .pcap or .pcapng file", filetypes=[("PCAP files", "*.pcap *.pcapng")])
    if file_path:
        analyze_packets(file_path)

if __name__ == "__main__":
    select_file()
