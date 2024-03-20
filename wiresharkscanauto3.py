import pyshark
import tkinter as tk
from tkinter import filedialog

def suppress_pyshark_logs():
    """Suppresses pyshark logs."""
    logging.getLogger("pyshark").setLevel(logging.ERROR)

def analyze_packets(pcap_file):
    """Analyzes packets in the given packet capture file."""
    attacker_ip = ""
    attacker_mac = ""
    victim_ip = ""
    victim_mac = ""
    identified_usernames = set()
    brute_force_attacks = set()
    malicious_executables = []
    shell_commands = []

    filter_expression = 'tcp'

    for packet in pyshark.FileCapture(pcap_file, display_filter=filter_expression):
        if 'IP' in packet and 'TCP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_mac = packet.eth.src
            dst_mac = packet.eth.dst

            if src_ip.startswith("192.168.18."):
                attacker_ip = src_ip
                attacker_mac = src_mac
                victim_ip = dst_ip
                victim_mac = dst_mac

                if hasattr(packet, 'telnet') and packet.telnet:
                    if 'password' in str(packet):
                        brute_force_attacks.add((packet.telnet.data.split()[1], packet.ip.src, packet.ip.dst))
                    elif 'login' in str(packet):
                        identified_usernames.add(packet.telnet.data.split()[1])

                if hasattr(packet.tcp, 'payload'):
                    payload = str(packet.tcp.payload).strip()
                    if payload.endswith('.exe'):
                        malicious_executables.append((packet.ip.src, packet.ip.dst, payload))
                    else:
                        shell_commands.append(payload)

    # Generate report
    print("Report on Network Traffic Analysis:")
    print("\n1. Source IP and MAC address of attacker’s machine:")
    print(f"  IP address: {attacker_ip}")
    print(f"  MAC address: {attacker_mac}")
    print("\n   Source IP and MAC address of victim’s machine:")
    print(f"  IP address: {victim_ip}")
    print(f"  MAC address: {victim_mac}")

    print("\n2. Identified usernames the malicious actors are trying to compromise:")
    for username in identified_usernames:
        print(f"  Username: {username}")

    print("\n3. Attack(s) the malicious actor has leveraged to find user passwords:")
    print("   Brute Force Attack")

    print("\n4. Correct password(s):")
    for password, src_ip, dst_ip in brute_force_attacks:
        print(f"  Password: {password}, Source IP: {src_ip}, Destination IP: {dst_ip}")

    print("\n5. Malicious executable downloads:")
    for src_ip, dst_ip, payload in malicious_executables:
        print(f"  From: {src_ip}, To: {dst_ip}, Payload: {payload}")

    print("\n6. Commands issued when attackers gained remote shell in the victim’s machine:")
    for command in shell_commands:
        print(f"  {command}")

def select_file():
    """Opens file dialog to select a .pcap or .pcapng file."""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    file_path = filedialog.askopenfilename(title="Select .pcap or .pcapng file", filetypes=[("PCAP files", "*.pcap *.pcapng")])
    if file_path:
        analyze_packets(file_path)

if __name__ == "__main__":
    select_file()
