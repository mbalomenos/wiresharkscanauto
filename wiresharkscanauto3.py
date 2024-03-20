import pyshark
import tkinter as tk
from tkinter import filedialog

def suppress_pyshark_logs():
    """Suppresses pyshark logs."""
    logging.getLogger("pyshark").setLevel(logging.ERROR)

def analyze_packets(pcap_file):
    """Analyzes packets in the given packet capture file."""
    attacker_ips = set()
    victim_ips = set()
    identified_usernames = set()
    successful_logins = set()
    malicious_downloads = []
    shell_commands = []
    passwords = set()

    filter_expression = 'tcp'

    for packet in pyshark.FileCapture(pcap_file, display_filter=filter_expression):
        if 'IP' in packet and 'TCP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_mac = packet.eth.src
            dst_mac = packet.eth.dst

            if src_ip.startswith("192.168.18."):
                attacker_ips.add((src_ip, src_mac))
                victim_ips.add((dst_ip, dst_mac))

                if hasattr(packet, 'telnet') and packet.telnet:
                    if 'password' in str(packet):
                        password = packet.telnet.data.split()[1]
                        shell_commands.append(password)
                        passwords.add(password)
                    elif 'login' in str(packet):
                        username = packet.telnet.data.split()[1]
                        identified_usernames.add(username)

                if hasattr(packet.tcp, 'payload'):
                    payload = str(packet.tcp.payload).strip()
                    if payload.endswith('.exe'):
                        protocol = "TCP" if packet.tcp.srcport else "UDP"
                        malicious_downloads.append((src_ip, dst_ip, payload, protocol))
                    else:
                        shell_commands.append(payload)

    # Generate report
    print("Report on Network Traffic Analysis:")
    print("\n1. Source IP and MAC address of attacker’s machine:")
    for ip, mac in attacker_ips:
        print(f"  IP: {ip}, MAC: {mac}")

    print("\n   Source IP and MAC address of victim’s machine:")
    for ip, mac in victim_ips:
        print(f"  IP: {ip}, MAC: {mac}")

    print("\n2. Identified usernames the malicious actors are trying to compromise:")
    for username in identified_usernames:
        print(f"  Username: {username}")

    print("\n3. Attack(s) the malicious actor has leveraged to find user passwords:")
    print("   Telnet sniffing")

    print("\n4. Correct password(s):")
    for password in passwords:
        print(f"  Password: {password}")

    print("\n5. Malicious executable downloads:")
    for src_ip, dst_ip, payload, protocol in malicious_downloads:
        print(f"  From: {src_ip}, To: {dst_ip}, Payload: {payload}, Protocol: {protocol}")

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
