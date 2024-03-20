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

    filter_expression = 'tcp'

    for packet in pyshark.FileCapture(pcap_file, display_filter=filter_expression):
        if 'IP' in packet and 'TCP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_mac = packet.eth.src
            dst_mac = packet.eth.dst

            if src_ip.startswith("192.168.18."):
                attacker_ips.add(src_ip)
                victim_ips.add(dst_ip)

                if hasattr(packet, 'telnet') and packet.telnet:
                    if 'password' in str(packet):
                        password = packet.telnet.data.split()[1]
                        shell_commands.append(password)
                    elif 'login' in str(packet):
                        username = packet.telnet.data.split()[1]
                        identified_usernames.add(username)

                if hasattr(packet.tcp, 'payload'):
                    payload = str(packet.tcp.payload).strip()
                    if payload.endswith('.exe'):
                        malicious_downloads.append((src_ip, dst_ip, payload))
                    else:
                        shell_commands.append(payload)

    # Generate report
    print("Report on Network Traffic Analysis:")
    print("Attacker IP(s) and MAC address(es):")
    for ip in attacker_ips:
        print(f"  IP: {ip}")

    print("\nVictim IP(s) and MAC address(es):")
    for ip in victim_ips:
        print(f"  IP: {ip}")

    print("\nIdentified compromised usernames:")
    for username in identified_usernames:
        print(f"  Username: {username}")

    print("\nSuccessful login attempts:")
    for username in successful_logins:
        print(f"  Username: {username}")

    print("\nMalicious executable downloads:")
    for src_ip, dst_ip, payload in malicious_downloads:
        print(f"  From: {src_ip}, To: {dst_ip}, Payload: {payload}")

    print("\nCommands issued during remote shell access:")
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
