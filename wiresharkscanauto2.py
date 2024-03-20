import pyshark
import tkinter as tk
from tkinter import filedialog

def extract_shell_commands(packet):
    """Extracts potential shell commands from packet payloads."""
    commands = []
    if hasattr(packet.tcp, 'payload'):
        # Convert payload to string for easier manipulation
        payload = str(packet.tcp.payload)
        # Split payload by space and analyze each element
        for item in payload.split():
            # Here you can implement any pattern matching or analysis logic
            # For simplicity, let's consider any non-empty string as a potential shell command
            if item.strip():  # Check if the item is not empty
                commands.append(item.strip())  # Add to commands list
    return commands

def analyze_packets(pcap_file):
    """Analyzes packets in the given packet capture file."""
    flagged_packets = []
    shell_commands = []

    attacker_ips = set()
    attacker_macs = set()
    victim_ips = set()
    victim_macs = set()
    compromised_usernames = set()
    attacks = set()
    downloaded_executables = []

    for packet in pyshark.FileCapture(pcap_file):
        if 'TCP' in packet:
            src_ip, src_mac, dst_ip, dst_mac = extract_addresses(packet)

            if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '1':
                # Flagging packets with both SYN and ACK flags set
                flagged_packets.append(packet)

            # Extract potential shell commands
            commands = extract_shell_commands(packet)
            if commands:
                shell_commands.extend(commands)

            # Add IP and MAC addresses to respective sets
            attacker_ips.add(src_ip)
            attacker_macs.add(src_mac)
            victim_ips.add(dst_ip)
            victim_macs.add(dst_mac)

            # Check for potential username compromise
            if hasattr(packet.tcp, 'payload'):
                payload = str(packet.tcp.payload)
                if 'username' in payload.lower():
                    compromised_usernames.add(payload)

            # Check for executable downloads
            if hasattr(packet.tcp, 'payload') and packet.tcp.payload and ".exe" in str(packet.tcp.payload):
                downloaded_executables.append((packet.ip.src, packet.tcp.srcport, packet.tcp.payload))

    print("Flagged [SYN, ACK] packets:")
    for packet in flagged_packets:
        print(packet)

    if shell_commands:
        print("\nPotential shell commands detected:")
        for command in shell_commands:
            print(f"  Command: {command}")

    print("\nAnswers to the questions:")
    print(f"1. Source IP and MAC address of attacker's machine: {attacker_ips}, {attacker_macs}")
    print(f"   Destination IP and MAC address of victim's machine: {victim_ips}, {victim_macs}")
    print(f"2. Identified compromised usernames: {compromised_usernames}")
    print(f"3. Types of attacks leveraged to find user passwords: {attacks}")
    print(f"4. Correct password(s):")  # This would require more sophisticated analysis
    print(f"5. Number of malicious executable downloads and their details: {len(downloaded_executables)}, {downloaded_executables}")
    print(f"6. Commands issued by attackers when they gained remote shell: {shell_commands}")

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
