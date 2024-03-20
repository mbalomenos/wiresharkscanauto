import tkinter as tk
from tkinter import filedialog
import pyshark

def choose_file():
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    file_path = filedialog.askopenfilename(filetypes=[("PCAPNG files", "*.pcapng"), ("PCAP files", "*.pcap")])
    return file_path

def analyze_pcap(file_path):
    print("Analyzing the file:", file_path)
    capture = pyshark.FileCapture(file_path)
    
    # Initialize variables to store analysis results
    attacker_ips = set()
    victim_ips = set()
    detected_usernames = set()
    identified_attacks = set()
    detected_passwords = set()
    malicious_downloads = []
    shell_commands = set()
    
    # Iterate over each packet in the capture
    for packet in capture:
        # Extract IP addresses
        if "ip" in packet:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            if "attacker" in packet:
                attacker_ips.add(ip_src)
            elif "victim" in packet:
                victim_ips.add(ip_src)
        
        # Identify potential attacks
        if hasattr(packet, 'http') and "attack" in str(packet.http):
            identified_attacks.add("HTTP attack detected")
        elif hasattr(packet, 'tls') and "attack" in str(packet.tls):
            identified_attacks.add("TLS attack detected")
        # Add other attack identification logic
        
        # Extract usernames and passwords
        if hasattr(packet, 'ftp'):
            if packet.ftp.request_command == "USER":
                detected_usernames.add(packet.ftp.request_arg)
            elif packet.ftp.request_command == "PASS":
                detected_passwords.add(packet.ftp.request_arg)
        # Add other username and password extraction logic
        
        # Identify malicious downloads
        if hasattr(packet, 'http') and hasattr(packet.http, 'response'):
            if packet.http.response.endswith(".exe"):
                malicious_downloads.append(packet.http.response)
        # Add other malicious download identification logic
        
        # Extract shell commands
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
            payload = str(packet.tcp.payload)
            if "whoami" in payload or "systeminfo" in payload:
                shell_commands.add(payload)
        # Add other shell command extraction logic
    
    # Construct the analysis report
    report = "Analysis Report:\n\n"

    # Source and victim IP addresses
    report += "1. What is the source IP and MAC address of attacker’s machine and victim’s machine?\n"
    for ip in attacker_ips:
        report += f"   - Attacker's machine:\n     - IP address: {ip}\n"
    for ip in victim_ips:
        report += f"   - Victim's machine:\n     - IP address: {ip}\n"
    
    # Detected usernames
    report += "\n2. Identify the usernames the malicious actors are trying to compromise.\n"
    for username in detected_usernames:
        report += f"   - {username}\n"
    
    # Identified attacks
    report += "\n3. Which attack(s) the malicious actor has leveraged in order to find user passwords?\n"
    for attack in identified_attacks:
        report += f"   - {attack}\n"
    
    # Detected passwords
    report += "\n4. Can you spot the correct password(s)?\n"
    for password in detected_passwords:
        report += f"   - {password}\n"
    
    # Malicious downloads
    report += "\n5. How many times a malicious executable (“.EXE”) has been downloaded into the victim’s machine and through which protocol? Provide name(s).\n"
    if malicious_downloads:
        for i, download in enumerate(malicious_downloads, 1):
            report += f"   - {i}. {download}\n"
    else:
        report += "   No malicious executables downloaded.\n"
    
    # Shell commands
    report += "\n6. What commands the attackers issued when they gained remote shell in the victim’s machine?\n"
    for command in shell_commands:
        report += f"   - {command.strip()}\n"
    
    return report

def main():
    file_path = choose_file()
    if file_path:
        analysis_report = analyze_pcap(file_path)
        print(analysis_report)
    else:
        print("No file selected.")

if __name__ == "__main__":
    main()
