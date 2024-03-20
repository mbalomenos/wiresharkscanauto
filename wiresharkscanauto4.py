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
    identified_attacks = set()
    detected_usernames = set()
    detected_passwords = set()
    malicious_downloads = set()
    shell_commands = set()
    tcp_flags = set()
    
    # Iterate over each packet in the capture
    for packet in capture:
        # Example: Detect potential attacks and threats
        if hasattr(packet, 'http'):
            if "attack" in str(packet.http):
                identified_attacks.add("HTTP attack detected")
        elif hasattr(packet, 'tls'):
            if "attack" in str(packet.tls):
                identified_attacks.add("TLS attack detected")
        elif hasattr(packet, 'ftp'):
            if "attack" in str(packet.ftp):
                identified_attacks.add("FTP attack detected")
        elif hasattr(packet, 'smb'):
            if "attack" in str(packet.smb):
                identified_attacks.add("SMB attack detected")
        elif hasattr(packet, 'smb2'):
            if "attack" in str(packet.smb2):
                identified_attacks.add("SMB2 attack detected")
        
        # Example: Extract potential usernames and passwords from packets
        if hasattr(packet, 'ftp') and hasattr(packet.ftp, 'request_command'):
            if packet.ftp.request_command == "USER":
                detected_usernames.add(packet.ftp.request_arg)
            elif packet.ftp.request_command == "PASS":
                detected_passwords.add(packet.ftp.request_arg)
        elif hasattr(packet, 'http') and hasattr(packet.http, 'request_uri'):
            if packet.http.request_uri.startswith("/login"):
                detected_usernames.add(packet.http.authbasic_user)
                detected_passwords.add(packet.http.authbasic_password)
        elif hasattr(packet, 'smb') and hasattr(packet.smb, 'user'):
            detected_usernames.add(packet.smb.user)
        elif hasattr(packet, 'smb2') and hasattr(packet.smb2, 'user'):
            detected_usernames.add(packet.smb2.user)
        
        # Example: Identify malicious downloads
        if hasattr(packet, 'http') and hasattr(packet.http, 'response'):
            if "malicious_file.exe" in packet.http.response:
                malicious_downloads.add("malicious_file.exe")
        
        # Example: Identify shell commands
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
            payload = str(packet.tcp.payload)
            if "whoami" in payload or "systeminfo" in payload:
                shell_commands.add(payload)
        
        # Example: Extract TCP flags
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
            tcp_flags.add(packet.tcp.flags)
    
    # Consolidate analysis results into a dictionary
    analysis_results = {
        "Identified Attacks": identified_attacks,
        "Detected Usernames": detected_usernames,
        "Detected Passwords": detected_passwords,
        "Malicious Downloads": malicious_downloads,
        "Shell Commands": shell_commands,
        "TCP Flags": tcp_flags
    }
    
    return analysis_results

def print_report(analysis_results):
    print("\nAnalysis Report:")
    for category, results in analysis_results.items():
        print(f"\n{category}:")
        if results:
            for result in results:
                print(f" - {result}")
        else:
            print("   No relevant data found.")

def main():
    file_path = choose_file()
    if file_path:
        analysis_results = analyze_pcap(file_path)
        print_report(analysis_results)
    else:
        print("No file selected.")

if __name__ == "__main__":
    main()
