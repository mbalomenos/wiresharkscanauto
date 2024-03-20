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
    identified_usernames = set()
    malicious_downloads = []
    shell_commands = []
    suspicious_traffic = []
    
    # Iterate over each packet in the capture
    for packet in capture:
        # Example: Extract source and destination IP addresses
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            if src_ip == "192.168.18.130":
                attacker_ips.add(src_ip)
            else:
                victim_ips.add(src_ip)
            
        # Example: Detect shell commands in TCP payloads
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
            payload = str(packet.tcp.payload)
            if "whoami" in payload or "systeminfo" in payload:
                shell_commands.append(payload)
        
        # Example: Identify suspicious traffic based on packet size
        if hasattr(packet, 'length') and int(packet.length) > 1500:
            suspicious_traffic.append(packet)
    
    # Consolidate analysis results into a dictionary
    analysis_results = {
        "Attacker IPs": list(attacker_ips),
        "Victim IPs": list(victim_ips),
        "Shell Commands": shell_commands,
        "Suspicious Traffic": suspicious_traffic
    }
    
    return analysis_results

def print_results(analysis_results):
    print("\nAnalysis Results:")
    for category, results in analysis_results.items():
        print(f"\n{category}:")
        if results:
            if isinstance(results, list):
                for result in results:
                    print(f" - {result}")
            else:
                for key, value in results.items():
                    print(f" - {key}: {value}")
        else:
            print("   No results found.")

def main():
    file_path = choose_file()
    if file_path:
        analysis_results = analyze_pcap(file_path)
        print_results(analysis_results)
    else:
        print("No file selected.")

if __name__ == "__main__":
    main()
