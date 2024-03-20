import tkinter as tk
from tkinter import filedialog
import pyshark
from collections import defaultdict
from datetime import datetime

# Function to select a file using a pop-up window
def select_file():
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    file_path = filedialog.askopenfilename(
        title="Select a .pcap or .pcapng file",
        filetypes=[("PCAP files", "*.pcap"), ("PCAPNG files", "*.pcapng")]
    )

    return file_path

# Function to analyze the pcap file
def analyze_pcap(file_path):
    capture = pyshark.FileCapture(file_path)

    # Analysis variables
    attacker_ips = set()
    victim_ips = set()
    identified_usernames = set()
    malicious_downloads = []
    shell_commands = []
    brute_force_attempts = defaultdict(int)

    # Perform analysis on the capture file
    for packet in capture:
        if "ip" in packet and "tcp" in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport

            # Detect potential attacks by analyzing TCP streams
            if packet.tcp.stream:
                stream_id = int(packet.tcp.stream)
                tcp_stream = capture.tcp_streams[stream_id]

                if "login" in str(tcp_stream).lower():
                    brute_force_attempts[src_ip] += 1
                    if brute_force_attempts[src_ip] >= 3:
                        attacker_ips.add(src_ip)

                if "pass" in str(tcp_stream).lower():
                    identified_usernames.add(dst_ip)

                if "exe" in str(tcp_stream).lower():
                    malicious_downloads.append({
                        "Date": packet.sniff_time.strftime("%m/%d/%Y"),
                        "Time": packet.sniff_time.strftime("%I:%M %p"),
                        "Filename": packet.tcp.segment_data.strip(),
                        "File size": packet.tcp.len,
                        "Protocol": "TCP"
                    })

            # Detect unusual lengths and sizes
            if len(packet.tcp.segment_data.strip()) > 1000:
                shell_commands.append(packet.tcp.segment_data.strip())

            if packet.tcp.len > 10000:
                malicious_downloads.append({
                    "Date": packet.sniff_time.strftime("%m/%d/%Y"),
                    "Time": packet.sniff_time.strftime("%I:%M %p"),
                    "Filename": "Suspicious large packet size",
                    "File size": packet.tcp.len,
                    "Protocol": "TCP"
                })

    # Prepare analysis results
    analysis_results = {
        "Attacker IPs": attacker_ips,
        "Victim IPs": victim_ips,
        "Identified Usernames": identified_usernames,
        "Brute Force Attempts": dict(brute_force_attempts),
        "Malicious Downloads": malicious_downloads,
        "Shell Commands": shell_commands
    }

    return analysis_results

# Function to generate a professional report
def generate_report(analysis_results, file_path):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_name = f"Analysis_Report_{timestamp}.txt"

    with open(report_name, "w") as report_file:
        report_file.write(f"Analysis Report for {file_path}\n")
        report_file.write("\n")

        for category, data in analysis_results.items():
            report_file.write(f"{category}:\n")
            if isinstance(data, set):
                for item in data:
                    report_file.write(f"  - {item}\n")
            elif isinstance(data, dict):
                for key, value in data.items():
                    report_file.write(f"  - {key}: {value}\n")
            elif isinstance(data, list):
                for item in data:
                    for key, value in item.items():
                        report_file.write(f"  - {key}: {value}\n")
                    report_file.write("\n")
            else:
                report_file.write(f"  - {data}\n")
            report_file.write("\n")

    print(f"Report generated: {report_name}")

def main():
    # Step 1: Select a file
    file_path = select_file()
    if not file_path:
        print("No file selected. Exiting...")
        return

    print(f"Selected file: {file_path}")

    # Step 2: Analyze the file
    print("Analyzing the file...")
    analysis_results = analyze_pcap(file_path)

    # Step 3: Generate a professional report
    print("Generating a professional report...")
    generate_report(analysis_results, file_path)

if __name__ == "__main__":
    main()
