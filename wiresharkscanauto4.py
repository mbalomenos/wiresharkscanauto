import tkinter as tk
from tkinter import filedialog
import pyshark

def select_file():
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    file_path = filedialog.askopenfilename(
        title="Select a .pcap or .pcapng file",
        filetypes=[("PCAP files", "*.pcap"), ("PCAPNG files", "*.pcapng")]
    )

    return file_path

def analyze_pcap(file_path):
    capture = pyshark.FileCapture(file_path)
    # Perform analysis on the capture file
    # Replace the placeholder results with your analysis
    results = {
        "Source IP and MAC address": {
            "Attacker's machine": {
                "IP address": "192.168.1.10",
                "MAC address": "00:0c:29:ff:8b:15"
            },
            "Victim's machine": {
                "IP address": "192.168.1.2",
                "MAC address": "00:0c:29:0a:55:62"
            }
        },
        "Identified usernames": ["John"],
        "Attacks leveraged": "Brute Force Attack",
        "Correct password(s)": "Unable to spot correct password(s)",
        "Malicious executable downloads": [
            {"Date": "09/03/2021", "Time": "11:07 AM", "Filename": "46aFwPnBPc.exe", "File size": "73,802 bytes", "Protocol": "TCP"}
        ],
        "Commands issued": ["whoami", "systeminfo"]
    }
    return results

def print_results(results):
    print("Analysis Results:")
    for category, data in results.items():
        print(f"\n{category}:")
        if isinstance(data, list):
            for item in data:
                print_item(item)
        elif isinstance(data, dict):
            for sub_category, sub_data in data.items():
                print(f"  {sub_category}:")
                print_item(sub_data)
        else:
            print_item(data)

def print_item(item):
    if isinstance(item, dict):
        for key, value in item.items():
            print(f"    {key}: {value}")
    else:
        print(f"  - {item}")

def main():
    file_path = select_file()
    if not file_path:
        print("No file selected. Exiting...")
        return

    print(f"Selected file: {file_path}")
    print("Analyzing the file...")

    analysis_results = analyze_pcap(file_path)
    print_results(analysis_results)

if __name__ == "__main__":
    main()
