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

def analyze_packets(pcap_file):
    """Analyzes packets in the given packet capture file."""
    filter_expression = 'tcp'

    for packet in pyshark.FileCapture(pcap_file, display_filter=filter_expression):
        if 'TCP' in packet:
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

def select_file():
    """Opens file dialog to select a .pcap or .pcapng file."""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    file_path = filedialog.askopenfilename(title="Select .pcap or .pcapng file", filetypes=[("PCAP files", "*.pcap *.pcapng")])
    if file_path:
        analyze_packets(file_path)

if __name__ == "__main__":
    select_file()
