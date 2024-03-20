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
    # Add your analysis code here
    return "Analysis completed"  # Placeholder message

def main():
    file_path = select_file()
    if not file_path:
        print("No file selected. Exiting...")
        return

    print(f"Selected file: {file_path}")
    print("Analyzing the file...")

    result = analyze_pcap(file_path)
    print(result)

if __name__ == "__main__":
    main()
