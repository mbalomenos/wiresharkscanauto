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
    results = "Sample analysis results"  # Placeholder results
    return results

def print_results(results):
    print("Analysis Results:")
    print(results)

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
