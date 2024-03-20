def analyze_pcap(file_path):
    capture = pyshark.FileCapture(file_path)

    # Analysis variables
    attacker_ips = set()
    identified_usernames = set()
    malicious_downloads = []
    shell_commands = []
    brute_force_attempts = defaultdict(int)

    # Perform analysis on the capture file
    for packet in capture:
        if "IP" in packet and "TCP" in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport

            # Detect potential attacks by analyzing TCP streams
            if hasattr(packet, "tcp") and hasattr(packet.tcp, "data"):
                data = str(packet.tcp.data).strip()
                if "login" in data.lower():
                    brute_force_attempts[src_ip] += 1
                    if brute_force_attempts[src_ip] >= 3:
                        attacker_ips.add(src_ip)

                if "pass" in data.lower():
                    identified_usernames.add(dst_ip)

                if "exe" in data.lower():
                    malicious_downloads.append({
                        "Date": packet.sniff_time.strftime("%m/%d/%Y"),
                        "Time": packet.sniff_time.strftime("%I:%M %p"),
                        "Filename": data.strip(),
                        "File size": packet.length,
                        "Protocol": "TCP"
                    })

            # Detect unusual lengths and sizes
            if hasattr(packet, "length") and packet.length > 10000:
                malicious_downloads.append({
                    "Date": packet.sniff_time.strftime("%m/%d/%Y"),
                    "Time": packet.sniff_time.strftime("%I:%M %p"),
                    "Filename": "Suspicious large packet size",
                    "File size": packet.length,
                    "Protocol": "TCP"
                })

    # Prepare analysis results
    analysis_results = {
        "Attacker IPs": attacker_ips,
        "Identified Usernames": identified_usernames,
        "Brute Force Attempts": dict(brute_force_attempts),
        "Malicious Downloads": malicious_downloads,
        "Shell Commands": shell_commands
    }

    return analysis_results
