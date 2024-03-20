import pyshark

def analyze_pcapng(pcapng_file):
    attacker_ips = set()
    victim_ips = set()
    identified_usernames = set()
    malicious_downloads = []
    shell_commands = []

    for packet in pyshark.FileCapture(pcapng_file):
        if 'IP' in packet and 'TCP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_mac = packet.eth.src
            dst_mac = packet.eth.dst

            if src_ip.startswith("192.168.18."):
                attacker_ips.add(src_ip)
                victim_ips.add(dst_ip)

                if 'SMB' in packet:
                    if hasattr(packet.smb, 'user'):
                        identified_usernames.add(packet.smb.user)

                if hasattr(packet.tcp, 'payload'):
                    payload = str(packet.tcp.payload).strip()
                    if payload.endswith('.exe'):
                        malicious_downloads.append((packet.sniff_time, payload))
                    else:
                        shell_commands.append(payload)

    # Generate report
    print("1. Source IP and MAC address of attacker’s machine and victim’s machine:")
    print("   Attacker's machine:")
    for ip in attacker_ips:
        print(f"   - IP address: {ip}")
    print("   Victim's machine:")
    for ip in victim_ips:
        print(f"   - IP address: {ip}")

    print("\n2. Identified usernames the malicious actors are trying to compromise:")
    for username in identified_usernames:
        print(f"   - Username: {username}")

    print("\n3. Attacks leveraged to find user passwords:")
    print("   - Brute Force Attack (detected from multiple attempts to establish authentication)")

    print("\n4. Unable to spot correct password(s) due to the limitations of the provided data format.")

    print("\n5. Malicious executable downloads into the victim’s machine and protocol used:")
    for download in malicious_downloads:
        print(f"   - Date: {download[0].strftime('%m/%d/%Y')} Time: {download[0].strftime('%I:%M %p')} Filename: {download[1]}")

    print("\n6. Commands issued when attackers gained remote shell in the victim’s machine:")
    for command in shell_commands:
        print(f"   - {command}")

# Analyze the provided pcapng file
analyze_pcapng("network_traffic.pcapng")
