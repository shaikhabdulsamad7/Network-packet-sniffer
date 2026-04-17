from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

LOG_FILE = "packets.log"

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        time = datetime.now().strftime("%H:%M:%S")

        if TCP in packet:
            line = f"[{time}] TCP | {src} --> {dst} | Port: {packet[TCP].dport}"
        elif UDP in packet:
            line = f"[{time}] UDP | {src} --> {dst} | Port: {packet[UDP].dport}"
        else:
            line = f"[{time}] OTHER | {src} --> {dst}"

        print(line)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")

print("[*] Starting Packet Sniffer... Press CTRL+C to stop")
sniff(count=50, prn=packet_callback)
print("[*] Done! Check packets.log for results")