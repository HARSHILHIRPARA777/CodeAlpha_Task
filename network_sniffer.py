from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

log_file = open("packet_log.txt", "w")

header = "=== Network Packet Sniffer Started ===\n"
header += f"Capture Start Time: {datetime.datetime.now()}\n\n"
print(header)
log_file.write(header)

def process_packet(packet):
    log_entry = ""
    log_entry += f"\n[+] Packet captured at {datetime.datetime.now()}\n"

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        log_entry += f"IP: {ip_src} -> {ip_dst}\n"
        
        if TCP in packet:
            log_entry += f"Protocol: TCP | Src Port: {packet[TCP].sport} | Dst Port: {packet[TCP].dport}\n"
        elif UDP in packet:
            log_entry += f"Protocol: UDP | Src Port: {packet[UDP].sport} | Dst Port: {packet[UDP].dport}\n"
        elif ICMP in packet:
            log_entry += f"Protocol: ICMP\n"
        else:
            log_entry += f"Other protocol (Number: {proto})\n"

    else:
        log_entry += "Non-IP Packet Captured\n"

    print(log_entry)
    log_file.write(log_entry)

try:
    sniff(prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\nSniffing stopped by user.")
    log_file.write("\n=== Sniffing stopped ===\n")
    log_file.close()
