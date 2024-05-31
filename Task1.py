import argparse
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if proto == 6:  # TCP
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                print(f"TCP Packet: {ip_src}:{sport} -> {ip_dst}:{dport}")

        elif proto == 17:  # UDP
            if UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                print(f"UDP Packet: {ip_src}:{sport} -> {ip_dst}:{dport}")

        else:
            print(f"Other IP Packet: {ip_src} -> {ip_dst}, Protocol: {proto}")

def main(interface, packet_count):
    print(f"Starting network sniffer on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, count=packet_count, store=0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Network Sniffer")
    parser.add_argument('-i', '--interface', type=str, required=True, help="Network interface to sniff on")
    parser.add_argument('-c', '--count', type=int, default=0, help="Number of packets to capture (0 for infinite)")
    args = parser.parse_args()

    main(args.interface, args.count)
