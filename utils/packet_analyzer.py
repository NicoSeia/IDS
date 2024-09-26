from scapy.all import sniff, IP, TCP
from collections import defaultdict

connection_counter = defaultdict(int)

# Define a callback function to process each captured packet
def packet_callback(packet):
    if packet.haslayer(TCP):
        print(f"Captured TCP packet: {packet.summary()}")
        connection_counter[packet[IP].dst] += 1

        if connection_counter[packet[IP].dst] > 10:
            print(f"Posible Port Scan Detected: {packet[IP].src} -> {packet[IP].dst}")


# Start sniffing packets
sniff(filter="tcp", prn=packet_callback, count=10)    # Call packet_callback for each captured packet, stopping after 10 packets


