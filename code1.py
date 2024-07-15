import scapy.all as scapy

def packet_sniffer(interface, count):
    try:
        sniffed_packets = scapy.sniff(iface=interface, count=count)
        return sniffed_packets
    except OSError as e:
        print(f"Error: {e}")

def packet_info(packet):
    # Extract relevant information from the packet
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        payload = packet.payload
        
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")
        print(f"Payload: {payload}")

# Prompt user for interface name input
interface = input("Enter the network interface name (e.g., Ethernet, Wi-Fi): ")
count = 10  # Number of packets to capture

sniffed_packets = packet_sniffer(interface, count)

if sniffed_packets:
    for packet in sniffed_packets:
        packet_info(packet)
