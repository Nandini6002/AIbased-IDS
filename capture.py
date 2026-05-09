from scapy.all import sniff

def process_packet(packet):
    print(packet.summary())

print("Capturing packets...")

sniff(prn=process_packet, count=10)