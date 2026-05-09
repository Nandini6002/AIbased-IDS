from scapy.all import sniff, IP
import requests

SERVER_URL = "http://127.0.0.1:5000/api/log"

API_KEY = "b4f702ddc5c2ad28b62e8fb18bffbccf"

def process_packet(packet):

    try:

        if packet.haslayer(IP):

            src = packet[IP].src

            dst = packet[IP].dst

            protocol = packet[IP].proto

            size = len(packet)

            payload = {

                "api_key": API_KEY,

                "source_ip": src,

                "destination_ip": dst,

                "protocol": str(protocol),

                "packet_size": size,

                "status": "Normal Traffic",

                "severity": "Low"

            }

            response = requests.post(
                SERVER_URL,
                json=payload
            )

            print("Packet Sent ✅")

            print(payload)

    except Exception as e:

        print("ERROR:", e)

print("AI IDS Agent Started...")

sniff(
    prn=process_packet,
    store=False
)