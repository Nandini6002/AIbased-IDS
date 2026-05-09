from scapy.all import sniff, IP
import requests
import random

SERVER_URL = "http://127.0.0.1:5000/api/log"

API_KEY = "__API_KEY__"

def process_packet(packet):

    if IP in packet:

        src = packet[IP].src

        dst = packet[IP].dst

        protocol = packet[IP].proto

        size = len(packet)

        status = random.choice([
            "Normal Traffic",
            "Attack Detected"
        ])

        severity = random.choice([
            "Low",
            "Medium",
            "High"
        ])

        payload = {

            "api_key": API_KEY,

            "source_ip": src,

            "destination_ip": dst,

            "protocol": str(protocol),

            "packet_size": size,

            "status": status,

            "severity": severity

        }

        try:

            response = requests.post(
                SERVER_URL,
                json=payload
            )

            print("Sent:", payload)

        except Exception as e:

            print("Connection Error:", e)

print("AI IDS Agent Started...")

sniff(
    prn=process_packet,
    store=False
)