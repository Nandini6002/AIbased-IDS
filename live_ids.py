from scapy.all import sniff
import joblib
import numpy as np

# Load trained model
model = joblib.load("model/ids_model.pkl")

def extract_features(packet):

    features = []

    # Packet length
    features.append(len(packet))

    # Protocol
    if packet.haslayer("TCP"):
        features.append(1)
    elif packet.haslayer("UDP"):
        features.append(2)
    else:
        features.append(0)

    # Fill remaining features with zeros
    while len(features) < 41:
        features.append(0)

    return np.array(features).reshape(1, -1)

def process_packet(packet):

    features = extract_features(packet)

    prediction = model.predict(features)

    if prediction[0] == 1:
        print("⚠ ATTACK DETECTED")
    else:
        print("✅ Normal Traffic")

print("AI IDS Monitoring Started...\n")

sniff(prn=process_packet, count=20)