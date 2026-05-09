from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import joblib
import numpy as np

# ---------------- LOAD MODEL ----------------

model = joblib.load("model/ids_model.pkl")


# ---------------- SAVE TO DATABASE ----------------

def save_to_database(src, dst, protocol, size, status, severity):

    conn = sqlite3.connect("database/ids.db")

    cursor = conn.cursor()

    cursor.execute("""

    INSERT INTO logs (

        source_ip,
        destination_ip,
        protocol,
        packet_size,
        status,
        severity

    )

    VALUES (?, ?, ?, ?, ?, ?)

    """, (

        src,
        dst,
        protocol,
        size,
        status,
        severity

    ))

    conn.commit()

    conn.close()


# ---------------- FEATURE EXTRACTION ----------------

def extract_features(packet):

    packet_size = len(packet)

    protocol = 0

    tcp_flag = 0

    if TCP in packet:
        protocol = 1
        tcp_flag = 1

    elif UDP in packet:
        protocol = 2

    features = [

        packet_size,
        protocol,
        tcp_flag

    ]

    # Fill remaining features
    while len(features) < 41:
        features.append(0)

    return np.array(features).reshape(1, -1)


# ---------------- PROCESS PACKETS ----------------

def process_packet(packet):

    if IP in packet:

        src = packet[IP].src

        dst = packet[IP].dst

        protocol = packet[IP].proto

        size = len(packet)

        # Extract ML features
        features = extract_features(packet)

        # Real ML prediction
        prediction = model.predict(features)[0]

        if prediction == 1:

            status = "Attack Detected"

            severity = "High"

        else:

            status = "Normal Traffic"

            severity = "Low"

        print(
            src,
            "→",
            dst,
            "|",
            status
        )

        save_to_database(
            src,
            dst,
            str(protocol),
            size,
            status,
            severity
        )


# ---------------- START IDS ----------------

print("AI IDS Started...\n")

sniff(
    prn=process_packet,
    store=False
)