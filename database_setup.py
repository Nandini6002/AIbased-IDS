import sqlite3

conn = sqlite3.connect("database/ids.db")

cursor = conn.cursor()

# ---------------- USERS TABLE ----------------

cursor.execute("""

CREATE TABLE IF NOT EXISTS users (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    email TEXT UNIQUE,

    username TEXT UNIQUE,

    password TEXT,

    api_key TEXT UNIQUE

)

""")

# ---------------- LOGS TABLE ----------------

cursor.execute("""

CREATE TABLE IF NOT EXISTS logs (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    user_id INTEGER,

    source_ip TEXT,

    destination_ip TEXT,

    protocol TEXT,

    packet_size INTEGER,

    status TEXT,

    severity TEXT,

    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP

)

""")

conn.commit()

conn.close()

print("Database created successfully!")