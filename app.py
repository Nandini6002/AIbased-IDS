# FILE: app.py

from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    redirect,
    send_file
)

import sqlite3
import secrets

from flask_login import (

    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user

)

from werkzeug.security import (

    generate_password_hash,
    check_password_hash

)

app = Flask(__name__)

app.secret_key = "supersecretkey"

# ---------------- LOGIN MANAGER ----------------

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"

# ---------------- USER CLASS ----------------

class User(UserMixin):

    def __init__(self, id):

        self.id = id


@login_manager.user_loader
def load_user(user_id):

    return User(user_id)

# ---------------- INDEX ----------------

@app.route("/")
def index():

    return redirect("/login")

# ---------------- HOME ----------------

@app.route("/home")
@login_required
def home():

    return render_template("home.html")

# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET","POST"])
def login():

    error = None

    if request.method == "POST":

        username = request.form["username"]

        password = request.form["password"]

        conn = sqlite3.connect("database/ids.db")

        cursor = conn.cursor()

        cursor.execute("""

        SELECT id,password

        FROM users

        WHERE username=?

        """,(username,))

        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[1], password):

            login_user(User(user[0]))

            return redirect("/dashboard")

        else:

            error = "Wrong username or password"

    return render_template(
        "login.html",
        error=error
    )

# ---------------- SIGNUP ----------------

@app.route("/signup", methods=["GET","POST"])
def signup():

    error = None

    if request.method == "POST":

        email = request.form["email"]

        username = request.form["username"]

        password = request.form["password"]

        confirm = request.form["confirm"]

        if password != confirm:

            error = "Passwords do not match"

            return render_template(
                "signup.html",
                error=error
            )

        conn = sqlite3.connect("database/ids.db")

        cursor = conn.cursor()

        cursor.execute("""

        SELECT *

        FROM users

        WHERE username=?
        OR email=?

        """,(username,email))

        existing = cursor.fetchone()

        if existing:

            conn.close()

            error = "User already exists"

            return render_template(
                "signup.html",
                error=error
            )

        hashed_password = generate_password_hash(password)

        api_key = secrets.token_hex(16)

        cursor.execute("""

        INSERT INTO users (

            email,
            username,
            password,
            api_key

        )

        VALUES (?,?,?,?)

        """,(

            email,
            username,
            hashed_password,
            api_key

        ))

        conn.commit()

        conn.close()

        return redirect("/login")

    return render_template(
        "signup.html",
        error=error
    )

# ---------------- LOGOUT ----------------

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect("/login")

# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template("dashboard.html")

# ---------------- LOGS PAGE ----------------

@app.route("/logs")
@login_required
def logs():

    return render_template("logs.html")

# ---------------- PACKETS PAGE ----------------

@app.route("/packets")
@login_required
def packets():

    return render_template("packets.html")

# ---------------- ANALYTICS PAGE ----------------

@app.route("/analytics")
@login_required
def analytics():

    return render_template("analytics.html")

# ---------------- SETTINGS PAGE ----------------

@app.route("/settings")
@login_required
def settings():

    return render_template("settings.html")

# ---------------- ABOUT PAGE ----------------

@app.route("/about")
@login_required
def about():

    return render_template("about.html")

# ---------------- API KEY PAGE ----------------

@app.route("/api_key")
@login_required
def api_key():

    conn = sqlite3.connect("database/ids.db")

    cursor = conn.cursor()

    cursor.execute("""

    SELECT api_key

    FROM users

    WHERE id=?

    """,(current_user.id,))

    key = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "api_key.html",
        api_key=key
    )

# ---------------- DOWNLOAD AGENT ----------------

@app.route("/download_agent")
@login_required
def download_agent():

    conn = sqlite3.connect("database/ids.db")

    cursor = conn.cursor()

    cursor.execute("""

    SELECT api_key

    FROM users

    WHERE id=?

    """,(current_user.id,))

    api_key = cursor.fetchone()[0]

    conn.close()

    with open("agents/agent_template.py","r") as f:

        content = f.read()

    content = content.replace(
        "__API_KEY__",
        api_key
    )

    output_path = "agents/generated_agent.py"

    with open(output_path,"w") as f:

        f.write(content)

    return send_file(
        output_path,
        as_attachment=True
    )

# ---------------- RECEIVE LOGS ----------------

@app.route("/api/log", methods=["POST"])
def receive_log():

    data = request.json

    api_key = data.get("api_key")

    conn = sqlite3.connect("database/ids.db")

    cursor = conn.cursor()

    cursor.execute("""

    SELECT id

    FROM users

    WHERE api_key=?

    """,(api_key,))

    user = cursor.fetchone()

    if not user:

        conn.close()

        return jsonify({

            "error":"Invalid API key"

        }),401

    user_id = user[0]

    cursor.execute("""

    INSERT INTO logs (

        user_id,
        source_ip,
        destination_ip,
        protocol,
        packet_size,
        status,
        severity

    )

    VALUES (?, ?, ?, ?, ?, ?, ?)

    """, (

        user_id,
        data["source_ip"],
        data["destination_ip"],
        data["protocol"],
        data["packet_size"],
        data["status"],
        data["severity"]

    ))

    conn.commit()

    conn.close()

    return jsonify({

        "message":"Log received"

    })

# ---------------- GET LOGS ----------------

@app.route("/get_logs")
@login_required
def get_logs():

    conn = sqlite3.connect("database/ids.db")

    cursor = conn.cursor()

    cursor.execute("""

    SELECT
    source_ip,
    destination_ip,
    protocol,
    packet_size,
    status,
    severity,
    timestamp

    FROM logs

    WHERE user_id=?

    ORDER BY id DESC

    LIMIT 50

    """,(current_user.id,))

    rows = cursor.fetchall()

    conn.close()

    logs = []

    for row in rows:

        logs.append({

            "source_ip": row[0],
            "destination_ip": row[1],
            "protocol": row[2],
            "packet_size": row[3],
            "status": row[4],
            "severity": row[5],
            "timestamp": row[6]

        })

    return jsonify(logs)

# ---------------- STATS ----------------

@app.route("/stats")
@login_required
def stats():

    conn = sqlite3.connect("database/ids.db")

    cursor = conn.cursor()

    cursor.execute("""

    SELECT COUNT(*)

    FROM logs

    WHERE status='Attack Detected'
    AND user_id=?

    """,(current_user.id,))

    attacks = cursor.fetchone()[0]

    cursor.execute("""

    SELECT COUNT(*)

    FROM logs

    WHERE status='Normal Traffic'
    AND user_id=?

    """,(current_user.id,))

    normal = cursor.fetchone()[0]

    conn.close()

    return jsonify({

        "normal": normal,
        "attacks": attacks

    })

# ---------------- TOP ATTACKERS ----------------

@app.route("/top_attackers")
@login_required
def top_attackers():

    conn = sqlite3.connect("database/ids.db")

    cursor = conn.cursor()

    cursor.execute("""

    SELECT
    source_ip,
    COUNT(*) as total

    FROM logs

    WHERE status='Attack Detected'
    AND user_id=?

    GROUP BY source_ip

    ORDER BY total DESC

    LIMIT 5

    """,(current_user.id,))

    rows = cursor.fetchall()

    conn.close()

    attackers = []

    for row in rows:

        attackers.append({

            "ip": row[0],

            "count": row[1]

        })

    return jsonify(attackers)

# ---------------- GET PACKETS ----------------

@app.route("/get_packets")
@login_required
def get_packets():

    conn = sqlite3.connect("database/ids.db")

    cursor = conn.cursor()

    cursor.execute("""

    SELECT
    source_ip,
    destination_ip,
    protocol,
    packet_size,
    status

    FROM logs

    WHERE user_id=?

    ORDER BY id DESC

    LIMIT 50

    """,(current_user.id,))

    rows = cursor.fetchall()

    conn.close()

    packets = []

    for row in rows:

        packets.append({

            "source_ip": row[0],
            "destination_ip": row[1],
            "protocol": row[2],
            "packet_size": row[3],
            "status": row[4]

        })

    return jsonify(packets)

# ---------------- MAIN ----------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )