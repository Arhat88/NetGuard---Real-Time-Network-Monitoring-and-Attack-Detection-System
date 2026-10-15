from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from functools import wraps
import pandas as pd
import threading
import time

from database import get_connection, safe_execute, create_table
from auth import login, register
from flow_agg import start_sniffing, stop_sniffing
from retrainer import should_retrain, reset_alert_count
from model import retrain_model

app = Flask(__name__)
app.secret_key = "ids_secret_key_change_in_production"

# ─── Background retrainer ─────────────────────────────────────────────────────

def retrain_loop():
    while True:
        if should_retrain():
            print("⚙️  Retraining model...")
            retrain_model()
            reset_alert_count()
        time.sleep(60)

# ─── Auth decorator ───────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            # fetch() GET requests have no Content-Type, so is_json is always
            # False for API calls. Check the URL path instead so we always
            # return proper JSON 401 for /api/* routes, never an HTML redirect.
            if request.path.startswith("/api/") or request.is_json:
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

# ─── Pages ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))

@app.route("/model")
@login_required
def model_page():
    return render_template("model.html", username=session.get("username"))

# ─── Auth API ─────────────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "error": "Please fill all fields"}), 400

    user = login(username, password)
    if user:
        session["user_id"]  = user[0]
        session["username"] = user[1]
        return jsonify({"success": True})
    else:
        # Log failed attempt
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE username=?", (username,))
        row = cursor.fetchone()
        target_user_id = row[0] if row else None
        conn.close()

        safe_execute(
            """INSERT INTO alerts_logs (flow_id, alert_type, severity_level, status, message, handled_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (None, "Login Failure", "LOW", "NEW", f"Failed login attempt for {username}", target_user_id)
        )
        return jsonify({"success": False, "error": "Invalid credentials"}), 401


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    email    = data.get("email", "").strip()

    if not username or not password or not email:
        return jsonify({"success": False, "error": "Please fill all fields"}), 400

    if register(username, password, email):
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "User already exists"}), 409


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})

# ─── Sniffing API ─────────────────────────────────────────────────────────────

sniffer_thread = None

@app.route("/api/start", methods=["POST"])
@login_required
def api_start():
    global sniffer_thread
    if sniffer_thread and sniffer_thread.is_alive():
        return jsonify({"success": False, "error": "Already running"})
    user_id = session["user_id"]
    sniffer_thread = threading.Thread(
        target=start_sniffing, args=(user_id,), daemon=True
    )
    sniffer_thread.start()
    return jsonify({"success": True, "message": "Sniffing started"})


@app.route("/api/stop", methods=["POST"])
@login_required
def api_stop():
    stop_sniffing()
    return jsonify({"success": True, "message": "Sniffing stopped"})


last_retrain_time = None

@app.route("/api/status")
@login_required
def api_status():
    global sniffer_thread, last_retrain_time
    running = sniffer_thread is not None and sniffer_thread.is_alive()
    return jsonify({
        "running": running,
        "last_retrain": last_retrain_time
    })

# ─── Data API ─────────────────────────────────────────────────────────────────

@app.route("/api/flows")
@login_required
def api_flows():
    user_id = session["user_id"]
    conn = get_connection()
    df = pd.read_sql(
        """SELECT nf.*,
                  p.prediction_label,
                  p.attack_type,
                  p.confidence_score,
                  al.alert_type
           FROM network_flows nf
           LEFT JOIN predictions p ON nf.flow_id = p.flow_id
           LEFT JOIN (
               SELECT flow_id, MAX(alert_type) as alert_type 
               FROM alerts_logs 
               WHERE flow_id IS NOT NULL 
               GROUP BY flow_id
           ) al ON nf.flow_id = al.flow_id
           WHERE nf.user_id = ?
           ORDER BY nf.flow_id DESC""",
        conn, params=(user_id,)
    )
    conn.close()
    # Use pandas to_json() — it converts NaN→null natively.
    # jsonify(df.to_dict()) emits bare NaN tokens which are not valid JSON.
    return app.response_class(
        response=df.to_json(orient="records"),
        status=200,
        mimetype="application/json"
    )


@app.route("/api/pie_stats")
@login_required
def api_pie_stats():
    """Return aggregated prediction label counts for the pie chart."""
    user_id = session["user_id"]
    conn = get_connection()

    df = pd.read_sql(
        """SELECT COALESCE(al.alert_type, p.prediction_label, 'Normal') AS label, COUNT(*) AS cnt
           FROM network_flows nf
           LEFT JOIN predictions p ON nf.flow_id = p.flow_id
           LEFT JOIN (
               SELECT flow_id, MAX(alert_type) as alert_type 
               FROM alerts_logs 
               WHERE flow_id IS NOT NULL 
               GROUP BY flow_id
           ) al ON nf.flow_id = al.flow_id
           WHERE nf.user_id = ?
           GROUP BY label""",
        conn, params=(user_id,)
    )
    conn.close()

    # Normalise labels to title-case so 'dos' -> 'DoS', etc.
    label_map = {
        'normal': 'Normal', 'dos': 'DoS', 'probe': 'Probe',
        'r2l': 'R2L', 'u2r': 'U2R',
        'Normal': 'Normal', 'DoS': 'DoS', 'Probe': 'Probe',
        'R2L': 'R2L', 'U2R': 'U2R'
    }
    counts = {'Normal': 0, 'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0, 'Other': 0}
    for _, row in df.iterrows():
        canonical = label_map.get(str(row['label']), 'Other')
        counts[canonical] += int(row['cnt'])

    return jsonify(counts)


@app.route("/api/alerts")
@login_required
def api_alerts():
    user_id = session["user_id"]
    conn = get_connection()
    df = pd.read_sql(
        """SELECT al.* FROM alerts_logs al
           JOIN network_flows nf ON al.flow_id = nf.flow_id
           WHERE nf.user_id = ?
           ORDER BY log_id DESC""",
        conn, params=(user_id,)
    )
    # Also include login-failure alerts (flow_id IS NULL) without join
    df2 = pd.read_sql(
        """SELECT * FROM alerts_logs
            WHERE flow_id IS NULL
            ORDER BY log_id DESC""",
        conn
    )
    conn.close()
    combined = pd.concat([df, df2]).drop_duplicates("log_id").sort_values("log_id", ascending=False)
    return app.response_class(
        response=combined.to_json(orient="records"),
        status=200,
        mimetype="application/json"
    )


# ─── Startup ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    create_table()
    threading.Thread(target=retrain_loop, daemon=True).start()
    app.run(debug=True, host="0.0.0.0", port=5000)
