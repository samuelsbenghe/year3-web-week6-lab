import ipaddress
import requests

import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# The secret key is used to sign session cookies so users cannot tamper with them
app.secret_key = "development-secret-key-change-in-production"

DATABASE = "threatmap.db"


def get_db():
    """Connects to SQLite and returns rows that behave like Python dictionaries."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates our database tables on first launch."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lookups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                city TEXT,
                country TEXT,
                lat REAL,
                lon REAL,
                x REAL,
                y REAL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        """)
        conn.commit()


# Run database setup immediately
init_db()


def login_required(f):
    """A decorator that ensures a user is logged in before accessing a route."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))

        hashed = generate_password_hash(password)
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, hashed),
                )
                conn.commit()
            flash("Account created! Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for("register"))

    return render_template("index.html.j2", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")
        return redirect(url_for("login"))

    return render_template("index.html.j2", mode="login")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("login"))


def is_safe_public_ip(ip_str):
    """Validates that a string is a real IP and is safe to query externally."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        # is_global ensures it is not localhost (127.0.0.1) or private (192.168.x.x, 10.x.x.x)
        return ip.is_global
    except ValueError:
        return False


def get_coordinates(ip_str):
    """Queries a free public API for IP coordinate data."""
    url = f"http://ip-api.com/json/{ip_str}"
    try:
        res = requests.get(url, timeout=3.0)
        data = res.json()
        if data.get("status") == "success":
            return {
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "city": data.get("city", "Unknown"),
                "country": data.get("country", "Unknown"),
            }
    except requests.RequestException:
        pass
    return None


def project_lat_lon(lat, lon, width=800, height=400):
    """Converts Latitude/Longitude degrees to (x, y) pixels on our map."""
    x = (lon + 180.0) * (width / 360.0)
    y = (90.0 - lat) * (height / 180.0)
    return round(x, 1), round(y, 1)


@app.route("/", methods=["GET", "POST"])
@login_required
def dashboard():
    if request.method == "POST":
        target_ip = request.form.get("ip", "").strip()

        if not is_safe_public_ip(target_ip):
            flash(
                "Invalid or private IP address. Please enter a public address (e.g. 8.8.8.8)."
            )
            return redirect(url_for("dashboard"))

        geo = get_coordinates(target_ip)
        if not geo:
            flash("Could not locate that IP address.")
            return redirect(url_for("dashboard"))

        # Calculate map coordinates
        px_x, px_y = project_lat_lon(geo["lat"], geo["lon"])

        # Persist into SQLite using safe parameterized bindings (?)
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO lookups (user_id, ip, city, country, lat, lon, x, y)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session["user_id"],
                    target_ip,
                    geo["city"],
                    geo["country"],
                    geo["lat"],
                    geo["lon"],
                    px_x,
                    px_y,
                ),
            )
            conn.commit()

        flash(f"Plotted {target_ip} in {geo['city']}, {geo['country']}!")
        return redirect(url_for("dashboard"))

    # Fetch past searches for this user
    with get_db() as conn:
        history = conn.execute(
            "SELECT * FROM lookups WHERE user_id = ? ORDER BY id DESC",
            (session["user_id"],),
        ).fetchall()

    return render_template("index.html.j2", mode="dashboard", history=history)


if __name__ == "__main__":
    app.run(port=5001, debug=True)
