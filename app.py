from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
import sqlite3
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = "login-attempt-control-secret-key"

DATABASE = "security.db"

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------------------------------
# INITIALIZE DATABASE
# --------------------------------------------------

def init_db():

    conn = get_db()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Login attempts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            last_attempt TEXT
        )
    """)

    # Audit logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            event TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    # Create demo admin account
    user = cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if user is None:

        password_hash = generate_password_hash("Admin@123")

        cursor.execute("""
            INSERT INTO users (username, password)
            VALUES (?, ?)
        """, ("admin", password_hash))

    conn.commit()
    conn.close()


# --------------------------------------------------
# AUDIT LOGGING
# --------------------------------------------------

def log_event(username, ip_address, event):

    conn = get_db()

    conn.execute("""
        INSERT INTO audit_logs
        (username, ip_address, event, timestamp)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        ip_address,
        event,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# --------------------------------------------------
# GET LOGIN ATTEMPT RECORD
# --------------------------------------------------

def get_attempt_record(username, ip_address):

    conn = get_db()

    record = conn.execute("""
        SELECT *
        FROM login_attempts
        WHERE username = ?
        AND ip_address = ?
    """, (
        username,
        ip_address
    )).fetchone()

    conn.close()

    return record


# --------------------------------------------------
# RECORD FAILED LOGIN
# --------------------------------------------------

def record_failed_attempt(username, ip_address):

    conn = get_db()

    record = conn.execute("""
        SELECT *
        FROM login_attempts
        WHERE username = ?
        AND ip_address = ?
    """, (
        username,
        ip_address
    )).fetchone()

    now = datetime.now()

    if record:

        attempts = record["failed_attempts"] + 1

        locked_until = None

        if attempts >= MAX_FAILED_ATTEMPTS:

            locked_until = (
                now + timedelta(minutes=LOCKOUT_MINUTES)
            ).strftime("%Y-%m-%d %H:%M:%S")

        conn.execute("""
            UPDATE login_attempts
            SET failed_attempts = ?,
                locked_until = ?,
                last_attempt = ?
            WHERE username = ?
            AND ip_address = ?
        """, (
            attempts,
            locked_until,
            now.strftime("%Y-%m-%d %H:%M:%S"),
            username,
            ip_address
        ))

    else:

        attempts = 1

        conn.execute("""
            INSERT INTO login_attempts
            (
                username,
                ip_address,
                failed_attempts,
                locked_until,
                last_attempt
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            username,
            ip_address,
            attempts,
            None,
            now.strftime("%Y-%m-%d %H:%M:%S")
        ))

    conn.commit()
    conn.close()

    return attempts


# --------------------------------------------------
# RESET LOGIN ATTEMPTS
# --------------------------------------------------

def reset_attempts(username, ip_address):

    conn = get_db()

    conn.execute("""
        DELETE FROM login_attempts
        WHERE username = ?
        AND ip_address = ?
    """, (
        username,
        ip_address
    ))

    conn.commit()
    conn.close()


# --------------------------------------------------
# CHECK ACCOUNT LOCK
# --------------------------------------------------

def check_lock(username, ip_address):

    record = get_attempt_record(
        username,
        ip_address
    )

    if not record:
        return False, None

    locked_until = record["locked_until"]

    if not locked_until:
        return False, None

    lock_time = datetime.strptime(
        locked_until,
        "%Y-%m-%d %H:%M:%S"
    )

    now = datetime.now()

    if now < lock_time:

        remaining_seconds = int(
            (lock_time - now).total_seconds()
        )

        minutes = remaining_seconds // 60
        seconds = remaining_seconds % 60

        return True, f"{minutes} minutes {seconds} seconds"

    # Lock expired
    reset_attempts(
        username,
        ip_address
    )

    return False, None


# --------------------------------------------------
# LOGIN PAGE
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        ip_address = request.remote_addr

        # Empty fields
        if not username or not password:

            flash(
                "Please enter username and password.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        # Check lock
        locked, remaining = check_lock(
            username,
            ip_address
        )

        if locked:

            log_event(
                username,
                ip_address,
                "LOGIN BLOCKED - ACCOUNT LOCKED"
            )

            flash(
                f"Account locked. Try again after {remaining}.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        # Get user
        conn = get_db()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (
            username,
        )).fetchone()

        conn.close()

        # Unknown username
        if user is None:

            attempts = record_failed_attempt(
                username,
                ip_address
            )

            log_event(
                username,
                ip_address,
                f"FAILED LOGIN - UNKNOWN USER - ATTEMPT {attempts}"
            )

            if attempts >= MAX_FAILED_ATTEMPTS:

                log_event(
                    username,
                    ip_address,
                    "ACCOUNT LOCKED FOR 15 MINUTES"
                )

                flash(
                    "Too many failed attempts. Account locked for 15 minutes.",
                    "error"
                )

            else:

                remaining_attempts = (
                    MAX_FAILED_ATTEMPTS - attempts
                )

                flash(
                    f"Invalid credentials. "
                    f"{remaining_attempts} attempts remaining.",
                    "error"
                )

            return redirect(
                url_for("login")
            )

        # Correct password
        if check_password_hash(
            user["password"],
            password
        ):

            reset_attempts(
                username,
                ip_address
            )

            log_event(
                username,
                ip_address,
                "SUCCESSFUL LOGIN"
            )

            session["username"] = username

            return redirect(
                url_for("dashboard")
            )

        # Wrong password
        attempts = record_failed_attempt(
            username,
            ip_address
        )

        log_event(
            username,
            ip_address,
            f"FAILED LOGIN - ATTEMPT {attempts}"
        )

        # Lock account after 5 failures
        if attempts >= MAX_FAILED_ATTEMPTS:

            log_event(
                username,
                ip_address,
                "ACCOUNT LOCKED FOR 15 MINUTES"
            )

            flash(
                "Too many failed attempts. "
                "Account locked for 15 minutes.",
                "error"
            )

        else:

            remaining_attempts = (
                MAX_FAILED_ATTEMPTS - attempts
            )

            flash(
                f"Invalid password. "
                f"{remaining_attempts} attempts remaining.",
                "error"
            )

        return redirect(
            url_for("login")
        )

    return render_template(
        "login.html"
    )


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():

    if "username" not in session:

        return redirect(
            url_for("login")
        )

    conn = get_db()

    logs = conn.execute("""
        SELECT *
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        logs=logs
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    username = session.get(
        "username"
    )

    if username:

        log_event(
            username,
            request.remote_addr,
            "USER LOGOUT"
        )

    session.clear()

    return redirect(
        url_for("login")
    )


# --------------------------------------------------
# CSS ROUTE
# CSS IS STORED INSIDE templates/
# --------------------------------------------------

@app.route("/style.css")
def style_css():

    css_path = os.path.join(
        app.root_path,
        "templates",
        "style.css"
    )

    with open(
        css_path,
        "r",
        encoding="utf-8"
    ) as file:

        css = file.read()

    return Response(
        css,
        mimetype="text/css"
    )


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    init_db()

    print("\n" + "=" * 60)
    print("LOGIN ATTEMPT CONTROL SYSTEM")
    print("=" * 60)
    print("Username : admin")
    print("Password : Admin@123")
    print("Attempts : 5")
    print("Lockout  : 15 minutes")
    print("URL      : http://127.0.0.1:5000")
    print("CSS      : http://127.0.0.1:5000/style.css")
    print("=" * 60 + "\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )