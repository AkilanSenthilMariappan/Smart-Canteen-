from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import secrets
import os
import re
import hmac
import hashlib
import smtplib
from email.message import EmailMessage
from functools import wraps
from pathlib import Path
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo
import sys
from getpass import getpass
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf


def load_local_env():
    """Load simple KEY=VALUE settings from a local .env file without extra dependencies."""
    env_file = Path(__file__).with_name(".env")
    if not env_file.exists():
        return
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


load_local_env()
app = Flask(__name__)

csrf = CSRFProtect(app)
@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generate_csrf}

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY must be configured before starting the app."
    )
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)
COLLEGE_EMAIL_DOMAIN = os.environ.get(
    "COLLEGE_EMAIL_DOMAIN", "psnacet.edu.in"
).strip().lower().lstrip("@")
OTP_LIFETIME_SECONDS = 5 * 60
OTP_RESEND_SECONDS = 60
OTP_MAX_ATTEMPTS = 5

DATABASE = Path(__file__).with_name("canteen.db")
STUDENT_DATABASE = Path(__file__).with_name("student.db")
INDIA_TZ = ZoneInfo("Asia/Kolkata")
UTC_TZ = ZoneInfo("UTC")


# --------------------------------------------------
# CANTEEN MENU
# --------------------------------------------------

menu_items = [
    {"id": 1, "name": "Idli (2 pcs)", "price": 20, "category": "Breakfast", "available": True},
    {"id": 2, "name": "Masala Dosa", "price": 40, "category": "Breakfast", "available": True},
    {"id": 3, "name": "Veg Meals", "price": 80, "category": "Lunch", "available": True},
    {"id": 4, "name": "Chicken Biryani", "price": 100, "category": "Lunch", "available": True},
    {"id": 5, "name": "Lemon Juice", "price": 25, "category": "Drinks", "available": True},
    {"id": 6, "name": "Samosa", "price": 15, "category": "Snacks", "available": False},
]


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def init_database():
    """Create tables and safely upgrade the existing database without deleting data."""
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS staff_users (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS email_otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL COLLATE NOCASE,
                purpose TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                total INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS order_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL,
                menu_item_id INTEGER NOT NULL,
                item_name TEXT NOT NULL,
                unit_price INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders(id)
            )
        """)

        columns = {row[1] for row in conn.execute("PRAGMA table_info(orders)").fetchall()}
        if "student_id" not in columns:
            conn.execute("ALTER TABLE orders ADD COLUMN student_id INTEGER REFERENCES students(id)")
        if "qr_token" not in columns:
            conn.execute("ALTER TABLE orders ADD COLUMN qr_token TEXT")
        if "pickup_code" not in columns:
            conn.execute("ALTER TABLE orders ADD COLUMN pickup_code TEXT")

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_qr_token
            ON orders(qr_token)
        """)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_pickup_code
            ON orders(pickup_code)
        """)


# --------------------------------------------------
# PICKUP CODE
# --------------------------------------------------

def generate_pickup_code(connection):
    """Generate a unique six-digit code, stored as TEXT to preserve leading zeroes."""
    for _ in range(50):
        code = f"{secrets.randbelow(1_000_000):06d}"
        existing = connection.execute(
            "SELECT 1 FROM orders WHERE pickup_code = ?", (code,)
        ).fetchone()
        if existing is None:
            return code
    raise RuntimeError("Could not generate a unique pickup code.")


# --------------------------------------------------
# BOOKING HOURS
# --------------------------------------------------

def is_booking_open():
    """Accept afternoon orders from 11:45 AM until 12:35 PM Indian time."""
    current_time = datetime.now(INDIA_TZ).time()
    opening_time = time(11, 45)
    closing_time = time(23, 55)
    return opening_time <= current_time < closing_time


# --------------------------------------------------
# AUTHENTICATION HELPERS
# --------------------------------------------------

def clear_student_session():
    """Remove only student authentication keys, preserving staff auth if present."""
    for key in ("student_id", "student_email", "student_name"):
        session.pop(key, None)


def clear_staff_session():
    """Remove only staff authentication keys, preserving student auth if present."""
    for key in ("staff_id", "staff_username"):
        session.pop(key, None)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("student_id"):
            if request.path.startswith("/api/"):
                return jsonify({
                    "error": "Please sign in to continue.",
                    "login_url": url_for("login_page")
                }), 401
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)
    return wrapped


def staff_login_required(view):
    """Require the shared staff account for staff pages and APIs."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("staff_id"):
            if request.path.startswith("/api/"):
                return jsonify({
                    "error": "Staff sign-in required.",
                    "login_url": url_for("staff_login_page")
                }), 401
            return redirect(url_for("staff_login_page"))
        return view(*args, **kwargs)
    return wrapped


def valid_college_email(email):
    if not isinstance(email, str):
        return False
    email = email.strip().lower()
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+", email):
        return False
    return email.endswith("@" + COLLEGE_EMAIL_DOMAIN)


def otp_digest(email, purpose, otp):
    key = app.secret_key.encode("utf-8")
    value = f"{email.lower()}|{purpose}|{otp}".encode("utf-8")
    return hmac.new(key, value, hashlib.sha256).hexdigest()


def send_email_otp(email, otp, purpose):
    host = os.environ.get("SMTP_HOST", "").strip()
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    sender = os.environ.get("SMTP_FROM", username).strip()
    port = int(os.environ.get("SMTP_PORT", "587"))

    if not host or not sender:
        raise RuntimeError(
            "Email delivery is not configured yet. Set SMTP_HOST, SMTP_USERNAME, "
            "SMTP_PASSWORD, and SMTP_FROM in your environment."
        )

    action = (
        "create your Smart Canteen account"
        if purpose == "register"
        else "reset your Smart Canteen password"
    )
    message = EmailMessage()
    message["Subject"] = "Your Smart Canteen verification code"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Your OTP to {action} is: {otp}\n\n"
        f"This code expires in 5 minutes and can be used only once.\n"
        "If you did not request this code, you can ignore this email."
    )

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=15) as server:
            if username:
                server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            if username:
                server.login(username, password)
            server.send_message(message)


def json_error(message, status=400):
    return jsonify({"error": message}), status


# --------------------------------------------------
# STUDENT PAGES / LOGOUT
# --------------------------------------------------

@app.route("/login")
def login_page():
    if session.get("student_id"):
        return redirect(url_for("home"))
    return render_template("login.html", email_domain=COLLEGE_EMAIL_DOMAIN)


@app.route("/logout", methods=["POST", "GET"])
def logout():
    clear_student_session()
    return redirect(url_for("login_page"))


# --------------------------------------------------
# EMAIL OTP
# --------------------------------------------------

@app.route("/api/auth/request-otp", methods=["POST"])
def request_registration_otp():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    purpose = str(data.get("purpose", "register")).strip().lower()

    if purpose not in ("register", "reset"):
        return json_error("Invalid verification request.")
    if not valid_college_email(email):
        return json_error(f"Use your college email ending in @{COLLEGE_EMAIL_DOMAIN}.")

    now = datetime.now(UTC_TZ)
    with sqlite3.connect(DATABASE) as conn:
        student = conn.execute(
            "SELECT id FROM students WHERE email = ?", (email,)
        ).fetchone()
        if purpose == "register" and student:
            return json_error("An account already exists for this email. Please sign in.", 409)
        if purpose == "reset" and not student:
            return jsonify({
                "message": "If the account exists, a verification code will be sent."
            }), 200

        recent = conn.execute("""
            SELECT created_at FROM email_otps
            WHERE email = ? AND purpose = ? ORDER BY id DESC LIMIT 1
        """, (email, purpose)).fetchone()
        if recent:
            try:
                previous = datetime.fromisoformat(recent[0])
                elapsed = (now - previous).total_seconds()
                if elapsed < OTP_RESEND_SECONDS:
                    wait = max(1, OTP_RESEND_SECONDS - int(elapsed))
                    return json_error(
                        f"Please wait {wait} seconds before requesting another code.", 429
                    )
            except ValueError:
                pass

        otp = f"{secrets.randbelow(1_000_000):06d}"
        conn.execute(
            "DELETE FROM email_otps WHERE email = ? AND purpose = ?", (email, purpose)
        )
        conn.execute("""
            INSERT INTO email_otps
                (email, purpose, otp_hash, expires_at, attempts, created_at)
            VALUES (?, ?, ?, ?, 0, ?)
        """, (
            email, purpose, otp_digest(email, purpose, otp),
            (now + timedelta(seconds=OTP_LIFETIME_SECONDS)).isoformat(),
            now.isoformat()
        ))

    try:
        send_email_otp(email, otp, purpose)
    except Exception as exc:
        app.logger.exception("OTP email delivery failed")
        with sqlite3.connect(DATABASE) as conn:
            conn.execute(
                "DELETE FROM email_otps WHERE email = ? AND purpose = ?", (email, purpose)
            )
        if isinstance(exc, RuntimeError):
            return json_error(str(exc), 503)
        return json_error(
            "Could not send the email. Check your SMTP settings and try again.", 503
        )

    return jsonify({
        "message": "OTP sent. It expires in 5 minutes.",
        "expires_in": OTP_LIFETIME_SECONDS
    }), 200


def consume_otp(email, purpose, otp):
    now = datetime.now(UTC_TZ)
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("""
            SELECT id, otp_hash, expires_at, attempts FROM email_otps
            WHERE email = ? AND purpose = ? ORDER BY id DESC LIMIT 1
        """, (email, purpose)).fetchone()

        if row is None:
            return False, "Request a new verification code."

        try:
            expires = datetime.fromisoformat(row["expires_at"])
        except ValueError:
            expires = now

        if now >= expires:
            conn.execute("DELETE FROM email_otps WHERE id = ?", (row["id"],))
            return False, "This code has expired. Request a new one."
        if row["attempts"] >= OTP_MAX_ATTEMPTS:
            conn.execute("DELETE FROM email_otps WHERE id = ?", (row["id"],))
            return False, "Too many incorrect attempts. Request a new code."
        if not hmac.compare_digest(row["otp_hash"], otp_digest(email, purpose, otp)):
            conn.execute(
                "UPDATE email_otps SET attempts = attempts + 1 WHERE id = ?",
                (row["id"],)
            )
            remaining = OTP_MAX_ATTEMPTS - row["attempts"] - 1
            return False, f"Incorrect code. You have {remaining} attempt(s) left."

        conn.execute("DELETE FROM email_otps WHERE id = ?", (row["id"],))
        return True, "Email verified."


@app.route("/api/auth/verify-otp", methods=["POST"])
def verify_email_otp():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    purpose = str(data.get("purpose", "register")).strip().lower()
    otp = str(data.get("otp", "")).strip()

    if (
        not valid_college_email(email)
        or purpose not in ("register", "reset")
        or not re.fullmatch(r"\d{6}", otp)
    ):
        return json_error("Enter your college email and the six-digit code.")

    ok, message = consume_otp(email, purpose, otp)
    if not ok:
        return json_error(message)

    session["verified_email"] = email
    session["verified_purpose"] = purpose
    session["verified_at"] = datetime.now(UTC_TZ).isoformat()
    return jsonify({"message": message}), 200


def verification_is_valid(email, purpose):
    if (
        session.get("verified_email") != email
        or session.get("verified_purpose") != purpose
    ):
        return False
    try:
        verified_at = datetime.fromisoformat(session.get("verified_at", ""))
        age = (datetime.now(UTC_TZ) - verified_at).total_seconds()
        return 0 <= age <= 10 * 60
    except ValueError:
        return False


# --------------------------------------------------
# STUDENT REGISTER / LOGIN / PASSWORD RESET
# --------------------------------------------------

@app.route("/api/auth/register", methods=["POST"])
def register_student():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    name = str(data.get("name", "")).strip()
    password = data.get("password", "")

    if not valid_college_email(email):
        return json_error(f"Use your college email ending in @{COLLEGE_EMAIL_DOMAIN}.")
    if not verification_is_valid(email, "register"):
        return json_error("Verify your email with a fresh OTP before creating your account.", 403)
    if not name or len(name) > 80:
        return json_error("Enter a name between 1 and 80 characters.")
    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return json_error("Password must contain between 8 and 128 characters.")

    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute(
                "INSERT INTO students (email, name, password_hash) VALUES (?, ?, ?)",
                (email, name, generate_password_hash(password))
            )
            student_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return json_error("An account already exists for this email. Please sign in.", 409)

    clear_student_session()
    session.permanent = True
    session["student_id"] = student_id
    session["student_email"] = email
    session["student_name"] = name
    session.pop("verified_email", None)
    session.pop("verified_purpose", None)
    session.pop("verified_at", None)
    return jsonify({
        "message": "Account created successfully.",
        "redirect": url_for("home")
    }), 201


@app.route("/api/auth/login", methods=["POST"])
def login_student():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not valid_college_email(email) or not isinstance(password, str):
        return json_error("Enter a valid college email and password.")

    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        student = conn.execute(
            "SELECT id, email, name, password_hash FROM students WHERE email = ?",
            (email,)
        ).fetchone()

    if student is None or not check_password_hash(student["password_hash"], password):
        return json_error("Email or password is incorrect.", 401)

    clear_student_session()
    session.permanent = True
    session["student_id"] = student["id"]
    session["student_email"] = student["email"]
    session["student_name"] = student["name"]
    return jsonify({
        "message": "Signed in successfully.",
        "redirect": url_for("home")
    }), 200


@app.route("/api/auth/reset-password", methods=["POST"])
def reset_student_password():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not valid_college_email(email) or not verification_is_valid(email, "reset"):
        return json_error("Verify your email with a fresh OTP before resetting your password.", 403)
    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return json_error("Password must contain between 8 and 128 characters.")

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.execute(
            "UPDATE students SET password_hash = ? WHERE email = ?",
            (generate_password_hash(password), email)
        )
        if cursor.rowcount == 0:
            return json_error("Could not reset the password. Check the email and try again.", 404)

    clear_student_session()
    session.pop("verified_email", None)
    session.pop("verified_purpose", None)
    session.pop("verified_at", None)
    return jsonify({"message": "Password reset successfully. You can now sign in."}), 200


@app.route("/api/auth/me", methods=["GET"])
@login_required
def current_student():
    return jsonify({
        "id": session["student_id"],
        "email": session["student_email"],
        "name": session["student_name"]
    })


@app.route("/api/auth/profile", methods=["POST"])
@login_required
def update_student_profile():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name or len(name) > 80:
        return json_error("Enter a name between 1 and 80 characters.")

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.execute(
            "UPDATE students SET name = ? WHERE id = ?",
            (name, session["student_id"])
        )
        if cursor.rowcount != 1:
            return json_error("Could not update your profile. Please sign in again.", 404)

    session["student_name"] = name
    return jsonify({"message": "Your name has been updated.", "name": name}), 200


# --------------------------------------------------
# SHARED STAFF LOGIN
# --------------------------------------------------

@app.route("/staff/login", methods=["GET", "POST"])
def staff_login_page():
    if session.get("staff_id"):
        return redirect(url_for("admin"))

    error = None
    if request.method == "POST":
        username = str(request.form.get("username", "")).strip()
        password = request.form.get("password", "")

        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            staff = conn.execute(
                "SELECT id, username, password_hash FROM staff_users WHERE id = 1"
            ).fetchone()

        if (
            staff is None
            or not isinstance(password, str)
            or not hmac.compare_digest(username.casefold(), staff["username"].casefold())
            or not check_password_hash(staff["password_hash"], password)
        ):
            error = "Username or password is incorrect."
        else:
            # Keep any student login in the same browser session.
            clear_staff_session()
            session.permanent = True
            session["staff_id"] = staff["id"]
            session["staff_username"] = staff["username"]
            return redirect(url_for("admin"))

    return render_template("staff_login.html", error=error)


@app.route("/staff/logout", methods=["POST"])
@staff_login_required
def staff_logout():
    clear_staff_session()
    return redirect(url_for("staff_login_page"))


# --------------------------------------------------
# STUDENT HOME / BOOKINGS
# --------------------------------------------------

@app.route("/")
@login_required
def home():
    return render_template(
        "index.html",
        menu_items=menu_items,
        student_name=session.get("student_name", "Student"),
        student_email=session.get("student_email", "")
    )


@app.route("/booking")
@login_required
def booking():
    return render_template(
        "booking.html",
        student_name=session.get("student_name", "Student")
    )


# --------------------------------------------------
# ADMIN DASHBOARD AND ANALYTICS
# --------------------------------------------------

@app.route("/admin")
@staff_login_required
def admin():
    today = datetime.now(INDIA_TZ).date()

    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        orders = connection.execute("""
            SELECT id, total, status, created_at
            FROM orders
            ORDER BY id DESC
        """).fetchall()

        order_items_by_id = {}
        for order in orders:
            items = connection.execute("""
                SELECT item_name, unit_price, quantity
                FROM order_items
                WHERE order_id = ?
            """, (order["id"],)).fetchall()
            order_items_by_id[order["id"]] = items

    today_orders = 0
    today_sales = 0
    items_sold_today = 0

    for order in orders:
        try:
            order_datetime = datetime.fromisoformat(order["created_at"])
            if order_datetime.tzinfo is None:
                order_datetime = order_datetime.replace(tzinfo=UTC_TZ)
            order_date_india = order_datetime.astimezone(INDIA_TZ).date()
        except (ValueError, TypeError):
            app.logger.warning(
                "Could not interpret created_at for order %s", order["id"]
            )
            continue

        if order_date_india == today:
            today_orders += 1
            today_sales += order["total"]
            for item in order_items_by_id[order["id"]]:
                items_sold_today += item["quantity"]

    return render_template(
        "admin.html",
        orders=orders,
        order_items_by_id=order_items_by_id,
        today_orders=today_orders,
        today_sales=today_sales,
        items_sold_today=items_sold_today,
    )


# --------------------------------------------------
# CREATE STUDENT ORDER
# --------------------------------------------------

@app.route("/api/orders", methods=["POST"])
@login_required
def create_order():
    if not is_booking_open():
        return jsonify({
            "error": (
                "Booking is currently closed. Please try between "
                "11:45 AM and 12:35 PM IST."
            )
        }), 403

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid order data."}), 400

    items = data.get("items")
    if not isinstance(items, list) or not items:
        return jsonify({"error": "Your cart is empty."}), 400

    validated_items = []
    seen_ids = set()
    total = 0
    menu_by_id = {item["id"]: item for item in menu_items}

    for entry in items:
        if not isinstance(entry, dict):
            return jsonify({"error": "Invalid item in your cart."}), 400

        item_id = entry.get("id")
        quantity = entry.get("quantity")
        if (
            isinstance(item_id, bool)
            or not isinstance(item_id, int)
            or item_id not in menu_by_id
        ):
            return jsonify({"error": "Invalid menu item."}), 400
        if (
            isinstance(quantity, bool)
            or not isinstance(quantity, int)
            or quantity < 1
            or quantity > 50
        ):
            return jsonify({"error": "Invalid item quantity."}), 400
        if item_id in seen_ids:
            return jsonify({"error": "Duplicate menu item."}), 400

        seen_ids.add(item_id)
        menu_item = menu_by_id[item_id]
        if not menu_item["available"]:
            return jsonify({"error": f'{menu_item["name"]} is unavailable.'}), 400

        total += menu_item["price"] * quantity
        validated_items.append({
            "id": item_id,
            "name": menu_item["name"],
            "price": menu_item["price"],
            "quantity": quantity,
        })

    qr_token = secrets.token_urlsafe(32)
    try:
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            pickup_code = generate_pickup_code(connection)
            cursor = connection.execute("""
                INSERT INTO orders (total, status, qr_token, pickup_code, student_id)
                VALUES (?, ?, ?, ?, ?)
            """, (
                total, "pending", qr_token, pickup_code, session["student_id"]
            ))
            order_id = cursor.lastrowid

            for item in validated_items:
                connection.execute("""
                    INSERT INTO order_items
                        (order_id, menu_item_id, item_name, unit_price, quantity)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    order_id, item["id"], item["name"],
                    item["price"], item["quantity"]
                ))

        return jsonify({
            "order_id": order_id,
            "total": total,
            "status": "pending",
            "qr_token": qr_token,
            "pickup_code": pickup_code,
            "items": validated_items,
        }), 201

    except sqlite3.Error:
        app.logger.exception("Could not save the canteen order.")
        return jsonify({"error": "Could not save your order. Please try again."}), 500
    except RuntimeError:
        app.logger.exception("Could not generate a unique pickup code.")
        return jsonify({"error": "Could not generate a pickup code. Please try again."}), 500


# --------------------------------------------------
# VERIFY QR CODE / PICKUP CODE
# --------------------------------------------------

@app.route("/api/orders/verify", methods=["POST"])
@staff_login_required
def verify_order():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid scan data."}), 400

    qr_token = data.get("qr_token")
    if not isinstance(qr_token, str) or not qr_token.strip() or len(qr_token) > 200:
        return jsonify({"error": "Invalid QR code."}), 400
    qr_token = qr_token.strip()

    try:
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            connection.execute("BEGIN IMMEDIATE")
            order = connection.execute(
                "SELECT id, status FROM orders WHERE qr_token = ?", (qr_token,)
            ).fetchone()
            if order is None:
                return jsonify({"error": "Invalid QR code."}), 404

            order_id, status = order
            if status == "successful":
                return jsonify({
                    "error": "This order has already been collected.",
                    "order_id": order_id,
                    "status": status
                }), 409
            if status != "pending":
                return jsonify({
                    "error": "This order cannot be collected.", "status": status
                }), 409

            connection.execute(
                "UPDATE orders SET status = 'successful' WHERE id = ? AND status = 'pending'",
                (order_id,)
            )

        return jsonify({
            "message": "QR verified. The order is ready for handover.",
            "order_id": order_id,
            "status": "successful"
        }), 200
    except sqlite3.Error:
        app.logger.exception("Could not verify the QR code.")
        return jsonify({"error": "Verification failed. Please try again."}), 500


@app.route("/api/orders/verify-code", methods=["POST"])
@staff_login_required
def verify_order_code():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid verification data."}), 400

    pickup_code = data.get("pickup_code")
    if (
        not isinstance(pickup_code, str)
        or len(pickup_code) != 6
        or not pickup_code.isdigit()
    ):
        return jsonify({"error": "Enter a valid six-digit pickup code."}), 400

    try:
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            connection.execute("BEGIN IMMEDIATE")
            order = connection.execute(
                "SELECT id, status FROM orders WHERE pickup_code = ?", (pickup_code,)
            ).fetchone()
            if order is None:
                return jsonify({"error": "Pickup code not found."}), 404

            order_id, status = order
            if status == "successful":
                return jsonify({
                    "error": "This order has already been collected.",
                    "order_id": order_id,
                    "status": status
                }), 409
            if status != "pending":
                return jsonify({
                    "error": "This order cannot be collected.", "status": status
                }), 409

            connection.execute(
                "UPDATE orders SET status = 'successful' WHERE id = ? AND status = 'pending'",
                (order_id,)
            )

        return jsonify({
            "message": "Pickup code verified successfully.",
            "order_id": order_id,
            "status": "successful"
        }), 200
    except sqlite3.Error:
        app.logger.exception("Pickup code verification failed.")
        return jsonify({"error": "Verification failed. Please try again."}), 500


# --------------------------------------------------
# STUDENT ORDER HISTORY / STATUS / RECEIPT
# --------------------------------------------------

@app.route("/api/my-orders", methods=["GET"])
@login_required
def my_orders():
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        orders = connection.execute("""
            SELECT id, total, status, created_at, qr_token, pickup_code
            FROM orders WHERE student_id = ? ORDER BY id DESC
        """, (session["student_id"],)).fetchall()

        result = []
        for order in orders:
            rows = connection.execute("""
                SELECT item_name, unit_price, quantity FROM order_items
                WHERE order_id = ? ORDER BY id
            """, (order["id"],)).fetchall()
            result.append({
                "order_id": order["id"],
                "total": order["total"],
                "status": order["status"],
                "created_at": order["created_at"],
                "qr_token": order["qr_token"],
                "pickup_code": order["pickup_code"],
                "items": [
                    {"name": row["item_name"], "price": row["unit_price"], "quantity": row["quantity"]}
                    for row in rows
                ]
            })
    return jsonify({"orders": result}), 200


@app.route("/api/orders/<int:order_id>/status", methods=["GET"])
@login_required
def order_status(order_id):
    qr_token = request.args.get("token", "")
    if not qr_token or len(qr_token) > 200:
        return jsonify({"error": "Invalid status request."}), 400

    with sqlite3.connect(DATABASE) as connection:
        order = connection.execute("""
            SELECT status FROM orders
            WHERE id = ? AND qr_token = ? AND student_id = ?
        """, (order_id, qr_token, session["student_id"])).fetchone()

    if order is None:
        return jsonify({"error": "Order not found."}), 404
    return jsonify({"order_id": order_id, "status": order[0]}), 200


@app.route("/api/orders/<int:order_id>/receipt", methods=["GET"])
@login_required
def order_receipt(order_id):
    qr_token = request.args.get("token", "")
    if not qr_token or len(qr_token) > 200:
        return jsonify({"error": "Invalid receipt request."}), 400

    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        order = connection.execute("""
            SELECT id, total, status, qr_token, pickup_code
            FROM orders
            WHERE id = ? AND qr_token = ? AND student_id = ?
        """, (order_id, qr_token, session["student_id"])).fetchone()
        if order is None:
            return jsonify({"error": "Booking not found."}), 404

        rows = connection.execute("""
            SELECT item_name, unit_price, quantity FROM order_items
            WHERE order_id = ? ORDER BY id
        """, (order_id,)).fetchall()

    return jsonify({
        "order_id": order["id"],
        "total": order["total"],
        "status": order["status"],
        "pickup_code": order["pickup_code"],
        "items": [
            {"name": row["item_name"], "price": row["unit_price"], "quantity": row["quantity"]}
            for row in rows
        ]
    }), 200


# --------------------------------------------------
# STAFF ACCOUNT SETUP
# --------------------------------------------------

def set_staff_account():
    """Create or update the shared staff login without storing a plaintext password."""
    username = input("Staff username (not an email): ").strip()
    if not username or len(username) > 40:
        raise SystemExit("Username must contain 1 to 40 characters.")

    password = getpass("Staff password (minimum 8 characters): ")
    confirmation = getpass("Confirm staff password: ")

    if len(password) < 8:
        raise SystemExit("Use a password with at least 8 characters.")
    if len(password) > 128:
        raise SystemExit("Password must not exceed 128 characters.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    password_hash = generate_password_hash(password)
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("""
            INSERT INTO staff_users (id, username, password_hash, updated_at)
            VALUES (1, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
                username = excluded.username,
                password_hash = excluded.password_hash,
                updated_at = CURRENT_TIMESTAMP
        """, (username, password_hash))
    print("Staff account saved. Keep the password private.")


# Create/upgrade tables in-place. Do not delete canteen.db.
init_database()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "set-staff":
        set_staff_account()
    else:
        app.run(host="0.0.0.0", port=5000, debug=True)
