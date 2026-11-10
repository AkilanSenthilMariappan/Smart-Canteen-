from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import secrets
import os
import re
import hmac
import hashlib
from functools import wraps
from pathlib import Path
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo
import sys
from getpass import getpass
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf
import razorpay


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
def json_error(message, status=400):
    return jsonify({
        "error": message,
        "message": message
    }), status
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
    """Create tables and safely upgrade the existing database."""
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS menu_items (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                price INTEGER NOT NULL CHECK (price >= 0),
                category TEXT NOT NULL,
                available INTEGER NOT NULL DEFAULT 1
                    CHECK (available IN (0, 1)),
                stock INTEGER NOT NULL DEFAULT 0
                    CHECK (stock >= 0),
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Read existing order columns.
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(orders)"
            ).fetchall()
        }

        # Preserve existing order data and add missing columns.
        migrations = {
            "student_id": (
                "ALTER TABLE orders ADD COLUMN "
                "student_id INTEGER REFERENCES students(id)"
            ),
            "qr_token": (
                "ALTER TABLE orders ADD COLUMN qr_token TEXT"
            ),
            "pickup_code": (
                "ALTER TABLE orders ADD COLUMN pickup_code TEXT"
            ),
            "payment_status": (
                "ALTER TABLE orders ADD COLUMN "
                "payment_status TEXT NOT NULL DEFAULT 'unpaid'"
            ),
            "razorpay_order_id": (
                "ALTER TABLE orders ADD COLUMN razorpay_order_id TEXT"
            ),
            "razorpay_payment_id": (
                "ALTER TABLE orders ADD COLUMN razorpay_payment_id TEXT"
            ),
            "payment_verified_at": (
                "ALTER TABLE orders ADD COLUMN payment_verified_at TEXT"
            ),
        }

        for column, sql in migrations.items():
            if column not in columns:
                conn.execute(sql)

        # Preserve historical collected orders.
        conn.execute("""
            UPDATE orders
            SET payment_status = 'legacy'
            WHERE status = 'successful'
              AND payment_status = 'unpaid'
              AND razorpay_payment_id IS NULL
        """)

        # Prevent duplicate Razorpay references.
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_qr_token
            ON orders(qr_token)
        """)

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_pickup_code
            ON orders(pickup_code)
        """)

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_razorpay_order
            ON orders(razorpay_order_id)
        """)

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_razorpay_payment
            ON orders(razorpay_payment_id)
        """)

        # Seed the existing menu only when the menu table is empty.
        menu_count = conn.execute(
            "SELECT COUNT(*) FROM menu_items"
        ).fetchone()[0]

        if menu_count == 0:
            conn.executemany("""
                INSERT INTO menu_items
                    (id, name, price, category, available, stock)
                VALUES (?, ?, ?, ?, ?, 0)
            """, [
                (
                    item["id"],
                    item["name"],
                    item["price"],
                    item["category"],
                    int(item["available"])
                )
                for item in menu_items
            ])

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
    closing_time = time(23, 35)
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
    import json
    import os
    import urllib.error
    import urllib.request

    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    sender = os.environ.get(
        "RESEND_FROM", "onboarding@resend.dev"
    ).strip()

    if not api_key:
        raise RuntimeError("RESEND_API_KEY is not configured.")

    action = (
        "create your Smart Canteen account"
        if purpose == "register"
        else "reset your Smart Canteen password"
    )

    payload = {
        "from": sender,
        "to": [email],
        "subject": "Your Smart Canteen verification code",
        "text": (
            f"Your OTP to {action} is: {otp}\n\n"
            "This code expires in 5 minutes and can be used only once.\n"
            "If you did not request this code, ignore this email."
        ),
    }

    request = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "SmartCanteen/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status not in (200, 201):
                raise RuntimeError(
                    f"Email API returned status {response.status}."
                )

    except urllib.error.HTTPError as exc:
        # Read Resend's error response without exposing the API key or OTP.
        try:
            error_body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            error_body = "Could not read error response"

        # Log provider diagnostics for the developer, but never log the API key or OTP.
        app.logger.error("Resend API error (HTTP %s): %s", exc.code, error_body[:1000])
        if exc.code == 403:
            raise RuntimeError(
                "Resend rejected the email (HTTP 403). The testing sender "
                "onboarding@resend.dev can only send to the Resend account owner's "
                "email until you verify a domain and set RESEND_FROM to an address "
                "on that verified domain. Check the server log for Resend's details."
            ) from None
        raise RuntimeError(
            f"Email API rejected the request (HTTP {exc.code}). "
            "Check the server logs for the Resend error details."
        ) from None
    except urllib.error.URLError as exc:
        raise RuntimeError(
            "Could not connect to the email API. Check network connectivity."
        ) from None



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
        app.logger.info("Student account found in database: %s", student is not None)
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
            "Could not send the email. Check the Resend API settings and sender verification, then try again.", 503
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
        password_matches = (
            check_password_hash(student["password_hash"], password)
        if student is not None
        else False
)

    app.logger.warning(
        "LOGIN DIAGNOSTIC: student_found=%s password_matches=%s",
        student is not None,
        password_matches
)

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
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row

        menu_items = conn.execute("""
            SELECT id, name, price, category, available, stock
            FROM menu_items
            ORDER BY id
        """).fetchall()

    return render_template(
        "index.html",
        menu_items=menu_items,
        student_name=session.get("student_name", "Student"),
        student_email=session.get("student_email", "")
    )


@app.route("/api/menu", methods=["GET"])
@login_required
def get_student_menu():
    try:
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            connection.row_factory = sqlite3.Row

            items = connection.execute("""
                SELECT id, name, price, category, available, stock
                FROM menu_items
                ORDER BY id
            """).fetchall()

        return jsonify({
            "success": True,
            "menu_items": [dict(item) for item in items]
        }), 200

    except Exception:
        app.logger.exception("Could not fetch student menu.")
        return jsonify({
            "error": "Could not refresh menu."
        }), 500


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

    with sqlite3.connect(DATABASE, timeout=10) as connection:
        connection.row_factory = sqlite3.Row

        orders = connection.execute("""
            SELECT id, total, status, payment_status, created_at
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
                "Could not interpret created_at for order %s",
                order["id"]
            )
            continue

        if order_date_india == today:
            today_orders += 1

            # Only captured payments count as sales.
            if order["payment_status"] == "paid":
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

@app.route("/api/admin/menu", methods=["GET"])
@staff_login_required
def admin_get_menu():
    try:
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            connection.row_factory = sqlite3.Row

            menu_items = connection.execute("""
                SELECT id, name, price, category, available, stock
                FROM menu_items
                ORDER BY category, name
            """).fetchall()

        return jsonify({
            "success": True,
            "menu_items": [
                dict(item) for item in menu_items
            ]
        }), 200

    except Exception:
        app.logger.exception("Could not fetch admin menu.")

        return jsonify({
            "error": "Could not load menu items."
        }), 500

@app.route("/api/admin/menu", methods=["POST"])
@staff_login_required
def admin_add_menu_item():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request data."}), 400

    name = data.get("name")
    category = data.get("category")
    price = data.get("price")
    stock = data.get("stock")
    available = data.get("available", True)

    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
        return jsonify({"error": "Enter a valid item name (max 80 characters)."}), 400

    if not isinstance(category, str) or not category.strip() or len(category.strip()) > 40:
        return jsonify({"error": "Enter a valid category (max 40 characters)."}), 400

    if type(price) is not int or price < 0:
        return jsonify({"error": "Price must be a non-negative integer."}), 400

    if type(stock) is not int or stock < 0:
        return jsonify({"error": "Stock must be a non-negative integer."}), 400

    if type(available) not in (bool, int) or available not in (0, 1, False, True):
        return jsonify({"error": "Invalid availability value."}), 400

    try:
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            cursor = connection.execute("""
                INSERT INTO menu_items
                    (name, price, category, available, stock)
                VALUES (?, ?, ?, ?, ?)
            """, (
                name.strip(),
                price,
                category.strip(),
                int(available),
                stock
            ))

            item_id = cursor.lastrowid

            connection.row_factory = sqlite3.Row
            item = connection.execute("""
                SELECT id, name, price, category, available, stock
                FROM menu_items
                WHERE id = ?
            """, (item_id,)).fetchone()

        return jsonify({
            "success": True,
            "message": "Menu item added successfully.",
            "menu_item": dict(item)
        }), 201

    except Exception:
        app.logger.exception("Could not add menu item.")
        return jsonify({"error": "Could not add menu item."}), 500

@app.route("/api/admin/menu/<int:item_id>", methods=["PUT"])
@staff_login_required
def admin_update_menu_item(item_id):
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request data."}), 400

    name = data.get("name")
    category = data.get("category")
    price = data.get("price")
    stock = data.get("stock")
    available = data.get("available")

    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
        return jsonify({"error": "Enter a valid item name."}), 400

    if not isinstance(category, str) or not category.strip() or len(category.strip()) > 40:
        return jsonify({"error": "Enter a valid category."}), 400

    if type(price) is not int or price < 0:
        return jsonify({"error": "Price must be a non-negative integer."}), 400

    if type(stock) is not int or stock < 0:
        return jsonify({"error": "Stock must be a non-negative integer."}), 400

    if type(available) not in (bool, int) or available not in (0, 1, False, True):
        return jsonify({"error": "Invalid availability value."}), 400

    try:
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            cursor = connection.execute("""
                UPDATE menu_items
                SET name = ?,
                    price = ?,
                    category = ?,
                    stock = ?,
                    available = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (
                name.strip(),
                price,
                category.strip(),
                stock,
                int(available),
                item_id
            ))

            if cursor.rowcount == 0:
                return jsonify({"error": "Menu item not found."}), 404

            connection.row_factory = sqlite3.Row

            item = connection.execute("""
                SELECT id, name, price, category, available, stock
                FROM menu_items
                WHERE id = ?
            """, (item_id,)).fetchone()

        return jsonify({
            "success": True,
            "message": "Menu item updated successfully.",
            "menu_item": dict(item)
        }), 200

    except Exception:
        app.logger.exception("Could not update menu item.")
        return jsonify({"error": "Could not update menu item."}), 500


# --------------------------------------------------
# VERIFY RAZORPAY PAYMENT
# --------------------------------------------------


@app.route("/api/orders", methods=["POST"])
@login_required
def create_order():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid order data."}), 400

    items = data.get("items")

    if not isinstance(items, list) or not items or len(items) > 50:
        return jsonify({"error": "Invalid order items."}), 400

    # Validate and combine item quantities.
    quantities = {}

    for item in items:
        if not isinstance(item, dict):
            return jsonify({"error": "Invalid item details."}), 400

        item_id = item.get("id")
        quantity = item.get("quantity")

        if (
            isinstance(item_id, bool)
            or not isinstance(item_id, int)
            or item_id <= 0
            or isinstance(quantity, bool)
            or not isinstance(quantity, int)
            or quantity <= 0
            or quantity > 99
        ):
            return jsonify({"error": "Invalid item ID or quantity."}), 400

        quantities[item_id] = quantities.get(item_id, 0) + quantity

        if quantities[item_id] > 99:
            return jsonify({"error": "Quantity limit exceeded."}), 400

    key_id = os.getenv("RAZORPAY_KEY_ID")
    key_secret = os.getenv("RAZORPAY_KEY_SECRET")

    if not key_id or not key_secret:
        return jsonify({
            "error": "Payment gateway is not configured."
        }), 503

    try:
        # 1. Validate menu items and calculate prices from the database.
        order_items = []
        total = 0

        with sqlite3.connect(DATABASE, timeout=10) as connection:
            connection.row_factory = sqlite3.Row

            for item_id, quantity in quantities.items():
                menu_item = connection.execute("""
                    SELECT id, name, price, stock, available
                    FROM menu_items
                    WHERE id = ?
                """, (item_id,)).fetchone()

                if menu_item is None:
                    return jsonify({
                        "error": "A selected menu item was not found."
                    }), 400

                if not menu_item["available"]:
                    return jsonify({
                        "error": f'{menu_item["name"]} is unavailable.'
                    }), 409

                if menu_item["stock"] < quantity:
                    return jsonify({
                        "error": f'Insufficient stock for {menu_item["name"]}.'
                    }), 409

                price = menu_item["price"]

                if price < 0:
                    return jsonify({
                        "error": "Invalid menu price."
                    }), 400

                subtotal = price * quantity
                total += subtotal

                order_items.append({
                    "id": menu_item["id"],
                    "name": menu_item["name"],
                    "price": price,
                    "quantity": quantity
                })

        if total <= 0:
            return jsonify({"error": "Invalid order total."}), 400

        # 2. Create a Razorpay order.
        client = razorpay.Client(auth=(key_id, key_secret))

        razorpay_order = client.order.create(data={
            "amount": total * 100,
            "currency": "INR",
            "receipt": "sc_" + secrets.token_hex(12)
        })

        razorpay_order_id = razorpay_order.get("id")

        if not razorpay_order_id:
            raise RuntimeError("Razorpay did not return an order ID.")

        # 3. Save the unpaid order and its items in SQLite.
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            connection.execute("BEGIN IMMEDIATE")

            cursor = connection.execute("""
                INSERT INTO orders (
                    total,
                    status,
                    student_id,
                    payment_status,
                    razorpay_order_id
                )
                VALUES (?, 'pending', ?, 'unpaid', ?)
            """, (
                total,
                session["student_id"],
                razorpay_order_id
            ))

            local_order_id = cursor.lastrowid

            for item in order_items:
                connection.execute("""
                    INSERT INTO order_items (
                        order_id,
                        menu_item_id,
                        item_name,
                        unit_price,
                        quantity
                    )
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    local_order_id,
                    item["id"],
                    item["name"],
                    item["price"],
                    item["quantity"]
                ))

        # 4. Return the response expected by index.html.
        return jsonify({
            "key_id": key_id,
            "razorpay_order_id": razorpay_order_id,
            "amount": total * 100,
            "currency": "INR",
            "order_id": local_order_id,
            "total": total,
            "items": [
                {
                    "name": item["name"],
                    "price": item["price"],
                    "quantity": item["quantity"]
                }
                for item in order_items
            ]
        }), 201

    except Exception:
        app.logger.exception("Order creation failed.")

        return jsonify({
            "error": "Could not create your order. Please try again."
        }), 500

@app.route("/api/orders/verify-payment", methods=["POST"])
@login_required
def verify_payment():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid payment data."}), 400

    order_id = data.get("order_id")
    razorpay_order_id = data.get("razorpay_order_id")
    payment_id = data.get("razorpay_payment_id")
    signature = data.get("razorpay_signature")

    if (
        isinstance(order_id, bool)
        or not isinstance(order_id, int)
        or not all(
            isinstance(value, str) and value.strip()
            for value in (razorpay_order_id, payment_id, signature)
        )
    ):
        return jsonify({"error": "Invalid payment details."}), 400

    key_id = os.getenv("RAZORPAY_KEY_ID")
    key_secret = os.getenv("RAZORPAY_KEY_SECRET")

    if not key_id or not key_secret:
        return jsonify({
            "error": "Payment gateway is not configured."
        }), 503

    try:
        # 1. Verify Razorpay checkout signature.
        message = f"{razorpay_order_id}|{payment_id}".encode()

        expected_signature = hmac.new(
            key_secret.encode(),
            message,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_signature, signature):
            return jsonify({
                "error": "Payment signature is invalid."
            }), 400

        # 2. Verify payment directly with Razorpay.
        client = razorpay.Client(auth=(key_id, key_secret))
        payment = client.payment.fetch(payment_id)

        if (
            payment.get("order_id") != razorpay_order_id
            or payment.get("status") != "captured"
        ):
            return jsonify({
                "error": "Payment has not been captured yet."
            }), 400

        response_data = None
        response_status = 200

        # 3. Verify and update everything atomically.
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")

            order = connection.execute("""
                SELECT id, total, student_id, payment_status,
                       razorpay_order_id, qr_token, pickup_code,
                       razorpay_payment_id
                FROM orders
                WHERE id = ? AND student_id = ?
            """, (
                order_id,
                session["student_id"]
            )).fetchone()

            if order is None:
                response_data = {
                    "error": "Order not found."
                }
                response_status = 404

            elif order["razorpay_order_id"] != razorpay_order_id:
                response_data = {
                    "error": "Order ID mismatch."
                }
                response_status = 400

            elif (
                payment.get("amount") != order["total"] * 100
                or payment.get("currency") != "INR"
            ):
                response_data = {
                    "error": "Payment amount mismatch."
                }
                response_status = 400

            # Already-paid order: never deduct stock again.
            elif order["payment_status"] == "paid":
                if order["razorpay_payment_id"] != payment_id:
                    response_data = {
                        "error": "This order has another payment recorded."
                    }
                    response_status = 409
                else:
                    response_data = {
                        "success": True,
                        "order_id": order_id,
                        "qr_token": order["qr_token"],
                        "pickup_code": order["pickup_code"]
                    }

            # Do not process other payment states.
            elif order["payment_status"] != "unpaid":
                response_data = {
                    "error": (
                        "This order cannot be paid. "
                        "Please contact canteen staff."
                    )
                }
                response_status = 409

            else:
                # Fetch all ordered items.
                order_items = connection.execute("""
                    SELECT menu_item_id, quantity
                    FROM order_items
                    WHERE order_id = ?
                """, (order_id,)).fetchall()

                if not order_items:
                    response_data = {
                        "error": "Order items not found. Contact canteen staff."
                    }
                    response_status = 409

                else:
                    # Check all stock before deducting anything.
                    stock_issue = None

                    for order_item in order_items:
                        menu_item = connection.execute("""
                            SELECT name, stock, available
                            FROM menu_items
                            WHERE id = ?
                        """, (
                            order_item["menu_item_id"],
                        )).fetchone()

                        if menu_item is None:
                            stock_issue = "A menu item no longer exists."
                            break

                        if not menu_item["available"]:
                            stock_issue = (
                                f'{menu_item["name"]} is unavailable.'
                            )
                            break

                        if menu_item["stock"] < order_item["quantity"]:
                            stock_issue = (
                                f'{menu_item["name"]} has insufficient stock.'
                            )
                            break

                    if stock_issue:
                        # Payment was captured, but the order cannot be fulfilled.
                        # Record this state for staff refund handling.
                        connection.execute("""
                            UPDATE orders
                            SET payment_status = 'refund_required',
                                razorpay_payment_id = ?,
                                payment_verified_at = ?
                            WHERE id = ?
                              AND payment_status = 'unpaid'
                        """, (
                            payment_id,
                            datetime.now(INDIA_TZ).isoformat(),
                            order_id
                        ))

                        response_data = {
                            "success": False,
                            "payment_captured": True,
                            "refund_required": True,
                            "error": (
                                "Payment was captured, but the order "
                                "could not be fulfilled: "
                                + stock_issue
                                + " Please contact canteen staff "
                                  "for a refund."
                            )
                        }
                        response_status = 409

                    else:
                        # Deduct stock within the same transaction.
                        stock_update_failed = False

                        for order_item in order_items:
                            cursor = connection.execute("""
                                UPDATE menu_items
                                SET stock = stock - ?
                                WHERE id = ?
                                  AND available = 1
                                  AND stock >= ?
                            """, (
                                order_item["quantity"],
                                order_item["menu_item_id"],
                                order_item["quantity"]
                            ))

                            if cursor.rowcount != 1:
                                stock_update_failed = True
                                break

                        if stock_update_failed:
                            # Roll back every stock deduction.
                            connection.rollback()

                            response_data = {
                                "error": (
                                    "Stock update failed. "
                                    "Payment may have been captured. "
                                    "Please contact canteen staff."
                                ),
                                "payment_captured": True
                            }
                            response_status = 409

                        else:
                            # Generate collection credentials.
                            qr_token = secrets.token_urlsafe(32)
                            pickup_code = generate_pickup_code(connection)

                            cursor = connection.execute("""
                                UPDATE orders
                                SET payment_status = 'paid',
                                    razorpay_payment_id = ?,
                                    payment_verified_at = ?,
                                    qr_token = ?,
                                    pickup_code = ?
                                WHERE id = ?
                                  AND student_id = ?
                                  AND payment_status = 'unpaid'
                                  AND razorpay_order_id = ?
                            """, (
                                payment_id,
                                datetime.now(INDIA_TZ).isoformat(),
                                qr_token,
                                pickup_code,
                                order_id,
                                session["student_id"],
                                razorpay_order_id
                            ))

                            if cursor.rowcount != 1:
                                connection.rollback()

                                response_data = {
                                    "error": (
                                        "Order update failed. "
                                        "Please contact canteen staff."
                                    ),
                                    "payment_captured": True
                                }
                                response_status = 409

                            else:
                                response_data = {
                                    "success": True,
                                    "order_id": order_id,
                                    "qr_token": qr_token,
                                    "pickup_code": pickup_code
                                }

        return jsonify(response_data), response_status

    except Exception:
        app.logger.exception("Payment verification failed.")

        return jsonify({
            "error": (
                "Could not verify payment. "
                "Please contact canteen staff."
            )
        }), 500


# --------------------------------------------------
# VERIFY QR CODE
# --------------------------------------------------

@app.route("/api/orders/verify", methods=["POST"])
@staff_login_required
def verify_order():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid scan data."}), 400

    qr_token = data.get("qr_token")

    if (
        not isinstance(qr_token, str)
        or not qr_token.strip()
        or len(qr_token) > 200
    ):
        return jsonify({"error": "Invalid QR code."}), 400

    qr_token = qr_token.strip()

    try:
        response_data = None
        response_status = 200

        with sqlite3.connect(DATABASE, timeout=10) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")

            order = connection.execute("""
                SELECT id, status, payment_status
                FROM orders
                WHERE qr_token = ?
            """, (qr_token,)).fetchone()

            if order is None:
                response_data = {
                    "error": "Invalid QR code."
                }
                response_status = 404

            elif order["payment_status"] != "paid":
                response_data = {
                    "error": "Payment has not been completed.",
                    "payment_status": order["payment_status"]
                }
                response_status = 403

            elif order["status"] == "successful":
                response_data = {
                    "error": "This order has already been collected.",
                    "order_id": order["id"],
                    "status": order["status"]
                }
                response_status = 409

            elif order["status"] != "pending":
                response_data = {
                    "error": "This order cannot be collected.",
                    "status": order["status"]
                }
                response_status = 409

            else:
                cursor = connection.execute("""
                    UPDATE orders
                    SET status = 'successful'
                    WHERE id = ?
                      AND status = 'pending'
                      AND payment_status = 'paid'
                """, (order["id"],))

                if cursor.rowcount != 1:
                    response_data = {
                        "error": "Order status changed. Please scan again."
                    }
                    response_status = 409
                else:
                    response_data = {
                        "message": "QR verified. The order is ready for handover.",
                        "order_id": order["id"],
                        "status": "successful"
                    }

        return jsonify(response_data), response_status

    except sqlite3.Error:
        app.logger.exception("Could not verify the QR code.")

        return jsonify({
            "error": "Verification failed. Please try again."
        }), 500


# --------------------------------------------------
# VERIFY PICKUP CODE
# --------------------------------------------------

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
        return jsonify({
            "error": "Enter a valid six-digit pickup code."
        }), 400

    try:
        response_data = None
        response_status = 200

        with sqlite3.connect(DATABASE, timeout=10) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")

            order = connection.execute("""
                SELECT id, status, payment_status
                FROM orders
                WHERE pickup_code = ?
            """, (pickup_code,)).fetchone()

            if order is None:
                response_data = {
                    "error": "Pickup code not found."
                }
                response_status = 404

            elif order["payment_status"] != "paid":
                response_data = {
                    "error": "Payment has not been completed.",
                    "payment_status": order["payment_status"]
                }
                response_status = 403

            elif order["status"] == "successful":
                response_data = {
                    "error": "This order has already been collected.",
                    "order_id": order["id"],
                    "status": order["status"]
                }
                response_status = 409

            elif order["status"] != "pending":
                response_data = {
                    "error": "This order cannot be collected.",
                    "status": order["status"]
                }
                response_status = 409

            else:
                cursor = connection.execute("""
                    UPDATE orders
                    SET status = 'successful'
                    WHERE id = ?
                      AND status = 'pending'
                      AND payment_status = 'paid'
                """, (order["id"],))

                if cursor.rowcount != 1:
                    response_data = {
                        "error": "Order status changed. Please verify again."
                    }
                    response_status = 409
                else:
                    response_data = {
                        "message": "Pickup code verified successfully.",
                        "order_id": order["id"],
                        "status": "successful"
                    }

        return jsonify(response_data), response_status

    except sqlite3.Error:
        app.logger.exception("Pickup code verification failed.")

        return jsonify({
            "error": "Verification failed. Please try again."
        }), 500

# --------------------------------------------------
# STUDENT ORDER HISTORY / STATUS / RECEIPT
# --------------------------------------------------


@app.route("/api/my-orders", methods=["GET"])
@login_required
def my_orders():
    try:
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            connection.row_factory = sqlite3.Row

            orders = connection.execute("""
                SELECT id, total, status, payment_status, created_at,
                       qr_token, pickup_code
                FROM orders
                WHERE student_id = ?
                ORDER BY id DESC
            """, (session["student_id"],)).fetchall()

            result = []

            for order in orders:
                rows = connection.execute("""
                    SELECT item_name, unit_price, quantity
                    FROM order_items
                    WHERE order_id = ?
                    ORDER BY id
                """, (order["id"],)).fetchall()

                is_paid = order["payment_status"] == "paid"

                result.append({
                    "order_id": order["id"],
                    "total": order["total"],
                    "status": order["status"],
                    "payment_status": order["payment_status"],
                    "created_at": order["created_at"],

                    # Only reveal collection credentials after payment.
                    "qr_token": order["qr_token"] if is_paid else None,
                    "pickup_code": order["pickup_code"] if is_paid else None,

                    "items": [
                        {
                            "name": row["item_name"],
                            "price": row["unit_price"],
                            "quantity": row["quantity"]
                        }
                        for row in rows
                    ]
                })

        return jsonify({"orders": result}), 200

    except sqlite3.Error:
        app.logger.exception("Could not load student order history.")
        return jsonify({"error": "Could not load your orders."}), 500




@app.route("/api/orders/<int:order_id>/status", methods=["GET"])
@login_required
def order_status(order_id):
    qr_token = request.args.get("token", "")

    if not qr_token or len(qr_token) > 200:
        return jsonify({"error": "Invalid status request."}), 400

    try:
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            order = connection.execute("""
                SELECT status, payment_status
                FROM orders
                WHERE id = ? AND qr_token = ? AND student_id = ?
            """, (order_id, qr_token, session["student_id"])).fetchone()

        if order is None:
            return jsonify({"error": "Order not found."}), 404

        return jsonify({
            "order_id": order_id,
            "status": order[0],
            "payment_status": order[1]
        }), 200

    except sqlite3.Error:
        app.logger.exception("Could not retrieve order status.")
        return jsonify({"error": "Could not retrieve order status."}), 500


@app.route("/api/orders/<int:order_id>/receipt", methods=["GET"])
@login_required
def order_receipt(order_id):
    qr_token = request.args.get("token", "")

    if not qr_token or len(qr_token) > 200:
        return jsonify({"error": "Invalid receipt request."}), 400

    try:
        with sqlite3.connect(DATABASE, timeout=10) as connection:
            connection.row_factory = sqlite3.Row

            order = connection.execute("""
                SELECT id, total, status, payment_status,
                       qr_token, pickup_code
                FROM orders
                WHERE id = ? AND qr_token = ? AND student_id = ?
            """, (order_id, qr_token, session["student_id"])).fetchone()

            if order is None:
                return jsonify({"error": "Booking not found."}), 404

            if order["payment_status"] != "paid":
                return jsonify({
                    "error": "Receipt is available only after successful payment."
                }), 403

            rows = connection.execute("""
                SELECT item_name, unit_price, quantity
                FROM order_items
                WHERE order_id = ?
                ORDER BY id
            """, (order_id,)).fetchall()

        return jsonify({
            "order_id": order["id"],
            "total": order["total"],
            "status": order["status"],
            "payment_status": order["payment_status"],
            "pickup_code": order["pickup_code"],
            "items": [
                {
                    "name": row["item_name"],
                    "price": row["unit_price"],
                    "quantity": row["quantity"]
                }
                for row in rows
            ]
        }), 200

    except sqlite3.Error:
        app.logger.exception("Could not retrieve order receipt.")
        return jsonify({"error": "Could not retrieve receipt."}), 500



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


def sync_staff_account_from_env():
    """Set the demo staff account from protected environment variables."""
    username = os.environ.get("STAFF_BOOTSTRAP_USERNAME", "").strip()
    password = os.environ.get("STAFF_BOOTSTRAP_PASSWORD", "")

    if not username and not password:
        return

    if not username or not password:
        raise RuntimeError("Both staff bootstrap variables are required.")

    if len(username) > 40 or len(password) < 8 or len(password) > 128:
        raise RuntimeError("Invalid staff bootstrap credentials.")

    password_hash = generate_password_hash(password)

    with sqlite3.connect(DATABASE) as conn:
        conn.execute("""
            INSERT INTO staff_users
                (id, username, password_hash, updated_at)
            VALUES (1, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
                username = excluded.username,
                password_hash = excluded.password_hash,
                updated_at = CURRENT_TIMESTAMP
        """, (username, password_hash))

# Create/upgrade tables in-place. Do not delete canteen.db.
# Initialize database
init_database()
sync_staff_account_from_env()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "set-staff":
        set_staff_account()
    else:
        app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("FLASK_DEBUG", "0") == "1")
