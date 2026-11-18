from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from database import get_connection
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
    """Initialize and verify the Smart Canteen PostgreSQL database."""
    conn = get_connection()
    cur = conn.cursor()

    try:
        # Verify that all required PostgreSQL tables exist.
        required_tables = {
            "students",
            "staff_users",
            "email_otps",
            "orders",
            "order_items",
            "menu_items"
        }

        cur.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
        """)

        existing_tables = {row[0] for row in cur.fetchall()}
        missing_tables = required_tables - existing_tables

        if missing_tables:
            raise RuntimeError(
                f"Missing PostgreSQL tables: {', '.join(sorted(missing_tables))}"
            )

        # Preserve historical collected orders.
        cur.execute("""
            UPDATE orders
            SET payment_status = 'legacy'
            WHERE status = 'successful'
              AND payment_status = 'unpaid'
              AND razorpay_payment_id IS NULL
        """)

        # Prevent duplicate QR and payment references.
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_qr_token
            ON orders(qr_token)
        """)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_pickup_code
            ON orders(pickup_code)
        """)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_razorpay_order
            ON orders(razorpay_order_id)
        """)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_razorpay_payment
            ON orders(razorpay_payment_id)
        """)

        # Seed the menu only if the PostgreSQL menu table is empty.
        cur.execute("SELECT COUNT(*) FROM menu_items")
        menu_count = cur.fetchone()[0]

        if menu_count == 0:
            cur.executemany("""
                INSERT INTO menu_items
                    (id, name, price, category, available, stock)
                VALUES (%s, %s, %s, %s, %s, 0)
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

        # Synchronize the menu identity sequence after explicit IDs.
        cur.execute("""
            SELECT setval(
                pg_get_serial_sequence('menu_items', 'id'),
                COALESCE(MAX(id), 1),
                MAX(id) IS NOT NULL
            )
            FROM menu_items
        """)

        conn.commit()
        app.logger.info("PostgreSQL database initialization successful.")

    except Exception:
        conn.rollback()
        app.logger.exception("PostgreSQL database initialization failed")
        raise

    finally:
        cur.close()
        conn.close()


# --------------------------------------------------
# PICKUP CODE
# --------------------------------------------------




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
        return json_error(
            f"Use your college email ending in @{COLLEGE_EMAIL_DOMAIN}."
        )

    now = datetime.now(UTC_TZ)
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT id FROM students WHERE email = %s",
            (email,)
        )
        student = cur.fetchone()

        app.logger.info(
            "Student account found in database: %s",
            student is not None
        )

        if purpose == "register" and student:
            return json_error(
                "An account already exists for this email. Please sign in.",
                409
            )

        if purpose == "reset" and not student:
            return jsonify({
                "message": "If the account exists, a verification code will be sent."
            }), 200

        cur.execute("""
            SELECT created_at FROM email_otps
            WHERE email = %s AND purpose = %s
            ORDER BY id DESC LIMIT 1
        """, (email, purpose))

        recent = cur.fetchone()

        if recent:
            try:
                previous = datetime.fromisoformat(recent[0])
                elapsed = (now - previous).total_seconds()

                if elapsed < OTP_RESEND_SECONDS:
                    wait = max(1, OTP_RESEND_SECONDS - int(elapsed))
                    return json_error(
                        f"Please wait {wait} seconds before requesting another code.",
                        429
                    )
            except ValueError:
                pass

        otp = f"{secrets.randbelow(1_000_000):06d}"

        cur.execute(
            "DELETE FROM email_otps WHERE email = %s AND purpose = %s",
            (email, purpose)
        )

        cur.execute("""
            INSERT INTO email_otps
                (email, purpose, otp_hash, expires_at, attempts, created_at)
            VALUES (%s, %s, %s, %s, 0, %s)
        """, (
            email,
            purpose,
            otp_digest(email, purpose, otp),
            (now + timedelta(seconds=OTP_LIFETIME_SECONDS)).isoformat(),
            now.isoformat()
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        app.logger.exception("Could not create OTP record")
        return json_error("Could not create a verification code. Please try again.", 500)

    finally:
        cur.close()
        conn.close()

    try:
        send_email_otp(email, otp, purpose)

    except Exception as exc:
        app.logger.exception("OTP email delivery failed")

        cleanup_conn = get_connection()
        cleanup_cur = cleanup_conn.cursor()

        try:
            cleanup_cur.execute(
                "DELETE FROM email_otps WHERE email = %s AND purpose = %s",
                (email, purpose)
            )
            cleanup_conn.commit()
        except Exception:
            cleanup_conn.rollback()
            app.logger.exception("Could not remove failed OTP record")
        finally:
            cleanup_cur.close()
            cleanup_conn.close()

        if isinstance(exc, RuntimeError):
            return json_error(str(exc), 503)

        return json_error(
            "Could not send the email. Check the Resend API settings and sender verification, then try again.",
            503
        )

    return jsonify({
        "message": "OTP sent. It expires in 5 minutes.",
        "expires_in": OTP_LIFETIME_SECONDS
    }), 200




def consume_otp(email, purpose, otp):
    now = datetime.now(UTC_TZ)
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT id, otp_hash, expires_at, attempts
            FROM email_otps
            WHERE email = %s AND purpose = %s
            ORDER BY id DESC
            LIMIT 1
            FOR UPDATE
        """, (email, purpose))

        row = cur.fetchone()

        if row is None:
            conn.commit()
            return False, "Request a new verification code."

        otp_id, otp_hash, expires_at, attempts = row

        try:
            expires = datetime.fromisoformat(expires_at)
        except (ValueError, TypeError):
            expires = now

        if now >= expires:
            cur.execute(
                "DELETE FROM email_otps WHERE id = %s",
                (otp_id,)
            )
            conn.commit()
            return False, "This code has expired. Request a new one."

        if attempts >= OTP_MAX_ATTEMPTS:
            cur.execute(
                "DELETE FROM email_otps WHERE id = %s",
                (otp_id,)
            )
            conn.commit()
            return False, "Too many incorrect attempts. Request a new code."

        if not hmac.compare_digest(
            otp_hash,
            otp_digest(email, purpose, otp)
        ):
            cur.execute(
                "UPDATE email_otps SET attempts = attempts + 1 WHERE id = %s",
                (otp_id,)
            )
            conn.commit()

            remaining = OTP_MAX_ATTEMPTS - attempts - 1
            return False, f"Incorrect code. You have {remaining} attempt(s) left."

        cur.execute(
            "DELETE FROM email_otps WHERE id = %s",
            (otp_id,)
        )

        conn.commit()
        return True, "Email verified."

    except Exception:
        conn.rollback()
        app.logger.exception("OTP verification database error")
        return False, "Could not verify the code. Please try again."

    finally:
        cur.close()
        conn.close()


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
        return json_error(
            f"Use your college email ending in @{COLLEGE_EMAIL_DOMAIN}."
        )

    if not verification_is_valid(email, "register"):
        return json_error(
            "Verify your email with a fresh OTP before creating your account.",
            403
        )

    if not name or len(name) > 80:
        return json_error("Enter a name between 1 and 80 characters.")

    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return json_error("Password must contain between 8 and 128 characters.")

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO students (email, name, password_hash)
            VALUES (%s, %s, %s)
            RETURNING id
        """, (
            email,
            name,
            generate_password_hash(password)
        ))

        student_id = cur.fetchone()[0]
        conn.commit()

    except Exception as exc:
        conn.rollback()

        # PostgreSQL unique-constraint violation
        if getattr(exc, "sqlstate", None) == "23505":
            return json_error(
                "An account already exists for this email. Please sign in.",
                409
            )

        app.logger.exception("Student registration failed")
        return json_error("Could not create your account. Please try again.", 500)

    finally:
        cur.close()
        conn.close()

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

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT id, email, name, password_hash
            FROM students
            WHERE email = %s
            """,
            (email,)
        )
        student = cur.fetchone()

    except Exception:
        app.logger.exception("Student login database query failed")
        return json_error("Unable to sign in right now. Please try again.", 500)

    finally:
        cur.close()
        conn.close()

    password_matches = (
        check_password_hash(student[3], password)
        if student is not None
        else False
    )

    app.logger.info("Student login attempt processed.")

    if student is None or not password_matches:
        return json_error("Email or password is incorrect.", 401)

    clear_student_session()
    session.permanent = True
    session["student_id"] = student[0]
    session["student_email"] = student[1]
    session["student_name"] = student[2]

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
        return json_error(
            "Verify your email with a fresh OTP before resetting your password.",
            403
        )

    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return json_error("Password must contain between 8 and 128 characters.")

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            UPDATE students
            SET password_hash = %s
            WHERE email = %s
            """,
            (generate_password_hash(password), email)
        )

        if cur.rowcount == 0:
            conn.rollback()
            return json_error(
                "Could not reset the password. Check the email and try again.",
                404
            )

        conn.commit()

    except Exception:
        conn.rollback()
        app.logger.exception("Student password reset failed")
        return json_error("Unable to reset your password. Please try again.", 500)

    finally:
        cur.close()
        conn.close()

    clear_student_session()
    session.pop("verified_email", None)
    session.pop("verified_purpose", None)
    session.pop("verified_at", None)

    return jsonify({
        "message": "Password reset successfully. You can now sign in."
    }), 200


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

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            UPDATE students
            SET name = %s
            WHERE id = %s
            """,
            (name, session["student_id"])
        )

        if cur.rowcount != 1:
            conn.rollback()
            return json_error(
                "Could not update your profile. Please sign in again.",
                404
            )

        conn.commit()

    except Exception:
        conn.rollback()
        app.logger.exception("Student profile update failed")
        return json_error("Unable to update your profile. Please try again.", 500)

    finally:
        cur.close()
        conn.close()

    session["student_name"] = name

    return jsonify({
        "message": "Your name has been updated.",
        "name": name
    }), 200


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

        conn = get_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                """
                SELECT id, username, password_hash
                FROM staff_users
                WHERE id = %s
                """,
                (1,)
            )
            staff = cur.fetchone()

        except Exception:
            app.logger.exception("Staff login database query failed")
            error = "Unable to sign in right now. Please try again."
            staff = None

        finally:
            cur.close()
            conn.close()

        if (
            staff is None
            or not isinstance(password, str)
            or not hmac.compare_digest(username.casefold(), staff[1].casefold())
            or not check_password_hash(staff[2], password)
        ):
            if error is None:
                error = "Username or password is incorrect."
        else:
            # Keep any student login in the same browser session.
            clear_staff_session()
            session.permanent = True
            session["staff_id"] = staff[0]
            session["staff_username"] = staff[1]
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
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT id, name, price, category, available, stock
            FROM menu_items
            ORDER BY id
        """)

        columns = [column[0] for column in cur.description]
        menu_items = [
            dict(zip(columns, row))
            for row in cur.fetchall()
        ]

    except Exception:
        app.logger.exception("Failed to fetch menu items")
        raise

    finally:
        cur.close()
        conn.close()

    return render_template(
        "index.html",
        menu_items=menu_items,
        student_name=session.get("student_name", "Student"),
        student_email=session.get("student_email", "")
    )

@app.route("/api/menu", methods=["GET"])
@login_required
def get_student_menu():
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT id, name, price, category, available, stock
            FROM menu_items
            ORDER BY id
        """)

        columns = [column[0] for column in cur.description]
        items = [
            dict(zip(columns, row))
            for row in cur.fetchall()
        ]

        return jsonify({
            "success": True,
            "menu_items": items
        }), 200

    except Exception:
        app.logger.exception("Could not fetch student menu.")
        return jsonify({
            "error": "Could not refresh menu."
        }), 500

    finally:
        cur.close()
        conn.close()


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

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT id, total, status, payment_status, created_at
            FROM orders
            ORDER BY id DESC
        """)

        columns = [column[0] for column in cur.description]
        orders = [
            dict(zip(columns, row))
            for row in cur.fetchall()
        ]

        order_items_by_id = {}

        for order in orders:
            cur.execute("""
                SELECT item_name, unit_price, quantity
                FROM order_items
                WHERE order_id = %s
            """, (order["id"],))

            item_columns = [column[0] for column in cur.description]
            order_items_by_id[order["id"]] = [
                dict(zip(item_columns, row))
                for row in cur.fetchall()
            ]

        today_orders = 0
        today_sales = 0
        items_sold_today = 0

        for order in orders:
            try:
                order_datetime = datetime.fromisoformat(
                    str(order["created_at"])
                )

                if order_datetime.tzinfo is None:
                    order_datetime = order_datetime.replace(tzinfo=UTC_TZ)

                order_date_india = order_datetime.astimezone(
                    INDIA_TZ
                ).date()

            except (ValueError, TypeError):
                app.logger.warning(
                    "Could not interpret created_at for order %s",
                    order["id"]
                )
                continue

            if order_date_india == today:
                today_orders += 1

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

    except Exception:
        app.logger.exception("Could not load admin dashboard.")
        raise

    finally:
        cur.close()
        conn.close()


@app.route("/api/admin/menu", methods=["GET"])
@staff_login_required
def admin_get_menu():
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT id, name, price, category, available, stock
            FROM menu_items
            ORDER BY category, name
        """)

        columns = [column[0] for column in cur.description]
        menu_items = [
            dict(zip(columns, row))
            for row in cur.fetchall()
        ]

        return jsonify({
            "success": True,
            "menu_items": menu_items
        }), 200

    except Exception:
        app.logger.exception("Could not fetch admin menu.")
        return jsonify({
            "error": "Could not load menu items."
        }), 500

    finally:
        cur.close()
        conn.close()

# --------------------------------------------------
# CREATE STUDENT ORDER
# --------------------------------------------------


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

    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO menu_items
                (name, price, category, available, stock)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, name, price, category, available, stock
        """, (
            name.strip(),
            price,
            category.strip(),
            int(available),
            stock
        ))

        columns = [column[0] for column in cur.description]
        item = dict(zip(columns, cur.fetchone()))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Menu item added successfully.",
            "menu_item": item
        }), 201

    except Exception:
        if conn is not None:
            conn.rollback()

        app.logger.exception("Could not add menu item.")
        return jsonify({"error": "Could not add menu item."}), 500

    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()





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

    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            UPDATE menu_items
            SET name = %s,
                price = %s,
                category = %s,
                stock = %s,
                available = %s,
                updated_at = CURRENT_TIMESTAMP::TEXT
            WHERE id = %s
        """, (
            name.strip(),
            price,
            category.strip(),
            stock,
            int(available),
            item_id
        ))

        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "Menu item not found."}), 404

        cur.execute("""
            SELECT id, name, price, category, available, stock
            FROM menu_items
            WHERE id = %s
        """, (item_id,))

        item = cur.fetchone()
        conn.commit()

        return jsonify({
            "success": True,
            "message": "Menu item updated successfully.",
            "menu_item": {
                "id": item[0],
                "name": item[1],
                "price": item[2],
                "category": item[3],
                "available": item[4],
                "stock": item[5]
            }
        }), 200

    except Exception:
        if conn is not None:
            conn.rollback()

        app.logger.exception("Could not update menu item.")
        return jsonify({"error": "Could not update menu item."}), 500

    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()

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
        # 1. Validate menu items and calculate prices from PostgreSQL.
        order_items = []
        total = 0

        conn = get_connection()
        cur = conn.cursor()

        try:
            for item_id, quantity in quantities.items():
                cur.execute("""
                    SELECT id, name, price, stock, available
                    FROM menu_items
                    WHERE id = %s
                """, (item_id,))

                menu_item = cur.fetchone()

                if menu_item is None:
                    return jsonify({
                        "error": "A selected menu item was not found."
                    }), 400

                menu_id, name, price, stock, available = menu_item

                if not available:
                    return jsonify({
                        "error": f"{name} is unavailable."
                    }), 409

                if stock < quantity:
                    return jsonify({
                        "error": f"Insufficient stock for {name}."
                    }), 409

                if price < 0:
                    return jsonify({
                        "error": "Invalid menu price."
                    }), 400

                total += price * quantity

                order_items.append({
                    "id": menu_id,
                    "name": name,
                    "price": price,
                    "quantity": quantity
                })

        finally:
            cur.close()
            conn.close()

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

        # 3. Save the unpaid order and its items in PostgreSQL.
        conn = get_connection()
        cur = conn.cursor()

        try:
            cur.execute("""
                INSERT INTO orders (
                    total,
                    status,
                    student_id,
                    payment_status,
                    razorpay_order_id
                )
                VALUES (%s, 'pending', %s, 'unpaid', %s)
                RETURNING id
            """, (
                total,
                session["student_id"],
                razorpay_order_id
            ))

            local_order_id = cur.fetchone()[0]

            for item in order_items:
                cur.execute("""
                    INSERT INTO order_items (
                        order_id,
                        menu_item_id,
                        item_name,
                        unit_price,
                        quantity
                    )
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    local_order_id,
                    item["id"],
                    item["name"],
                    item["price"],
                    item["quantity"]
                ))

            conn.commit()

        except Exception:
            conn.rollback()
            raise

        finally:
            cur.close()
            conn.close()

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

        conn = get_connection()
        cur = conn.cursor()

        try:
            # 3. Lock the order for atomic payment processing.
            cur.execute("""
                SELECT id, total, student_id, payment_status,
                       razorpay_order_id, qr_token, pickup_code,
                       razorpay_payment_id
                FROM orders
                WHERE id = %s AND student_id = %s
                FOR UPDATE
            """, (
                order_id,
                session["student_id"]
            ))

            order = cur.fetchone()

            if order is None:
                conn.rollback()
                response_data = {"error": "Order not found."}
                response_status = 404

            elif order[4] != razorpay_order_id:
                conn.rollback()
                response_data = {"error": "Order ID mismatch."}
                response_status = 400

            elif (
                payment.get("amount") != order[1] * 100
                or payment.get("currency") != "INR"
            ):
                conn.rollback()
                response_data = {"error": "Payment amount mismatch."}
                response_status = 400

            # Already-paid order: never deduct stock again.
            elif order[3] == "paid":
                conn.rollback()

                if order[7] != payment_id:
                    response_data = {
                        "error": "This order has another payment recorded."
                    }
                    response_status = 409
                else:
                    response_data = {
                        "success": True,
                        "order_id": order_id,
                        "qr_token": order[5],
                        "pickup_code": order[6]
                    }

            # Do not process other payment states.
            elif order[3] != "unpaid":
                conn.rollback()
                response_data = {
                    "error": (
                        "This order cannot be paid. "
                        "Please contact canteen staff."
                    )
                }
                response_status = 409

            else:
                # 4. Fetch ordered items.
                cur.execute("""
                    SELECT menu_item_id, quantity
                    FROM order_items
                    WHERE order_id = %s
                    ORDER BY menu_item_id
                """, (order_id,))

                order_items = cur.fetchall()

                if not order_items:
                    conn.rollback()
                    response_data = {
                        "error": (
                            "Order items not found. "
                            "Contact canteen staff."
                        )
                    }
                    response_status = 409

                else:
                    # 5. Lock and check every menu item.
                    stock_issue = None

                    for order_item in order_items:
                        cur.execute("""
                            SELECT name, stock, available
                            FROM menu_items
                            WHERE id = %s
                            FOR UPDATE
                        """, (order_item[0],))

                        menu_item = cur.fetchone()

                        if menu_item is None:
                            stock_issue = "A menu item no longer exists."
                            break

                        if not menu_item[2]:
                            stock_issue = (
                                f"{menu_item[0]} is unavailable."
                            )
                            break

                        if menu_item[1] < order_item[1]:
                            stock_issue = (
                                f"{menu_item[0]} has insufficient stock."
                            )
                            break

                    if stock_issue:
                        # Payment was captured, but order cannot be fulfilled.
                        cur.execute("""
                            UPDATE orders
                            SET payment_status = 'refund_required',
                                razorpay_payment_id = %s,
                                payment_verified_at = %s
                            WHERE id = %s
                              AND payment_status = 'unpaid'
                        """, (
                            payment_id,
                            datetime.now(INDIA_TZ).isoformat(),
                            order_id
                        ))

                        conn.commit()

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
                        # 6. Deduct stock within the same transaction.
                        stock_update_failed = False

                        for order_item in order_items:
                            cur.execute("""
                                UPDATE menu_items
                                SET stock = stock - %s
                                WHERE id = %s
                                  AND available = 1
                                  AND stock >= %s
                            """, (
                                order_item[1],
                                order_item[0],
                                order_item[1]
                            ))

                            if cur.rowcount != 1:
                                stock_update_failed = True
                                break

                        if stock_update_failed:
                            conn.rollback()

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
                            # 7. Generate collection credentials.
                            qr_token = secrets.token_urlsafe(32)

                            # Generate a unique six-digit pickup code.
                            pickup_code = None

                            for _ in range(20):
                                candidate = str(
                                    secrets.randbelow(900000) + 100000
                                )

                                cur.execute("""
                                    SELECT 1
                                    FROM orders
                                    WHERE pickup_code = %s
                                """, (candidate,))

                                if cur.fetchone() is None:
                                    pickup_code = candidate
                                    break

                            if pickup_code is None:
                                conn.rollback()
                                response_data = {
                                    "error": (
                                        "Could not generate pickup code. "
                                        "Please contact canteen staff."
                                    ),
                                    "payment_captured": True
                                }
                                response_status = 409

                            else:
                                cur.execute("""
                                    UPDATE orders
                                    SET payment_status = 'paid',
                                        razorpay_payment_id = %s,
                                        payment_verified_at = %s,
                                        qr_token = %s,
                                        pickup_code = %s
                                    WHERE id = %s
                                      AND student_id = %s
                                      AND payment_status = 'unpaid'
                                      AND razorpay_order_id = %s
                                """, (
                                    payment_id,
                                    datetime.now(INDIA_TZ).isoformat(),
                                    qr_token,
                                    pickup_code,
                                    order_id,
                                    session["student_id"],
                                    razorpay_order_id
                                ))

                                if cur.rowcount != 1:
                                    conn.rollback()

                                    response_data = {
                                        "error": (
                                            "Order update failed. "
                                            "Please contact canteen staff."
                                        ),
                                        "payment_captured": True
                                    }
                                    response_status = 409

                                else:
                                    conn.commit()

                                    response_data = {
                                        "success": True,
                                        "order_id": order_id,
                                        "qr_token": qr_token,
                                        "pickup_code": pickup_code
                                    }

        except Exception:
            conn.rollback()
            raise

        finally:
            cur.close()
            conn.close()

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

    conn = None
    cur = None

    try:
        response_data = None
        response_status = 200

        conn = get_connection()
        cur = conn.cursor()

        # Lock this order while verifying collection.
        cur.execute("""
            SELECT id, status, payment_status
            FROM orders
            WHERE qr_token = %s
            FOR UPDATE
        """, (qr_token,))

        order = cur.fetchone()

        if order is None:
            response_data = {
                "error": "Invalid QR code."
            }
            response_status = 404

        elif order[2] != "paid":
            response_data = {
                "error": "Payment has not been completed.",
                "payment_status": order[2]
            }
            response_status = 403

        elif order[1] == "successful":
            response_data = {
                "error": "This order has already been collected.",
                "order_id": order[0],
                "status": order[1]
            }
            response_status = 409

        elif order[1] != "pending":
            response_data = {
                "error": "This order cannot be collected.",
                "status": order[1]
            }
            response_status = 409

        else:
            cur.execute("""
                UPDATE orders
                SET status = 'successful'
                WHERE id = %s
                  AND status = 'pending'
                  AND payment_status = 'paid'
            """, (order[0],))

            if cur.rowcount != 1:
                response_data = {
                    "error": "Order status changed. Please scan again."
                }
                response_status = 409

            else:
                response_data = {
                    "message": (
                        "QR verified. The order is ready for handover."
                    ),
                    "order_id": order[0],
                    "status": "successful"
                }

        conn.commit()

        return jsonify(response_data), response_status

    except Exception:
        if conn is not None:
            conn.rollback()

        app.logger.exception("Could not verify the QR code.")

        return jsonify({
            "error": "Verification failed. Please try again."
        }), 500

    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()


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

    conn = None
    cur = None

    try:
        response_data = None
        response_status = 200

        conn = get_connection()
        cur = conn.cursor()

        # Lock the order during pickup verification.
        cur.execute("""
            SELECT id, status, payment_status
            FROM orders
            WHERE pickup_code = %s
            FOR UPDATE
        """, (pickup_code,))

        order = cur.fetchone()

        if order is None:
            response_data = {
                "error": "Pickup code not found."
            }
            response_status = 404

        elif order[2] != "paid":
            response_data = {
                "error": "Payment has not been completed.",
                "payment_status": order[2]
            }
            response_status = 403

        elif order[1] == "successful":
            response_data = {
                "error": "This order has already been collected.",
                "order_id": order[0],
                "status": order[1]
            }
            response_status = 409

        elif order[1] != "pending":
            response_data = {
                "error": "This order cannot be collected.",
                "status": order[1]
            }
            response_status = 409

        else:
            cur.execute("""
                UPDATE orders
                SET status = 'successful'
                WHERE id = %s
                  AND status = 'pending'
                  AND payment_status = 'paid'
            """, (order[0],))

            if cur.rowcount != 1:
                response_data = {
                    "error": (
                        "Order status changed. Please verify again."
                    )
                }
                response_status = 409

            else:
                response_data = {
                    "message": "Pickup code verified successfully.",
                    "order_id": order[0],
                    "status": "successful"
                }

        conn.commit()

        return jsonify(response_data), response_status

    except Exception:
        if conn is not None:
            conn.rollback()

        app.logger.exception("Pickup code verification failed.")

        return jsonify({
            "error": "Verification failed. Please try again."
        }), 500

    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()
# --------------------------------------------------
# STUDENT ORDER HISTORY / STATUS / RECEIPT
# --------------------------------------------------


@app.route("/api/my-orders", methods=["GET"])
@login_required
def my_orders():
    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT id, total, status, payment_status, created_at,
                   qr_token, pickup_code
            FROM orders
            WHERE student_id = %s
            ORDER BY id DESC
        """, (session["student_id"],))

        orders = cur.fetchall()
        result = []

        for order in orders:
            cur.execute("""
                SELECT item_name, unit_price, quantity
                FROM order_items
                WHERE order_id = %s
                ORDER BY id
            """, (order[0],))

            rows = cur.fetchall()

            is_paid = order[3] == "paid"

            result.append({
                "order_id": order[0],
                "total": order[1],
                "status": order[2],
                "payment_status": order[3],
                "created_at": order[4],

                # Only reveal collection credentials after payment.
                "qr_token": order[5] if is_paid else None,
                "pickup_code": order[6] if is_paid else None,

                "items": [
                    {
                        "name": row[0],
                        "price": row[1],
                        "quantity": row[2]
                    }
                    for row in rows
                ]
            })

        return jsonify({"orders": result}), 200

    except Exception:
        app.logger.exception("Could not load student order history.")
        return jsonify({"error": "Could not load your orders."}), 500

    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()

@app.route("/api/orders/<int:order_id>/status", methods=["GET"])
@login_required
def order_status(order_id):
    qr_token = request.args.get("token", "")

    if not qr_token or len(qr_token) > 200:
        return jsonify({"error": "Invalid status request."}), 400

    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT status, payment_status
            FROM orders
            WHERE id = %s AND qr_token = %s AND student_id = %s
        """, (order_id, qr_token, session["student_id"]))

        order = cur.fetchone()

        if order is None:
            return jsonify({"error": "Order not found."}), 404

        return jsonify({
            "order_id": order_id,
            "status": order[0],
            "payment_status": order[1]
        }), 200

    except Exception:
        app.logger.exception("Could not retrieve order status.")
        return jsonify({"error": "Could not retrieve order status."}), 500

    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()


@app.route("/api/orders/<int:order_id>/receipt", methods=["GET"])
@login_required
def order_receipt(order_id):
    qr_token = request.args.get("token", "")

    if not qr_token or len(qr_token) > 200:
        return jsonify({"error": "Invalid receipt request."}), 400

    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT id, total, status, payment_status,
                   qr_token, pickup_code
            FROM orders
            WHERE id = %s
              AND qr_token = %s
              AND student_id = %s
        """, (
            order_id,
            qr_token,
            session["student_id"]
        ))

        order = cur.fetchone()

        if order is None:
            return jsonify({"error": "Booking not found."}), 404

        if order[3] != "paid":
            return jsonify({
                "error": (
                    "Receipt is available only after successful payment."
                )
            }), 403

        cur.execute("""
            SELECT item_name, unit_price, quantity
            FROM order_items
            WHERE order_id = %s
            ORDER BY id
        """, (order_id,))

        rows = cur.fetchall()

        return jsonify({
            "order_id": order[0],
            "total": order[1],
            "status": order[2],
            "payment_status": order[3],
            "pickup_code": order[5],
            "items": [
                {
                    "name": row[0],
                    "price": row[1],
                    "quantity": row[2]
                }
                for row in rows
            ]
        }), 200

    except Exception:
        app.logger.exception("Could not retrieve order receipt.")
        return jsonify({"error": "Could not retrieve receipt."}), 500

    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()

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

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO staff_users (id, username, password_hash, updated_at)
            VALUES (1, %s, %s, CURRENT_TIMESTAMP::TEXT)
            ON CONFLICT (id) DO UPDATE SET
                username = EXCLUDED.username,
                password_hash = EXCLUDED.password_hash,
                updated_at = CURRENT_TIMESTAMP::TEXT
        """, (username, password_hash))

        conn.commit()

    except Exception:
        conn.rollback()
        app.logger.exception("Staff account update failed")
        raise SystemExit("Could not save the staff account.")

    finally:
        cur.close()
        conn.close()

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

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO staff_users
                (id, username, password_hash, updated_at)
            VALUES (1, %s, %s, CURRENT_TIMESTAMP::TEXT)
            ON CONFLICT (id) DO UPDATE SET
                username = EXCLUDED.username,
                password_hash = EXCLUDED.password_hash,
                updated_at = CURRENT_TIMESTAMP::TEXT
        """, (username, password_hash))

        conn.commit()

    except Exception:
        conn.rollback()
        app.logger.exception("Staff bootstrap synchronization failed")
        raise

    finally:
        cur.close()
        conn.close()

# Initialize and verify the PostgreSQL database.
# Initialize database
init_database()
sync_staff_account_from_env()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "set-staff":
        set_staff_account()
    else:
        app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("FLASK_DEBUG", "0") == "1")
