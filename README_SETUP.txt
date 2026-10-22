SMART CANTEEN STUDENT LOGIN UPDATE

Files in this bundle:
- app.py: Flask backend with registration, login, OTP, password reset, and account-linked orders.
- templates/index.html: existing menu page with student welcome and Log Out option.
- templates/login.html: sign-in, account registration, and password reset interface.
- templates/booking.html: account-based booking history with QR codes and pickup codes.
- .env.example: configuration template (copy it to .env and fill in your settings).

IMPORTANT DATA SAFETY
1. Stop the running Flask app before replacing files.
2. Make a backup copy of your existing canteen.db first.
3. Copy the updated app.py into your project folder.
4. Copy the supplied templates into your existing templates folder, replacing index.html and booking.html and adding login.html.
5. Do NOT delete, recreate, or replace canteen.db. On startup, app.py creates the new students/OTP tables and adds student_id to the existing orders table without deleting existing orders.
6. Existing orders created before student accounts existed are preserved, but they cannot automatically be assigned to a student account. New orders will be linked to the signed-in student.

EMAIL OTP CONFIGURATION
The server does not fake or display OTPs in the browser. Real email delivery requires SMTP settings. Copy `.env.example` to `.env` in the same folder as `app.py`, then fill in your values before starting Flask. The app reads this local `.env` file automatically:
- FLASK_SECRET_KEY: a long random secret, unique to your installation.
- COLLEGE_EMAIL_DOMAIN=psnacet.edu.in
- SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM

Alternatively, set the variables directly in Windows PowerShell for a local run (replace values with your provider's settings):
$env:FLASK_SECRET_KEY = "replace-this-with-a-long-random-secret"
$env:COLLEGE_EMAIL_DOMAIN = "psnacet.edu.in"
$env:SMTP_HOST = "smtp.gmail.com"
$env:SMTP_PORT = "587"
$env:SMTP_USERNAME = "your-sending-account@gmail.com"
$env:SMTP_PASSWORD = "your-provider-app-password"
$env:SMTP_FROM = "your-sending-account@gmail.com"
python app.py

Never paste or commit the actual SMTP password or FLASK_SECRET_KEY. If using Gmail, use an app password where supported, not your normal account password. After setting the environment variables, open http://127.0.0.1:5000/login.

FEATURES
- Only @psnacet.edu.in addresses can register.
- Email OTP expires after five minutes, is single-use, and resend is rate-limited.
- Up to five incorrect OTP attempts are allowed before a new code is required.
- Passwords are stored as hashes using Werkzeug.
- Student sessions are cleared on Log Out.
- Students can change their display name from the three-dot menu after signing in.
- Orders are associated with the signed-in student and shown in My Bookings across days/devices that can access the same server/database.
- Existing menu, QR verification, pickup codes, and admin routes are retained.

SECURITY NOTE
This is a development-ready student login addition, not a complete production deployment. Before deploying publicly, configure HTTPS, set COOKIE_SECURE=1, add rate limiting at the server/proxy level, and protect the existing /admin route with a separate admin authentication system. The current project’s admin page remains as it was.
