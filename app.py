from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
import os
import uuid
import time
import csv

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from crypto import aes128, aes256, chacha20
from otp import sha256_otp, hmac_otp, totp

app = Flask(__name__, template_folder='ui/templates', static_folder='ui/static')
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super_secure_key")

# ==========================================
# 📊 CSV LOGGING
# ==========================================
CSV_FILE = "/tmp/results.csv"

def log_to_csv(action, filename, algo, extra_info=""):
    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow(["Timestamp", "Action", "Filename", "Algorithm", "Extra Info"])

        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            action,
            filename,
            algo,
            extra_info
        ])

# ==========================================
# 📥 DOWNLOAD CSV
# ==========================================
@app.route('/download-csv')
def download_csv():
    if not os.path.exists(CSV_FILE):
        return "No CSV data found yet."
    return send_file(CSV_FILE, as_attachment=True)

# ==========================================
# 📧 SENDGRID
# ==========================================
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "noreply@example.com")

def send_real_email(receiver_email, otp_code, filename, algo):
    if not SENDGRID_API_KEY:
        print("SENDGRID_API_KEY not set")
        return False

    try:
        message = Mail(
            from_email=SENDER_EMAIL,
            to_emails=receiver_email,
            subject="Secure Cloud Vault - OTP",
            plain_text_content=(
                f"File: {filename}\n"
                f"OTP ({algo}): {otp_code}\n"
                f"Expires in 2 minutes"
            )
        )

        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        return 200 <= response.status_code < 300

    except Exception as e:
        print(e)
        return False

# ==========================================
# 💾 DATABASE (IN MEMORY)
# ==========================================
USERS = {}
FILES_DB = {}

# ==========================================
# 📁 STORAGE FOLDERS
# ==========================================
os.makedirs("storage/encrypted_files", exist_ok=True)
os.makedirs("storage/decrypted_files", exist_ok=True)
os.makedirs("test_data", exist_ok=True)

# ==========================================
# 🌐 ROUTES
# ==========================================

@app.route('/')
def index():
    return redirect(url_for('login'))

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').lower()

        if username in USERS:
            flash("User exists!", "error")
        else:
            USERS[username] = {
                "name": request.form.get('name'),
                "email": request.form.get('email'),
                "password": request.form.get('password')
            }

            flash("Registered!", "success")
            return redirect(url_for('login'))

    return render_template('register.html')

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']

        if username in USERS and USERS[username]['password'] == password:
            session['user'] = username
            return redirect(url_for('dashboard'))

        flash("Invalid login", "error")

    return render_template('login.html')

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']

    my_files = {fid: f for fid, f in FILES_DB.items() if f['owner'] == user}
    shared_files = {fid: f for fid, f in FILES_DB.items() if user in f['shared_with']}

    return render_template(
        'dashboard.html',
        username=user,
        my_files=my_files,
        shared_files=shared_files,
        all_users=list(USERS.keys())
    )

# ---------------- UPLOAD ----------------
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))

    file = request.files.get('file')
    algo = request.form.get('algorithm')

    if not file or file.filename == '':
        flash("No file!", "error")
        return redirect(url_for('dashboard'))

    temp_path = f"test_data/temp_{file.filename}"
    file.save(temp_path)

    file_id = str(uuid.uuid4())[:8]
    enc_path = f"storage/encrypted_files/locked_{file_id}.enc"

    try:
        if algo == "AES-128":
            key = aes128.generate_aes128_key()
            aes128.encrypt_file(temp_path, enc_path, key)

        elif algo == "AES-256":
            key = aes256.generate_aes256_key()
            aes256.encrypt_file(temp_path, enc_path, key)

        elif algo == "ChaCha20":
            key = chacha20.generate_chacha20_key()
            chacha20.encrypt_file(temp_path, enc_path, key)

        FILES_DB[file_id] = {
            "owner": session['user'],
            "filename": file.filename,
            "algo": algo,
            "key": key,
            "shared_with": []   # FIXED
        }

        os.remove(temp_path)

        log_to_csv("UPLOAD", file.filename, algo)

        flash("Uploaded & encrypted!", "success")

    except Exception as e:
        flash(str(e), "error")

    return redirect(url_for('dashboard'))

# ---------------- SHARE (NEW FIX) ----------------
@app.route('/share/<file_id>', methods=['POST'])
def share_file(file_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    if file_id not in FILES_DB:
        return jsonify({"error": "File not found"}), 404

    file_data = FILES_DB[file_id]

    # only owner can share
    if file_data['owner'] != session['user']:
        return jsonify({"error": "Not allowed"}), 403

    target_user = request.form.get('username')

    if target_user not in USERS:
        return jsonify({"error": "User not found"}), 404

    if target_user not in file_data['shared_with']:
        file_data['shared_with'].append(target_user)

    return jsonify({"message": "File shared successfully"})

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# ==========================================
# RUN APP
# ==========================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
