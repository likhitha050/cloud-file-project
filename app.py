from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import os
import uuid
import time
import csv
import psutil

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from crypto import aes128, aes256, chacha20
from otp import sha256_otp, hmac_otp, totp

app = Flask(
    __name__,
    template_folder='ui/templates',
    static_folder='ui/static'
)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "super_secure_key"
)

# ==========================================
# 📁 FOLDERS
# ==========================================
os.makedirs("storage/encrypted_files", exist_ok=True)
os.makedirs("storage/decrypted_files", exist_ok=True)
os.makedirs("test_data", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# ==========================================
# 📊 CSV CONFIG
# ==========================================
CSV_FILE = "logs/results.csv"

# ==========================================
# 📧 SENDGRID CONFIG
# ==========================================
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

SENDER_EMAIL = os.getenv(
    "SENDER_EMAIL",
    "noreply@example.com"
)

# ==========================================
# 💾 IN-MEMORY DATABASE
# ==========================================
USERS = {}
FILES_DB = {}

# ==========================================
# ⚡ ENERGY CALCULATION
# ==========================================
MAX_POWER_WATTS = 15.0


def calculate_energy(cpu_percent, exec_time):

    energy = (
        MAX_POWER_WATTS *
        (cpu_percent / 100.0) *
        exec_time
    )

    return energy


# ==========================================
# 📊 LOG TO CSV
# ==========================================
def log_to_csv(
    action,
    filename,
    algorithm,
    file_size_mb,
    exec_time,
    cpu_percent,
    ram_usage_mb,
    energy,
    extra_info=""
):

    file_exists = os.path.isfile(CSV_FILE)

    with open(
        CSV_FILE,
        mode="a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        # Write header only once
        if not file_exists:

            writer.writerow([
                "Timestamp",
                "Action",
                "Filename",
                "Algorithm",
                "File Size (MB)",
                "Execution Time (s)",
                "CPU Usage (%)",
                "RAM Usage (MB)",
                "Energy (J)",
                "Extra Info"
            ])

        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            action,
            filename,
            algorithm,
            file_size_mb,
            round(exec_time, 6),
            round(cpu_percent, 2),
            round(ram_usage_mb, 2),
            round(energy, 6),
            extra_info
        ])

    print("✅ Metrics Saved")


# ==========================================
# 📊 MEASURE SYSTEM METRICS
# ==========================================
def measure_metrics(start_time):

    process = psutil.Process(os.getpid())

    end_time = time.perf_counter()

    exec_time = end_time - start_time

    cpu_percent = process.cpu_percent(interval=0.1)

    ram_usage_mb = (
        process.memory_info().rss /
        (1024 * 1024)
    )

    energy = calculate_energy(
        cpu_percent,
        exec_time
    )

    return (
        exec_time,
        cpu_percent,
        ram_usage_mb,
        energy
    )


# ==========================================
# 📧 SEND OTP EMAIL
# ==========================================
def send_real_email(
    receiver_email,
    otp_code,
    filename,
    algo
):

    if not SENDGRID_API_KEY:
        print("SENDGRID_API_KEY not set")
        return False

    try:

        message = Mail(
            from_email=SENDER_EMAIL,
            to_emails=receiver_email,
            subject="Secure Cloud Vault - OTP",
            plain_text_content=(
                f"Hello!\n\n"
                f"File: {filename}\n"
                f"OTP ({algo}): {otp_code}\n\n"
                f"Expires in 2 minutes."
            )
        )

        sg = SendGridAPIClient(
            SENDGRID_API_KEY
        )

        response = sg.send(message)

        return (
            200 <= response.status_code < 300
        )

    except Exception as e:

        print(e)

        return False


# ==========================================
# 🌐 ROUTES
# ==========================================

@app.route('/')
def index():

    return redirect(url_for('login'))


# ==========================================
# REGISTER
# ==========================================
@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = (
            request.form
            .get('username')
            .lower()
        )

        if username in USERS:

            flash(
                "Username already exists!",
                "error"
            )

        else:

            USERS[username] = {
                "name": request.form.get('name'),
                "email": request.form.get('email'),
                "password": request.form.get('password')
            }

            flash(
                "Account created!",
                "success"
            )

            return redirect(
                url_for('login')
            )

    return render_template('register.html')


# ==========================================
# LOGIN
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = (
            request.form['username']
            .lower()
        )

        password = request.form['password']

        if (
            username in USERS and
            USERS[username]['password'] == password
        ):

            session['user'] = username

            return redirect(
                url_for('dashboard')
            )

        flash(
            "Invalid credentials!",
            "error"
        )

    return render_template('login.html')


# ==========================================
# DASHBOARD
# ==========================================
@app.route('/dashboard')
def dashboard():

    if 'user' not in session:
        return redirect(url_for('login'))

    current_user = session['user']

    my_files = {
        fid: data
        for fid, data in FILES_DB.items()
        if data['owner'] == current_user
    }

    shared_files = {
        fid: data
        for fid, data in FILES_DB.items()
        if current_user in data['shared_with']
    }

    return render_template(
        'dashboard.html',
        username=current_user,
        my_files=my_files,
        shared_files=shared_files,
        all_users=list(USERS.keys())
    )


# ==========================================
# UPLOAD
# ==========================================
@app.route('/upload', methods=['POST'])
def upload_file():

    if 'user' not in session:
        return redirect(url_for('login'))

    uploaded_file = request.files.get('file')

    algorithm = request.form.get('algorithm')

    if (
        not uploaded_file or
        uploaded_file.filename == ''
    ):

        flash("No file selected!", "error")

        return redirect(url_for('dashboard'))

    temp_path = (
        f"test_data/temp_"
        f"{uploaded_file.filename}"
    )

    uploaded_file.save(temp_path)

    file_id = str(uuid.uuid4())[:8]

    encrypted_path = (
        f"storage/encrypted_files/"
        f"locked_{file_id}.enc"
    )

    start_time = time.perf_counter()

    try:

        # ==================================
        # ENCRYPTION
        # ==================================
        if algorithm == "AES-128":

            key = aes128.generate_aes128_key()

            aes128.encrypt_file(
                temp_path,
                encrypted_path,
                key
            )

        elif algorithm == "AES-256":

            key = aes256.generate_aes256_key()

            aes256.encrypt_file(
                temp_path,
                encrypted_path,
                key
            )

        elif algorithm == "ChaCha20":

            key = chacha20.generate_chacha20_key()

            chacha20.encrypt_file(
                temp_path,
                encrypted_path,
                key
            )

        # ==================================
        # FILE DATABASE
        # ==================================
        FILES_DB[file_id] = {
            'owner': session['user'],
            'filename': uploaded_file.filename,
            'algo': algorithm,
            'key': key,
            'shared_with': {}
        }

        # ==================================
        # METRICS
        # ==================================
        file_size_mb = (
            os.path.getsize(encrypted_path)
            / (1024 * 1024)
        )

        (
            exec_time,
            cpu_percent,
            ram_usage_mb,
            energy
        ) = measure_metrics(start_time)

        log_to_csv(
            action="UPLOAD",
            filename=uploaded_file.filename,
            algorithm=algorithm,
            file_size_mb=round(file_size_mb, 6),
            exec_time=exec_time,
            cpu_percent=cpu_percent,
            ram_usage_mb=ram_usage_mb,
            energy=energy
        )

        os.remove(temp_path)

        flash(
            "File uploaded & encrypted!",
            "success"
        )

    except Exception as e:

        flash(f"Error: {e}", "error")

    return redirect(url_for('dashboard'))


# ==========================================
# SHARE FILE
# ==========================================
@app.route('/share/<file_id>', methods=['POST'])
def share_file(file_id):

    if 'user' not in session:
        return redirect(url_for('login'))

    target_username = request.form.get('share_user')

    otp_algo = request.form.get('otp_algo')

    if file_id not in FILES_DB:
        return "File not found", 404

    if target_username not in USERS:
        return "User not found", 404

    file_data = FILES_DB[file_id]

    if file_data['owner'] != session['user']:
        return "Not allowed", 403

    # ======================================
    # OTP GENERATION
    # ======================================
    if otp_algo == "SHA-256":

        secret = sha256_otp.generate_secret()

        otp_code = sha256_otp.generate_otp(secret)

    elif otp_algo == "HMAC":

        secret = hmac_otp.generate_hmac_secret()

        otp_code = hmac_otp.generate_otp(
            secret,
            counter=1
        )

    else:

        secret = totp.generate_totp_secret()

        otp_code = totp.generate_otp(secret)

    # ======================================
    # SAVE SHARE INFO
    # ======================================
    file_data['shared_with'][target_username] = {
        "secret": secret,
        "algo": otp_algo,
        "timestamp": time.time()
    }

    email = USERS[target_username]['email']

    filename = file_data['filename']

    send_real_email(
        email,
        otp_code,
        filename,
        otp_algo
    )

    # ======================================
    # LOG SHARE
    # ======================================
    log_to_csv(
        action="SHARE",
        filename=filename,
        algorithm=otp_algo,
        file_size_mb="N/A",
        exec_time=0,
        cpu_percent=0,
        ram_usage_mb=0,
        energy=0,
        extra_info=f"Shared to {target_username}"
    )

    flash(
        f"Shared with {target_username}",
        "success"
    )

    return redirect(url_for('dashboard'))


# ==========================================
# VERIFY OTP
# ==========================================
@app.route('/verify/<file_id>', methods=['GET', 'POST'])
def verify_otp(file_id):

    if 'user' not in session:
        return redirect(url_for('login'))

    current_user = session['user']

    file_data = FILES_DB.get(file_id)

    if (
        not file_data or
        current_user not in file_data['shared_with']
    ):

        flash(
            "Access denied or expired.",
            "error"
        )

        return redirect(url_for('dashboard'))

    if request.method == 'POST':

        user_otp = request.form.get('otp_code')

        share_data = (
            file_data['shared_with']
            [current_user]
        )

        if (
            time.time() -
            share_data['timestamp']
        ) > 120:

            del file_data['shared_with'][current_user]

            flash("OTP expired.", "error")

            return redirect(url_for('dashboard'))

        algo = share_data['algo']

        secret = share_data['secret']

        # ==================================
        # VERIFY OTP
        # ==================================
        if algo == "SHA-256":

            valid = sha256_otp.verify_otp(
                secret,
                user_otp
            )

        elif algo == "HMAC":

            valid = hmac_otp.verify_otp(
                secret,
                user_otp,
                counter=1
            )

        else:

            valid = totp.verify_otp(
                secret,
                user_otp
            )

        if valid:

            enc_path = (
                f"storage/encrypted_files/"
                f"locked_{file_id}.enc"
            )

            dec_path = (
                f"storage/decrypted_files/"
                f"unlocked_{file_data['filename']}"
            )

            key = file_data['key']

            crypt = file_data['algo']

            # ==============================
            # DECRYPT
            # ==============================
            if crypt == "AES-128":

                aes128.decrypt_file(
                    enc_path,
                    dec_path,
                    key
                )

            elif crypt == "AES-256":

                aes256.decrypt_file(
                    enc_path,
                    dec_path,
                    key
                )

            else:

                chacha20.decrypt_file(
                    enc_path,
                    dec_path,
                    key
                )

            del file_data['shared_with'][current_user]

            return send_file(
                dec_path,
                as_attachment=True
            )

        flash("Invalid OTP", "error")

    return render_template(
        'verify.html',
        file_id=file_id,
        filename=file_data['filename']
    )


# ==========================================
# METRICS DASHBOARD
# ==========================================
@app.route('/metrics')
def metrics():

    metrics_data = []

    if os.path.exists(CSV_FILE):

        with open(
            CSV_FILE,
            mode="r",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:
                metrics_data.append(row)

    return render_template(
        'metrics.html',
        metrics=metrics_data
    )


# ==========================================
# DOWNLOAD CSV
# ==========================================
@app.route('/download-csv')
def download_csv():

    if not os.path.exists(CSV_FILE):
        return "No CSV logs found yet."

    return send_file(
        CSV_FILE,
        as_attachment=True,
        download_name="cloud_vault_logs.csv"
    )


# ==========================================
# LOGOUT
# ==========================================
@app.route('/logout')
def logout():

    session.pop('user', None)

    return redirect(url_for('login'))


# ==========================================
# RUN
# ==========================================
if __name__ == '__main__':

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False
    )
