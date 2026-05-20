from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
import os
import uuid
import time

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from crypto import aes128, aes256, chacha20
from otp import sha256_otp, hmac_otp, totp

app = Flask(__name__, template_folder='ui/templates', static_folder='ui/static')

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "super_secure_key"
)

# ==========================================
# 📧 SENDGRID CONFIGURATION
# ==========================================
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

SENDER_EMAIL = os.getenv(
    "SENDER_EMAIL",
    "noreply@example.com"
)

def send_real_email(receiver_email, otp_code, filename, algo):
    """Sends OTP using SendGrid API."""

    if not SENDGRID_API_KEY:
        print("SENDGRID_API_KEY not set")
        return False

    try:

        message = Mail(

            from_email=SENDER_EMAIL,

            to_emails=receiver_email,

            subject="Secure Cloud Vault - Your OTP Code",

            plain_text_content=(

                f"Hello!\n\n"

                f"A secure file '{filename}' "
                f"has been shared with you.\n\n"

                f"Your {algo} OTP is: "
                f"{otp_code}\n\n"

                f"WARNING: This code expires "
                f"in 2 minutes."

            )
        )

        sg = SendGridAPIClient(
            SENDGRID_API_KEY
        )

        response = sg.send(message)

        if 200 <= response.status_code < 300:

            print(
                f"Email sent successfully "
                f"to {receiver_email}"
            )

            return True

        else:

            print(
                f"SendGrid Error: "
                f"{response.status_code}"
            )

            return False

    except Exception as e:

        import traceback
        print(traceback.format_exc())

        return False

# ==========================================
# 💾 SIMULATED DATABASE
# ==========================================
USERS = {}
FILES_DB = {}

# ==========================================
# 📁 CREATE REQUIRED FOLDERS
# ==========================================
os.makedirs(
    "storage/encrypted_files",
    exist_ok=True
)

os.makedirs(
    "storage/decrypted_files",
    exist_ok=True
)

os.makedirs(
    "test_data",
    exist_ok=True
)

# ==========================================
# 🌐 ROUTES
# ==========================================

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        name = request.form.get('name')

        email = request.form.get('email')

        username = request.form.get(
            'username'
        ).lower()

        password = request.form.get(
            'password'
        )

        if username in USERS:

            flash(
                "Username already exists! "
                "Choose another.",
                "error"
            )

        else:

            USERS[username] = {

                "name": name,

                "email": email,

                "password": password

            }

            flash(
                "Account created successfully!",
                "success"
            )

            return redirect(
                url_for('login')
            )

    return render_template(
        'register.html'
    )

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form[
            'username'
        ].lower()

        password = request.form[
            'password'
        ]

        if (

            username in USERS and

            USERS[username]['password']
            == password

        ):

            session['user'] = username

            return redirect(
                url_for('dashboard')
            )

        else:

            flash(
                "Invalid credentials!",
                "error"
            )

    return render_template(
        'login.html'
    )

@app.route('/dashboard')
def dashboard():

    if 'user' not in session:

        return redirect(
            url_for('login')
        )

    current_user = session['user']

    my_files = {

        fid: data

        for fid, data in FILES_DB.items()

        if data['owner']
        == current_user

    }

    shared_files = {

        fid: data

        for fid, data in FILES_DB.items()

        if current_user
        in data['shared_with']

    }

    return render_template(

        'dashboard.html',

        username=current_user,

        my_files=my_files,

        shared_files=shared_files,

        all_users=list(
            USERS.keys()
        )
    )

@app.route('/upload', methods=['POST'])
def upload_file():

    if 'user' not in session:

        return redirect(
            url_for('login')
        )

    uploaded_file = request.files.get(
        'file'
    )

    algorithm = request.form.get(
        'algorithm'
    )

    if (

        not uploaded_file or

        uploaded_file.filename == ''

    ):

        flash(
            "No file selected!",
            "error"
        )

        return redirect(
            url_for('dashboard')
        )

    temp_path = (

        f"test_data/"
        f"temp_{uploaded_file.filename}"

    )

    uploaded_file.save(temp_path)

    file_id = str(
        uuid.uuid4()
    )[:8]

    encrypted_path = (

        f"storage/encrypted_files/"
        f"locked_{file_id}.enc"

    )

    try:

        if algorithm == "AES-128":

            key = (
                aes128.generate_aes128_key()
            )

            aes128.encrypt_file(
                temp_path,
                encrypted_path,
                key
            )

        elif algorithm == "AES-256":

            key = (
                aes256.generate_aes256_key()
            )

            aes256.encrypt_file(
                temp_path,
                encrypted_path,
                key
            )

        elif algorithm == "ChaCha20":

            key = (
                chacha20.generate_chacha20_key()
            )

            chacha20.encrypt_file(
                temp_path,
                encrypted_path,
                key
            )

        FILES_DB[file_id] = {

            'owner': session['user'],

            'filename':
            uploaded_file.filename,

            'algo': algorithm,

            'key': key,

            'shared_with': {}

        }

        os.remove(temp_path)

        flash(
            f"File encrypted with "
            f"{algorithm} and stored.",
            "success"
        )

    except Exception as e:

        flash(
            f"Encryption error: {e}",
            "error"
        )

    return redirect(
        url_for('dashboard')
    )

@app.route('/share/<file_id>', methods=['POST'])
def share_file(file_id):

    if 'user' not in session:

        return redirect(
            url_for('login')
        )

    target_username = request.form.get(
        'share_user'
    )

    otp_algo = request.form.get(
        'otp_algo'
    )

    if (

        file_id in FILES_DB and

        target_username in USERS and

        otp_algo

    ):

        if otp_algo == "SHA-256":

            secret = (
                sha256_otp.generate_secret()
            )

            otp_code = (
                sha256_otp.generate_otp(secret)
            )

        elif otp_algo == "HMAC":

            secret = (
                hmac_otp.generate_hmac_secret()
            )

            otp_code = (
                hmac_otp.generate_otp(
                    secret,
                    counter=1
                )
            )

        elif otp_algo == "TOTP":

            secret = (
                totp.generate_totp_secret()
            )

            otp_code = (
                totp.generate_otp(secret)
            )

        FILES_DB[file_id][
            'shared_with'
        ][target_username] = {

            'secret': secret,

            'algo': otp_algo,

            'timestamp': time.time()

        }

        target_email = USERS[
            target_username
        ]['email']

        filename = FILES_DB[
            file_id
        ]['filename']

        print(
            f"Attempting to send "
            f"{otp_algo} email "
            f"to {target_email}..."
        )

        email_sent = send_real_email(
            target_email,
            otp_code,
            filename,
            otp_algo
        )

        if email_sent:

            flash(
                f"File shared! "
                f"A 2-minute "
                f"{otp_algo} OTP "
                f"has been emailed "
                f"to {target_email}.",
                "success"
            )

        else:

            flash(
                "Email sending failed.",
                "error"
            )

    return redirect(
        url_for('dashboard')
    )

@app.route('/verify/<file_id>', methods=['GET', 'POST'])
def verify_otp(file_id):

    if 'user' not in session:

        return redirect(
            url_for('login')
        )

    current_user = session['user']

    file_data = FILES_DB.get(file_id)

    if (

        not file_data or

        current_user not in
        file_data['shared_with']

    ):

        flash(
            "Permission denied "
            "or OTP already used.",
            "error"
        )

        return redirect(
            url_for('dashboard')
        )

    if request.method == 'POST':

        user_input_otp = (
            request.form.get('otp_code')
        )

        share_data = file_data[
            'shared_with'
        ][current_user]

        secret = share_data['secret']

        algo = share_data['algo']

        generated_time = (
            share_data['timestamp']
        )

        if (

            time.time()
            - generated_time

        ) > 120:

            del file_data[
                'shared_with'
            ][current_user]

            flash(
                "OTP expired after "
                "2 minutes.",
                "error"
            )

            return redirect(
                url_for('dashboard')
            )

        is_valid = False

        if algo == "SHA-256":

            is_valid = (
                sha256_otp.verify_otp(
                    secret,
                    user_input_otp
                )
            )

        elif algo == "HMAC":

            is_valid = (
                hmac_otp.verify_otp(
                    secret,
                    user_input_otp,
                    counter=1
                )
            )

        elif algo == "TOTP":

            is_valid = (
                totp.verify_otp(
                    secret,
                    user_input_otp
                )
            )

        if is_valid:

            del file_data[
                'shared_with'
            ][current_user]

            enc_path = (

                f"storage/"
                f"encrypted_files/"
                f"locked_{file_id}.enc"

            )

            dec_path = (

                f"storage/"
                f"decrypted_files/"
                f"unlocked_"
                f"{file_data['filename']}"

            )

            crypt_algo = file_data[
                'algo'
            ]

            key = file_data['key']

            if crypt_algo == "AES-128":

                aes128.decrypt_file(
                    enc_path,
                    dec_path,
                    key
                )

            elif crypt_algo == "AES-256":

                aes256.decrypt_file(
                    enc_path,
                    dec_path,
                    key
                )

            elif crypt_algo == "ChaCha20":

                chacha20.decrypt_file(
                    enc_path,
                    dec_path,
                    key
                )

            return send_file(
                dec_path,
                as_attachment=True
            )

        else:

            flash(
                "Invalid OTP.",
                "error"
            )

    return render_template(
        'verify.html',
        file_id=file_id,
        filename=file_data['filename']
    )

@app.route('/admin/users')
def admin_view_users():

    return jsonify(USERS)

@app.route('/logout')
def logout():

    session.pop('user', None)

    return redirect(
        url_for('login')
    )

if __name__ == '__main__':

    print(
        "Starting Secure Cloud Server..."
    )

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False
    )
