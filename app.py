from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
import os
import uuid
import time

# 🔒 Security Imports
from werkzeug.security import generate_password_hash, check_password_hash

# 🗄️ Database Imports
from pymongo import MongoClient
import certifi

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Your custom encryption/OTP modules
from crypto import aes128, aes256, chacha20
from otp import sha256_otp, hmac_otp, totp

app = Flask(__name__, template_folder='ui/templates', static_folder='ui/static')

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "super_secure_key"
)

# ==========================================
# 🗄️ MONGODB CONFIGURATION
# ==========================================

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    print("WARNING: MONGO_URI environment variable is not set!")

try:
    # Use certifi to prevent SSL handshake errors on Render
    client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
    db = client.get_database("secure_cloud_vault")
    
    # Collections
    users_col = db.users
    files_col = db.files
    print("Successfully connected to MongoDB Atlas.")
except Exception as e:
    print(f"Failed to connect to MongoDB Atlas: {e}")


# ==========================================
# 📧 SENDGRID CONFIGURATION
# ==========================================

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "noreply@example.com")

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
                f"A secure file '{filename}' has been shared with you.\n\n"
                f"Your {algo} OTP is: {otp_code}\n\n"
                f"WARNING: This code expires in 2 minutes."
            )
        )

        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)

        if 200 <= response.status_code < 300:
            print(f"Email sent successfully to {receiver_email}")
            return True
        else:
            print(f"SendGrid Error: {response.status_code}")
            return False

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return False

# ==========================================
# 📁 CREATE REQUIRED FOLDERS
# ==========================================

os.makedirs("storage/encrypted_files", exist_ok=True)
os.makedirs("storage/decrypted_files", exist_ok=True)
os.makedirs("test_data", exist_ok=True)
os.makedirs("results", exist_ok=True)

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
        name = request.form.get('name')
        email = request.form.get('email')
        username = request.form.get('username').lower()
        password = request.form.get('password')

        # Check if user already exists in MongoDB
        if users_col.find_one({"username": username}):
            flash("Username already exists!", "error")
        else:
            # 🔒 Hash the password before saving it to the database
            hashed_password = generate_password_hash(password)

            # Insert new user into MongoDB
            users_col.insert_one({
                "username": username,
                "name": name,
                "email": email,
                "password": hashed_password # Save the hash, NOT the raw password
            })
            flash("Account created successfully!", "success")
            return redirect(url_for('login'))

    return render_template('register.html')

# ==========================================
# LOGIN
# ==========================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']

        # Fetch user from MongoDB
        user = users_col.find_one({"username": username})

        # 🔒 Check if user exists AND if the input password matches the stored hash
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials!", "error")

    return render_template('login.html')

# ==========================================
# DASHBOARD
# ==========================================

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    current_user = session['user']

    # Fetch files owned by the current user
    my_files_cursor = files_col.find({"owner": current_user})
    my_files = {f["file_id"]: f for f in my_files_cursor}

    # Fetch files shared with the current user
    shared_files_cursor = files_col.find({f"shared_with.{current_user}": {"$exists": True}})
    shared_files = {f["file_id"]: f for f in shared_files_cursor}

    # Fetch all usernames for the sharing dropdown
    all_users_cursor = users_col.find({}, {"username": 1})
    all_users = [u["username"] for u in all_users_cursor]

    return render_template(
        'dashboard.html',
        username=current_user,
        my_files=my_files,
        shared_files=shared_files,
        all_users=all_users
    )

# ==========================================
# FILE UPLOAD
# ==========================================

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))

    uploaded_file = request.files.get('file')
    algorithm = request.form.get('algorithm')

    if not uploaded_file or uploaded_file.filename == '':
        flash("No file selected!", "error")
        return redirect(url_for('dashboard'))

    temp_path = f"test_data/temp_{uploaded_file.filename}"
    uploaded_file.save(temp_path)

    file_id = str(uuid.uuid4())[:8]
    encrypted_path = f"storage/encrypted_files/locked_{file_id}.enc"

    try:
        if algorithm == "AES-128":
            key = aes128.generate_aes128_key()
            aes128.encrypt_file(temp_path, encrypted_path, key)
        elif algorithm == "AES-256":
            key = aes256.generate_aes256_key()
            aes256.encrypt_file(temp_path, encrypted_path, key)
        elif algorithm == "ChaCha20":
            key = chacha20.generate_chacha20_key()
            chacha20.encrypt_file(temp_path, encrypted_path, key)

        # Store file metadata in MongoDB
        files_col.insert_one({
            'file_id': file_id,
            'owner': session['user'],
            'filename': uploaded_file.filename,
            'algo': algorithm,
            'key': key, 
            'shared_with': {}
        })

        os.remove(temp_path)
        flash(f"File encrypted with {algorithm} and stored.", "success")

    except Exception as e:
        flash(f"Encryption error: {e}", "error")

    return redirect(url_for('dashboard'))

# ==========================================
# DELETE FILE
# ==========================================

@app.route('/delete_file/<file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    current_user = session['user']

    # Fetch the file to ensure it exists and belongs to the logged-in user
    file_data = files_col.find_one({"file_id": file_id})

    if not file_data:
        flash("File not found.", "error")
        return redirect(url_for('dashboard'))

    # Security Check: Ensure the user trying to delete is the actual owner
    if file_data['owner'] != current_user:
        flash("Permission denied. You do not own this file.", "error")
        return redirect(url_for('dashboard'))

    try:
        # 1. Delete the physical encrypted file from Render storage
        # This matches the path format you used in your upload route
        enc_path = f"storage/encrypted_files/locked_{file_id}.enc"
        if os.path.exists(enc_path):
            os.remove(enc_path)

        # 2. Delete the file record from MongoDB Atlas
        files_col.delete_one({"file_id": file_id})

        flash(f"File '{file_data['filename']}' successfully deleted.", "success")

    except Exception as e:
        print(f"Error deleting file: {e}")
        flash(f"An error occurred while deleting: {e}", "error")

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

    # Verify file and target user exist in DB
    file_data = files_col.find_one({"file_id": file_id})
    target_user_data = users_col.find_one({"username": target_username})

    if file_data and target_user_data and otp_algo:
        if otp_algo == "SHA-256":
            secret = sha256_otp.generate_secret()
            otp_code = sha256_otp.generate_otp(secret)
        elif otp_algo == "HMAC":
            secret = hmac_otp.generate_hmac_secret()
            otp_code = hmac_otp.generate_otp(secret, counter=1)
        elif otp_algo == "TOTP":
            secret = totp.generate_totp_secret()
            otp_code = totp.generate_otp(secret)

        # Update MongoDB with the share details
        files_col.update_one(
            {"file_id": file_id},
            {"$set": {
                f"shared_with.{target_username}": {
                    'secret': secret,
                    'algo': otp_algo,
                    'timestamp': time.time()
                }
            }}
        )

        target_email = target_user_data['email']
        filename = file_data['filename']

        print(f"Attempting to send {otp_algo} email to {target_email}...")
        
        email_sent = send_real_email(target_email, otp_code, filename, otp_algo)

        if email_sent:
            flash(f"File shared! A 2-minute {otp_algo} OTP has been emailed to {target_email}.", "success")
        else:
            flash("Email sending failed.", "error")

    return redirect(url_for('dashboard'))

# ==========================================
# VERIFY OTP
# ==========================================

@app.route('/verify/<file_id>', methods=['GET', 'POST'])
def verify_otp(file_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    current_user = session['user']
    
    # Fetch the file to ensure the current user has access
    file_data = files_col.find_one({"file_id": file_id})

    if not file_data or current_user not in file_data.get('shared_with', {}):
        flash("Permission denied or OTP already used.", "error")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        user_input_otp = request.form.get('otp_code')
        share_data = file_data['shared_with'][current_user]

        secret = share_data['secret']
        algo = share_data['algo']
        generated_time = share_data['timestamp']

        # Check expiration (120 seconds)
        if (time.time() - generated_time) > 120:
            # Remove share access if expired
            files_col.update_one(
                {"file_id": file_id}, 
                {"$unset": {f"shared_with.{current_user}": ""}}
            )
            flash("OTP expired after 2 minutes.", "error")
            return redirect(url_for('dashboard'))

        is_valid = False

        if algo == "SHA-256":
            is_valid = sha256_otp.verify_otp(secret, user_input_otp)
        elif algo == "HMAC":
            is_valid = hmac_otp.verify_otp(secret, user_input_otp, counter=1)
        elif algo == "TOTP":
            is_valid = totp.verify_otp(secret, user_input_otp)

        if is_valid:
            # If successful, consume the OTP by removing the user's access mapping
            files_col.update_one(
                {"file_id": file_id}, 
                {"$unset": {f"shared_with.{current_user}": ""}}
            )

            enc_path = f"storage/encrypted_files/locked_{file_id}.enc"
            dec_path = f"storage/decrypted_files/unlocked_{file_data['filename']}"

            crypt_algo = file_data['algo']
            key = file_data['key']

            if crypt_algo == "AES-128":
                aes128.decrypt_file(enc_path, dec_path, key)
            elif crypt_algo == "AES-256":
                aes256.decrypt_file(enc_path, dec_path, key)
            elif crypt_algo == "ChaCha20":
                chacha20.decrypt_file(enc_path, dec_path, key)

            return send_file(dec_path, as_attachment=True)
        else:
            flash("Invalid OTP.", "error")

    return render_template(
        'verify.html',
        file_id=file_id,
        filename=file_data['filename']
    )

# ==========================================
# ADMIN USERS
# ==========================================

@app.route('/admin/users')
def admin_view_users():
    # Fetch all users but hide their hashed passwords from the API output
    all_users = users_col.find({}, {"_id": 0, "password": 0})
    
    user_dict = {}
    for u in all_users:
        username = u.pop("username")
        user_dict[username] = u
        
    return jsonify(user_dict)

# ==========================================
# DOWNLOAD CSV RESULTS
# ==========================================

@app.route('/download-results')
def download_results():
    csv_path = 'results/performance_results.csv'
    if not os.path.exists(csv_path):
        return ("CSV file not generated yet.", 404)

    return send_file(csv_path, as_attachment=True)

# ==========================================
# LOGOUT
# ==========================================

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# ==========================================
# MAIN
# ==========================================

if __name__ == '__main__':
    print("Starting Secure Cloud Server...")
    app.run(host='0.0.0.0', port=5000, debug=False)
