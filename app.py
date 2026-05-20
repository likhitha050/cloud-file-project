from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
import os
import uuid
import time
import smtplib
from email.message import EmailMessage

from crypto import aes128, aes256, chacha20
from otp import sha256_otp, hmac_otp, totp # IMPORTING ALL 3 OTPs

app = Flask(__name__, template_folder='ui/templates', static_folder='ui/static')
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super_secure_key")

# ==========================================
# 📧 EMAIL CONFIGURATION
# ==========================================
SENDER_EMAIL = "cloudserversecure001@gmail.com" # <--- PUT YOUR GMAIL HERE
APP_PASSWORD = "nafaywvjemqzrfjy" # <--- PUT YOUR APP PASSWORD HERE

def send_real_email(receiver_email, otp_code, filename, algo):
    """Sends the OTP via real Gmail servers."""
    try:
        msg = EmailMessage()
        msg.set_content(f"Hello!\n\nA secure file '{filename}' has been shared with you via the Energy-Aware Cloud Vault.\n\nYour {algo} One-Time Password (OTP) to unlock this file is: {otp_code}\n\nWARNING: This code will expire in 2 minutes and can only be used ONCE.\nDo not share this code with anyone.")
        msg['Subject'] = 'Secure Cloud Vault - Your OTP Code'
        msg['From'] = SENDER_EMAIL
        msg['To'] = receiver_email

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

# ==========================================
# 💾 SIMULATED DATABASE
# ==========================================
USERS = {}
FILES_DB = {}

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
        username = request.form.get('username').lower()
        password = request.form.get('password')

        if username in USERS:
            flash("Username already exists! Choose another.", "error")
        else:
            USERS[username] = {"name": name, "email": email, "password": password}
            flash("Account created successfully! You can now log in.", "success")
            return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        
        if username in USERS and USERS[username]['password'] == password:
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials! Please try again.", "error")
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: return redirect(url_for('login'))
    
    current_user = session['user']
    my_files = {fid: data for fid, data in FILES_DB.items() if data['owner'] == current_user}
    shared_files = {fid: data for fid, data in FILES_DB.items() if current_user in data['shared_with']}
    
    return render_template('dashboard.html', 
                           username=current_user, 
                           my_files=my_files, 
                           shared_files=shared_files,
                           all_users=list(USERS.keys()))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session: return redirect(url_for('login'))
        
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
            
        FILES_DB[file_id] = {
            'owner': session['user'],
            'filename': uploaded_file.filename,
            'algo': algorithm,
            'key': key,             
            'shared_with': {}       
        }

        os.remove(temp_path)
        flash(f"File encrypted with {algorithm} and stored.", "success")
        
    except Exception as e:
        flash(f"Encryption error: {e}", "error")

    return redirect(url_for('dashboard'))

@app.route('/share/<file_id>', methods=['POST'])
def share_file(file_id):
    if 'user' not in session: return redirect(url_for('login'))
    
    target_username = request.form.get('share_user')
    otp_algo = request.form.get('otp_algo')
    
    if file_id in FILES_DB and target_username in USERS and otp_algo:
        
        # 1. Generate Secret and OTP based on chosen Algorithm
        if otp_algo == "SHA-256":
            secret = sha256_otp.generate_secret()
            otp_code = sha256_otp.generate_otp(secret)
        elif otp_algo == "HMAC":
            secret = hmac_otp.generate_hmac_secret()
            otp_code = hmac_otp.generate_otp(secret, counter=1)
        elif otp_algo == "TOTP":
            secret = totp.generate_totp_secret()
            otp_code = totp.generate_otp(secret)
            
        # 2. Store the secret, the algorithm type, and the EXACT TIME it was generated
        FILES_DB[file_id]['shared_with'][target_username] = {
            'secret': secret,
            'algo': otp_algo,
            'timestamp': time.time() # Records current time in seconds
        }
        
        # 3. Send Email
        target_email = USERS[target_username]['email']
        filename = FILES_DB[file_id]['filename']
        print(f"Attempting to send {otp_algo} email to {target_email}...")
        
        email_sent = send_real_email(target_email, otp_code, filename, otp_algo)
        
        if email_sent:
            flash(f"File shared! A 2-minute {otp_algo} OTP has been emailed to {target_email}.", "success")
        else:
            flash(f"File shared, but the email failed to send. Check server console.", "error")
    
    return redirect(url_for('dashboard'))

@app.route('/verify/<file_id>', methods=['GET', 'POST'])
def verify_otp(file_id):
    if 'user' not in session: return redirect(url_for('login'))
    
    current_user = session['user']
    file_data = FILES_DB.get(file_id)
    
    if not file_data or current_user not in file_data['shared_with']:
        flash("You do not have permission to view this file or the OTP was already used.", "error")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        user_input_otp = request.form.get('otp_code')
        
        # Retrieve the specific data for this user
        share_data = file_data['shared_with'][current_user]
        secret = share_data['secret']
        algo = share_data['algo']
        generated_time = share_data['timestamp']
        
        # FIX 1: CHECK TIME EXPIRATION (120 seconds = 2 minutes)
        if time.time() - generated_time > 120:
            # If expired, delete it so it can never be guessed
            del file_data['shared_with'][current_user]
            flash(" Security Alert: This OTP has expired after 2 minutes. Ask the sender to share the file again.", "error")
            return redirect(url_for('dashboard'))

        # FIX 2: VERIFY USING THE CORRECT ALGORITHM
        is_valid = False
        if algo == "SHA-256":
            is_valid = sha256_otp.verify_otp(secret, user_input_otp)
        elif algo == "HMAC":
            is_valid = hmac_otp.verify_otp(secret, user_input_otp, counter=1)
        elif algo == "TOTP":
            is_valid = totp.verify_otp(secret, user_input_otp)
        
        if is_valid:
            # BUG FIX 3: ENFORCE SINGLE USE!
            # Delete the permission from the database so the OTP can NEVER be used again.
            del file_data['shared_with'][current_user]
            
            # Decrypt and send file
            enc_path = f"storage/encrypted_files/locked_{file_id}.enc"
            dec_path = f"storage/decrypted_files/unlocked_{file_data['filename']}"
            
            crypt_algo = file_data['algo']
            key = file_data['key']
            
            if crypt_algo == "AES-128": aes128.decrypt_file(enc_path, dec_path, key)
            elif crypt_algo == "AES-256": aes256.decrypt_file(enc_path, dec_path, key)
            elif crypt_algo == "ChaCha20": chacha20.decrypt_file(enc_path, dec_path, key)
            
            return send_file(dec_path, as_attachment=True)
        else:
            flash("Invalid OTP Code. Access Denied.", "error")
            
    return render_template('verify.html', file_id=file_id, filename=file_data['filename'])

@app.route('/admin/users')
def admin_view_users():
    """A secret route to view the in-memory database during the presentation."""
    return jsonify(USERS)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    os.makedirs("storage/encrypted_files", exist_ok=True)
    os.makedirs("storage/decrypted_files", exist_ok=True)
    os.makedirs("test_data", exist_ok=True)
    print("Starting Secure Cloud Server...")
    app.run(debug=True, port=5000)