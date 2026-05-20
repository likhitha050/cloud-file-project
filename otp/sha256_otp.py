import hashlib
import random
import string
from measurement import measure_performance

def generate_secret():
    """Generates a random 16-character string to act as the user's secret."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

@measure_performance(algo_name="SHA256-OTP", operation="Generate")
def generate_otp(secret, challenge="auth_request"):
    """Generates a 6-digit OTP using basic SHA-256 hashing."""
    data = f"{secret}{challenge}".encode()
    hash_hex = hashlib.sha256(data).hexdigest()
    # Convert hex to an integer, take the last 6 digits as a string
    return str(int(hash_hex, 16))[-6:].zfill(6)

@measure_performance(algo_name="SHA256-OTP", operation="Verify")
def verify_otp(secret, user_otp, challenge="auth_request"):
    """Verifies the SHA-256 OTP."""
    data = f"{secret}{challenge}".encode()
    hash_hex = hashlib.sha256(data).hexdigest()
    expected_otp = str(int(hash_hex, 16))[-6:].zfill(6)
    
    return user_otp == expected_otp
