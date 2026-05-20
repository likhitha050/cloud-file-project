import pyotp
import hashlib
from measurement import measure_performance

def generate_totp_secret():
    """Generates a base32 secret."""
    return pyotp.random_base32()

@measure_performance(algo_name="TOTP", operation="Generate")
def generate_otp(secret):
    """Generates a Time-Based OTP (valid for 30 seconds) using SHA256."""
    totp = pyotp.TOTP(secret, digest=hashlib.sha256)
    return totp.now()

@measure_performance(algo_name="TOTP", operation="Verify")
def verify_otp(secret, user_otp):
    """Verifies the TOTP code against the current time."""
    totp = pyotp.TOTP(secret, digest=hashlib.sha256)
    return totp.verify(user_otp)
