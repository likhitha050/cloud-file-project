import pyotp
import hashlib
from measurement import measure_performance

def generate_hmac_secret():
    """Generates a base32 secret required by standard HMAC/TOTP algorithms."""
    return pyotp.random_base32()

@measure_performance(algo_name="HMAC-OTP", operation="Generate")
def generate_otp(secret, counter):
    """Generates a 6-digit OTP using HMAC-SHA256 based on a counter."""
    hotp = pyotp.HOTP(secret, digest=hashlib.sha256)
    return hotp.at(counter)

@measure_performance(algo_name="HMAC-OTP", operation="Verify")
def verify_otp(secret, user_otp, counter):
    """Verifies the HMAC-SHA256 OTP."""
    hotp = pyotp.HOTP(secret, digest=hashlib.sha256)
    return hotp.verify(user_otp, counter)
