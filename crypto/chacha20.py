import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from measurement import measure_performance

def generate_chacha20_key():
    """Generates a random 32-byte key for ChaCha20."""
    return ChaCha20Poly1305.generate_key()

@measure_performance(algo_name="ChaCha20", operation="Encrypt")
def encrypt_file(input_path, output_path, key):
    """Encrypts a file using ChaCha20-Poly1305."""
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12) # ChaCha20 uses a 12-byte "number used once" (nonce)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # The library handles the tagging/integrity check automatically here
    ciphertext = chacha.encrypt(nonce, plaintext, None)

    with open(output_path, 'wb') as f:
        f.write(nonce + ciphertext)

    return True

@measure_performance(algo_name="ChaCha20", operation="Decrypt")
def decrypt_file(input_path, output_path, key):
    """Decrypts a file using ChaCha20-Poly1305."""
    chacha = ChaCha20Poly1305(key)

    with open(input_path, 'rb') as f:
        file_data = f.read()

    nonce = file_data[:12]
    ciphertext = file_data[12:]

    # Automatically verifies integrity before decrypting
    plaintext = chacha.decrypt(nonce, ciphertext, None)

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    return True
