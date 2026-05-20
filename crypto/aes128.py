import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from measurement import measure_performance

def generate_aes128_key():
    """Generates a random 16-byte (128-bit) key for AES-128."""
    return os.urandom(16)

@measure_performance(algo_name="AES-128", operation="Encrypt")
def encrypt_file(input_path, output_path, key):
    """Encrypts a file using AES-128 GCM."""
    # GCM requires a unique 12-byte initialization vector (IV) per encryption
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # We must save the IV, the Auth Tag, and the Ciphertext to decrypt it later
    with open(output_path, 'wb') as f:
        f.write(iv + encryptor.tag + ciphertext)

    return True

@measure_performance(algo_name="AES-128", operation="Decrypt")
def decrypt_file(input_path, output_path, key):
    """Decrypts a file using AES-128 GCM."""
    with open(input_path, 'rb') as f:
        file_data = f.read()

    # Extract the IV (first 12 bytes), Tag (next 16 bytes), and Ciphertext (the rest)
    iv = file_data[:12]
    tag = file_data[12:28]
    ciphertext = file_data[28:]

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    return True
