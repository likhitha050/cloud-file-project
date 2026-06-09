import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from measurement import measure_performance

def generate_chacha20_key():
    """Generates a random 32-byte key for ChaCha20."""
    return os.urandom(32)

@measure_performance(algo_name="ChaCha20", operation="Encrypt")
def encrypt_file(input_path, output_path, key):
    """Encrypts a file using ChaCha20 in streaming chunks."""
    nonce = os.urandom(16) 
    
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    
    CHUNK_SIZE = 64 * 1024  # 64KB chunks

    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        # 1. Write the nonce to the file FIRST, by itself
        outfile.write(nonce)
        
        # 2. Loop through the file 64KB at a time
        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # 3. Encrypt the tiny chunk and write it immediately to disk
            encrypted_chunk = encryptor.update(chunk)
            outfile.write(encrypted_chunk)

    return True

@measure_performance(algo_name="ChaCha20", operation="Decrypt")
def decrypt_file(input_path, output_path, key):
    """Decrypts a file using ChaCha20 in streaming chunks."""
    CHUNK_SIZE = 64 * 1024

    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        # 1. Read ONLY the first 16 bytes to extract the nonce
        nonce = infile.read(16)
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()

        # 2. Loop through the rest of the file 64KB at a time
        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # 3. Decrypt the tiny chunk and write it immediately to disk
            decrypted_chunk = decryptor.update(chunk)
            outfile.write(decrypted_chunk)

    return True
