import os
from cryptography.hazmat.primitives.ciphers.aead import Cipher, algorithms
from measurement import measure_performance

def generate_chacha20_key():
    """Generates a random 32-byte key for ChaCha20."""
    return os.urandom(32)

@measure_performance(algo_name="ChaCha20", operation="Encrypt")
def encrypt_file(input_path, output_path, key):
    """Encrypts a file using ChaCha20 in streaming chunks."""
    nonce = os.urandom(16) # ChaCha20 uses a 16-byte "number used once" (nonce)

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    
    CHUNK_SIZE = 64 * 1024  # 64KB chunks to keep memory usage tiny
    
    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        # Write the nonce at the beginning of the file so we can decrypt later
        outfile.write(nonce)
        
        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # Encrypt the chunk and write it immediately
            encrypted_chunk = encryptor.update(chunk)
            outfile.write(encrypted_chunk)

    return True

@measure_performance(algo_name="ChaCha20", operation="Decrypt")
def decrypt_file(input_path, output_path, key):
    """Decrypts a file using ChaCha20 in streaming chunks."""
    CHUNK_SIZE = 64 * 1024

    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        # Read the first 16 bytes to get the nonce
        nonce = infile.read(16)
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()

        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # Decrypt the chunk and write it immediately
            decrypted_chunk = decryptor.update(chunk)
            outfile.write(decrypted_chunk)

    return True
