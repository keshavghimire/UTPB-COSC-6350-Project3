from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

keys = {
    0b00: b'\xd7\xff\xe8\xf1\x0f\x12\x4c\x56\x91\x8a\x61\x4a\xcf\xc6\x58\x14',
    0b01: b'\x55\x26\x73\x6d\xdd\x6c\x4a\x05\x92\xed\x33\xcb\xc5\xb1\xb7\x6d',
    0b10: b'\x88\x86\x3e\xef\x1a\x37\x42\x7e\xa0\xb8\x67\x22\x7f\x09\xa7\xc1',
    0b11: b'\x45\x35\x5f\x12\x5d\xb4\x44\x9e\xb0\x74\x15\xe8\xdf\x5e\x27\xd4'
}


# Function to encrypt a string using AES
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)  # Generate a random 16-byte IV

    # Create cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create encryptor
    encryptor = cipher.encryptor()

    # Pad the plaintext to be AES block size (16 bytes) compatible
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the IV concatenated with the ciphertext (to be used in decryption)
    return iv + ciphertext


# Function to decrypt the AES ciphertext
def aes_decrypt(ciphertext, key):
    # Extract the IV from the first 16 bytes
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    # Create cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create decryptor
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Return the original plaintext as a string
    return unpadded_data.decode()


def decompose_byte(byte):
    return [(byte >> 6) & 0b11, (byte >> 4) & 0b11, (byte >> 2) & 0b11, byte & 0b11]


def recompose_byte(crumbs):
    return (crumbs[0] << 6) + (crumbs[1] << 4) + (crumbs[2] << 2) + crumbs[3]
