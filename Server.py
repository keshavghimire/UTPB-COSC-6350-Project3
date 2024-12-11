import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

from Crypto import keys

HOST = '0.0.0.0'
PORT = 5555
BUFFER_SIZE = 2048
PAYLOAD = "The quick brown fox jumps over the lazy dog."



def aes_encrypt(plaintext, key):
    iv = os.urandom(16)  # Random 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    print(f"[DEBUG] Encrypting: {plaintext}, IV: {iv.hex()}, Ciphertext: {ciphertext.hex()}")
    return iv + ciphertext  # Concatenate IV and ciphertext

def decompose_byte(byte):
    return [(byte >> (2 * i)) & 0b11 for i in range(4)]

def handle_client(conn, addr):
    print(f"[INFO] Connection from {addr} established.")
    try:
        crumbs = []
        for char in PAYLOAD:
            crumbs.extend(decompose_byte(ord(char)))

        total_crumbs = len(crumbs)
        print(f"[INFO] Total crumbs to send: {total_crumbs}")
        conn.sendall(str(total_crumbs).encode('utf-8'))

        decrypted_indices = set()

        while len(decrypted_indices) < total_crumbs:
            for crumb_index, crumb in enumerate(crumbs):
                if crumb_index in decrypted_indices:
                    continue

                key = keys[crumb]
                encrypted_crumb = aes_encrypt(str(crumb_index), key)  # Encrypt index
                print(f"[DEBUG] Encrypting index {crumb_index} as {str(crumb_index)}, Ciphertext: {encrypted_crumb.hex()}")
                conn.sendall(f"{crumb_index}|{encrypted_crumb.hex()}".encode('utf-8'))

                try:
                    feedback = conn.recv(BUFFER_SIZE).decode('utf-8').strip()
                    if feedback.isdigit():
                        received_index = int(feedback)
                        if received_index == crumb_index:
                            decrypted_indices.add(received_index)
                            print(f"[INFO] Client successfully decrypted crumb index {received_index}.")
                except Exception as e:
                    print(f"[ERROR] Error receiving feedback from client: {e}")
    except Exception as e:
        print(f"[ERROR] Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"[INFO] Connection from {addr} has been closed.")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[INFO] Server started on port {PORT}.")
        while True:
            conn, addr = server_socket.accept()
            handle_client(conn, addr)

if __name__ == "__main__":
    start_server()
