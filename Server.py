import socket
from concurrent.futures import ThreadPoolExecutor
from Crypto import *
import os
import time

# Constants
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 5555  # Port number
TIMEOUT = 600  # 10 minutes (in seconds)
MAX_THREADS = 10  # Maximum number of threads in the pool
CIPHER_TEXT = "The quick brown fox jumps over the lazy dog."

# Function to handle client connection
def handle_client(conn, addr):
    conn.settimeout(TIMEOUT)
    print(f"[INFO] Connection from {addr} established.")

    try:
        with open("input.txt", "rb") as dat_file:
            file_size = os.path.getsize("input.txt")
            conn.sendall(str(file_size * 4).encode())  # Send total file size in crumbs

            crumbs = [crumb for byte in dat_file.read() for crumb in decompose_byte(byte)]

        while True:
            for crumb in crumbs:
                key = keys[crumb]
                ciphertext = aes_encrypt(CIPHER_TEXT, key)
                conn.sendall(ciphertext)

                # Await client status update
                status = conn.recv(1024).decode()
                if status == "100%":
                    print(f"[INFO] {addr} has completed file transfer.")
                    return

            print(f"[INFO] Resending crumbs for {addr}.")
            time.sleep(1)

    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        conn.close()

# Main server function
def start_server():
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((HOST, PORT))
            server_socket.listen()
            print(f"[INFO] Server started, listening on {PORT}...")

            while True:
                conn, addr = server_socket.accept()
                print(f"[INFO] Accepted connection from {addr}.")
                # Spawn a thread from the pool to handle the connection
                executor.submit(handle_client, conn, addr)

if __name__ == "__main__":
    start_server()
