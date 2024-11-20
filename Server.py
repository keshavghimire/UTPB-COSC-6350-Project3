import socket
from concurrent.futures import ThreadPoolExecutor
from Crypto import aes_encrypt, keys, decompose_byte

# Constants
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 5555       # Port number
TIMEOUT = 600     # 10 minutes (in seconds)
MAX_THREADS = 10  # Maximum number of threads in the pool

# Function to handle client connection
def handle_client(conn, addr):
    conn.settimeout(TIMEOUT)
    print(f"[INFO] Connection from {addr} established.")
    try:
        file_size = 0
        crumbs = []

        # Read and process the file
        with open("risk.bmp", "rb") as dat_file:
            dat_file.seek(0, 2)  # Move to end of file to get size
            file_size = dat_file.tell()
            dat_file.seek(0)  # Reset pointer to start of file

            # Decompose the file into crumbs (2 bits each)
            for byte in dat_file.read():
                crumbs.extend(decompose_byte(byte))

        total_crumbs = len(crumbs)
        print(f"[INFO] Total crumbs to send: {total_crumbs}")

        # Send total crumbs to the client
        conn.sendall(str(total_crumbs).encode('utf-8'))

        # Transmit encrypted crumbs to the client
        for crumb_index, crumb in enumerate(crumbs):
            key = keys[crumb]
            encrypted_crumb = aes_encrypt("some string", key)
            conn.sendall(encrypted_crumb)

            # Await client progress feedback
            progress_data = conn.recv(1024).decode('utf-8').strip()
            if progress_data:
                print(f"[INFO] Client progress: {progress_data}%")

        print("[INFO] File transmission complete.")
    except socket.timeout:
        print(f"[INFO] Connection from {addr} timed out.")
    except Exception as e:
        print(f"[ERROR] Error handling client {addr}: {e}")
    finally:
        # Close the connection
        try:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
        except Exception as e:
            print(f"[ERROR] Error closing connection from {addr}: {e}")
        print(f"[INFO] Connection from {addr} has been closed.")

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
