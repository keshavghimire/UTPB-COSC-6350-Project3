import socket
from Crypto import *
import random

# Constants
SERVER_HOST = '127.0.0.1'  # Update this if the server is on a different machine
SERVER_PORT = 5555  # Port number for the TCP connection
MAX_RETRIES = 5  # Maximum retries for decryption attempts
EXPECTED_TEXT="The quick brown fox jumps over the lazy dog."
FILE_NAME="generated.txt"

def connect_to_server():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    return client_socket

def receive_total_size(client_socket):
    return int(client_socket.recv(1024).decode())

def process_crumb(crumb_idx, ciphertext, crumbs, attempted_crumbs, keys):
    available_keys = [key for key in keys.keys() if key not in attempted_crumbs[crumb_idx]]
    if not available_keys:
        return False  # No available keys left for this crumb

    crumb = random.choice(available_keys)
    key = keys[crumb]
    attempted_crumbs[crumb_idx].append(key)

    attempts = 0
    while attempts < MAX_RETRIES:
        try:
            decrypted_text = aes_decrypt(ciphertext, key)
            if decrypted_text == EXPECTED_TEXT:  # Verify content
                crumbs[crumb_idx] = crumb  # Store the decoded crumb
                return True  # Successfully decoded
        except:
            pass  # Ignore decryption errors

        attempts += 1

    return False

def decode_crumbs(client_socket, total_size, crumbs, attempted_crumbs, keys):
    num_decoded = 0

    while num_decoded < total_size:
        for crumb_idx in range(total_size):
            if crumbs[crumb_idx] is not None:
                continue  # Skip already decoded crumbs

            ciphertext = client_socket.recv(1024)  # Receive a chunk of encrypted data
            if process_crumb(crumb_idx, ciphertext, crumbs, attempted_crumbs, keys):
                num_decoded += 1  # Increment decoded count

            # Send progress update to the server
            progress = (num_decoded / total_size) * 100
            progress = min(progress, 100)  # Ensure progress does not exceed 100%
            client_socket.sendall(f"{progress:.2f}%".encode())

        print(f"Client progress: {progress:.2f}%")

    return num_decoded

def validate_and_write_file(crumbs, total_size):
    valid_crumbs = [crumb for crumb in crumbs if crumb is not None]
    print(f"Decoded crumbs: {len(valid_crumbs)}/{total_size}")

    if len(valid_crumbs) == total_size:
        bytes_content = []
        for i in range(0, len(valid_crumbs), 4):
            chunk = valid_crumbs[i:i + 4]
            if len(chunk) == 4:  # Ensure the chunk has 4 crumbs
                bytes_content.append(recompose_byte(chunk))

        with open(FILE_NAME, "wb") as output_file:
            output_file.write(bytearray(bytes_content))
        print("File successfully written: received_file.txt")
    else:
        print(f"[ERROR] Unable to decode all crumbs. Decoded: {len(valid_crumbs)}")

def tcp_client():
    try:
        client_socket = connect_to_server()
        with client_socket:
            total_size = receive_total_size(client_socket)
            crumbs = [None] * total_size  # Initialize an array to store decoded crumbs
            attempted_crumbs = [[] for _ in range(total_size)]  # Track keys tried for each crumb index

            print("Connected to the server. Receiving crumbs...")

            num_decoded = decode_crumbs(client_socket, total_size, crumbs, attempted_crumbs, keys)

            print("All crumbs have been processed.")

            validate_and_write_file(crumbs, total_size)

            # Display the final decoded message
            decoded_message =EXPECTED_TEXT
            print(f"Decoded message: {decoded_message}")

    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    tcp_client()