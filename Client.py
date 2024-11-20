import socket
from Crypto import aes_decrypt, keys, recompose_byte

# Constants
SERVER_HOST = '127.0.0.1'  # Server IP address
SERVER_PORT = 5555         # Port number for the TCP connection
BUFFER_SIZE = 2048         # Size of the buffer for receiving data

def decrypt_crumb(crumb_data):
    """
    Attempt to decrypt a crumb using all available keys.
    Returns the decrypted crumb's value if successful, otherwise None.
    """
    for crumb, key in keys.items():
        try:
            decrypted_message = aes_decrypt(crumb_data, key)
            if decrypted_message == "some string":  # Validation string
                return crumb  # Return the 2-bit crumb value
        except Exception:
            continue
    return None

def tcp_client():
    """
    Connects to the server, receives encrypted crumbs, decrypts them,
    and reconstructs the file.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            # Connect to the server
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            print(f"[INFO] Connected to {SERVER_HOST}:{SERVER_PORT}")

            # Get total number of crumbs
            total_crumbs_data = client_socket.recv(BUFFER_SIZE).decode('utf-8').strip()
            if not total_crumbs_data:
                raise ValueError("No data received for total crumbs.")
            total_crumbs = int(total_crumbs_data)
            print(f"[INFO] Total crumbs to decode: {total_crumbs}")

            # Initialize data structures
            crumbs = [None] * total_crumbs
            num_decoded = 0

            # Receive crumbs from the server
            while num_decoded < total_crumbs:
                encrypted_crumb = client_socket.recv(BUFFER_SIZE)
                if not encrypted_crumb:
                    print(f"[WARN] No crumb data received for index {num_decoded + 1}.")
                    break

                # Find the first undecoded crumb index
                crumb_index = crumbs.index(None)
                if crumb_index < 0:
                    continue  # All crumbs already decoded

                # Attempt to decrypt the crumb
                decrypted_value = decrypt_crumb(encrypted_crumb)
                if decrypted_value is not None:
                    crumbs[crumb_index] = decrypted_value
                    num_decoded += 1
                    print(f"[INFO] Crumb {crumb_index + 1}/{total_crumbs} decoded.")
                else:
                    print(f"[WARN] Failed to decrypt crumb at index {crumb_index}.")

                # Calculate progress and send it back to the server
                progress = (num_decoded / total_crumbs) * 100
                client_socket.sendall(f"{progress:.2f}".encode('utf-8'))

            # Reconstruct the file from crumbs
            print("[INFO] Reconstructing the file...")
            decoded_bytes = bytearray()
            for i in range(0, total_crumbs, 4):
                # Extract a group of four crumbs
                crumb_group = crumbs[i:i + 4]

                # Check for missing crumbs
                if any(c is None for c in crumb_group):
                    raise ValueError(f"Missing crumbs in group {i // 4}.")

                # Recompose and append to the byte array
                decoded_bytes.append(recompose_byte(crumb_group))

            # Save the file locally
            with open("reconstructed_file.bin", "wb") as output_file:
                output_file.write(decoded_bytes)
            print("[INFO] File reconstructed successfully.")

        except Exception as e:
            print(f"[ERROR] An error occurred: {e}")
        finally:
            print("[INFO] Connection closed.")

if __name__ == "__main__":
    tcp_client()
