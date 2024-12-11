import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from Crypto import keys

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555
BUFFER_SIZE = 2048



def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    print(f"[DEBUG] Decrypting: IV={iv.hex()}, Ciphertext={actual_ciphertext.hex()}, Result={unpadded_data.decode()}")
    return unpadded_data.decode()

class Client:
    def __init__(self):
        self.decrypted_crumbs = {}  # Successfully decrypted crumbs
        self.attempted_keys = {}    # Keys attempted for each index

    def run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((SERVER_HOST, SERVER_PORT))
                print("[INFO] Connected to server.")

                total_crumbs = 0
                while True:
                    data = client_socket.recv(BUFFER_SIZE).decode('utf-8').strip()
                    if not data:
                        break

                    print(f"[DEBUG] Received data: {data}")
                    if data.isdigit():
                        total_crumbs = int(data)
                        print(f"[INFO] Total crumbs to handle: {total_crumbs}")
                        continue

                    if "|" in data:
                        index, encrypted_crumb_hex = data.split("|")
                        index = int(index)
                        encrypted_crumb = bytes.fromhex(encrypted_crumb_hex)

                        if index in self.decrypted_crumbs:
                            client_socket.sendall(str(index).encode('utf-8'))
                            continue

                        if index not in self.attempted_keys:
                            self.attempted_keys[index] = set()

                        print(f"[DEBUG] Attempting to decrypt index {index}.")

                        for key in keys.values():
                            if key in self.attempted_keys[index]:
                                continue

                            self.attempted_keys[index].add(key)
                            try:
                                decrypted_message = aes_decrypt(encrypted_crumb, key)
                                print(f"[DEBUG] Decrypting with key={key.hex()}, Result={decrypted_message}")

                                if decrypted_message == str(index):
                                    print(f"[INFO] Successfully decrypted crumb index {index}.")
                                    self.decrypted_crumbs[index] = key
                                    client_socket.sendall(str(index).encode('utf-8'))
                                    break
                            except Exception as e:
                                print(f"[ERROR] Failed to decrypt index {index}: {e}")

        except Exception as e:
            print(f"[ERROR] Client encountered an exception: {e}")

if __name__ == "__main__":
    client = Client()
    client.run()
