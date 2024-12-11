from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Corrected keys to be bytes-like
keys = {
    0b00: bytes.fromhex("d7ffe8f10f124c56918a614acfc65814"),
    0b01: bytes.fromhex("5526736ddd6c4a0592ed33cbc5b1b76d"),
    0b10: bytes.fromhex("88863eef1a37427ea0b867227f09a7c1"),
    0b11: bytes.fromhex("45355f125db4449eb07415e8df5e27d4")
}
