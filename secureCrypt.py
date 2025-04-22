import os
import random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from getpass import getpass
from colorama import Fore

# AES Encryption Constants
KEY_LENGTH = 32  # 256 bits
SALT_SIZE = 16   # 128 bits
IV_SIZE = 16     # AES block size
BLOCK_SIZE = 16  # AES block size
PBKDF2_ITERATIONS = 100_000

# Function to derive AES key from password
def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS)

# Securely delete a file by overwriting with random data
def secure_delete(file_path: str):
    try:
        if os.path.isfile(file_path):
            length = os.path.getsize(file_path)
            with open(file_path, "ba+", buffering=0) as f:
                f.seek(0)
                f.write(os.urandom(length))
            os.remove(file_path)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to securely delete {file_path}: {e}")

# Encrypt a file
def encrypt_file(file_path: str, password: str) -> bool:
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        salt = get_random_bytes(SALT_SIZE)
        iv = get_random_bytes(IV_SIZE)
        key = derive_key(password, salt)

        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        encrypted_data = cipher.encrypt(pad(data, BLOCK_SIZE))

        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as enc_file:
            enc_file.write(salt + iv + encrypted_data)

        secure_delete(file_path)
        print(Fore.GREEN + f"Successfully encrypted: {file_path}")
        return True
    except Exception as e:
        print(Fore.RED + f"Failed to encrypt {file_path}: {e}")
        return False

# Decrypt a file
def decrypt_file(file_path: str, password: str) -> bool:
    try:
        with open(file_path, 'rb') as f:
            enc_data = f.read()

        salt = enc_data[:SALT_SIZE]
        iv = enc_data[SALT_SIZE:SALT_SIZE + IV_SIZE]
        encrypted_data = enc_data[SALT_SIZE + IV_SIZE:]

        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE)

        decrypted_file_path = file_path[:-4]
        with open(decrypted_file_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)

        secure_delete(file_path)
        print(Fore.GREEN + f"Successfully decrypted: {file_path}")
        return True
    except Exception as e:
        print(Fore.RED + f"Failed to decrypt {file_path}: {e}")
        return False

# Main function (unchanged)
def main():
    directory = input(Fore.CYAN + "Enter the directory path: ")
    action = input(Fore.YELLOW + "Encrypt or Decrypt? [e/d]: ").lower()
    password = getpass(Fore.MAGENTA + "Enter password: ")

    if action == 'e':
        print(Fore.CYAN + f"Encrypting files in: {directory}")
        files_changed = 0
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if not file.endswith('.enc'):
                    if encrypt_file(file_path, password):
                        files_changed += 1
        print(Fore.GREEN + f"Encryption completed. {files_changed} files changed.")
    elif action == 'd':
        print(Fore.CYAN + f"Decrypting files in: {directory}")
        files_changed = 0
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.enc'):
                    file_path = os.path.join(root, file)
                    if decrypt_file(file_path, password):
                        files_changed += 1
        print(Fore.GREEN + f"Decryption completed. {files_changed} files changed.")
    else:
        print(Fore.RED + "Invalid option. Please choose 'e' to encrypt or 'd' to decrypt.")

if __name__ == "__main__":
    main()
