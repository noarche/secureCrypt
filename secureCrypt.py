import os
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

# Encrypt a file
def encrypt_file(file_path: str, password: str) -> bool:
    try:
        # Read the file to encrypt
        with open(file_path, 'rb') as f:
            data = f.read()

        # Generate a random salt and IV
        salt = get_random_bytes(SALT_SIZE)
        iv = get_random_bytes(IV_SIZE)

        # Derive the key using PBKDF2
        key = derive_key(password, salt)

        # Create AES cipher in CFB mode
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)

        # Pad data and encrypt
        encrypted_data = cipher.encrypt(pad(data, BLOCK_SIZE))

        # Save the encrypted file
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as enc_file:
            enc_file.write(salt + iv + encrypted_data)

        # Delete the original file
        os.remove(file_path)
        print(Fore.GREEN + f"Successfully encrypted: {file_path}")
        return True
    except Exception as e:
        print(Fore.RED + f"Failed to encrypt {file_path}: {e}")
        return False

# Decrypt a file
def decrypt_file(file_path: str, password: str) -> bool:
    try:
        # Read the encrypted file
        with open(file_path, 'rb') as f:
            enc_data = f.read()

        # Extract salt, IV, and encrypted data
        salt = enc_data[:SALT_SIZE]
        iv = enc_data[SALT_SIZE:SALT_SIZE + IV_SIZE]
        encrypted_data = enc_data[SALT_SIZE + IV_SIZE:]

        # Derive the key using PBKDF2
        key = derive_key(password, salt)

        # Create AES cipher in CFB mode
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)

        # Decrypt and unpad data
        decrypted_data = unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE)

        # Save the decrypted file
        decrypted_file_path = file_path[:-4]  # Remove '.enc' from the file name
        with open(decrypted_file_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)

        # Delete the encrypted file
        os.remove(file_path)
        print(Fore.GREEN + f"Successfully decrypted: {file_path}")
        return True
    except Exception as e:
        print(Fore.RED + f"Failed to decrypt {file_path}: {e}")
        return False

# Main function to interact with the user
def main():
    # Prompt for directory and action
    directory = input(Fore.CYAN + "Enter the directory path: ")
    action = input(Fore.YELLOW + "Encrypt or Decrypt? [e/d]: ").lower()

    # Prompt for password
    password = getpass(Fore.MAGENTA + "Enter password: ")

    # Process files in the directory
    if action == 'e':
        print(Fore.CYAN + f"Encrypting files in: {directory}")
        files_changed = 0
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if not file.endswith('.enc'):  # Skip already encrypted files
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
