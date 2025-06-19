from cryptography.fernet import Fernet, InvalidToken
import sys
import os

def find_folder_path(folder_name, search_path="C:\\"):
    try:
        for root, dirs, _ in os.walk(search_path):
            if folder_name in dirs:
                return os.path.join(root, folder_name)
    except (PermissionError, OSError):
        pass
    return None

def get_files(folder_path):
    file_list = []
    try:
        for root, _, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                file_list.append(file_path)
    except (PermissionError, OSError):
        pass 
    return file_list

def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_path: str, key: bytes):
    fernet = Fernet(key)

    try:
        with open(file_path, 'rb') as file:
            original_data = file.read()

        encrypted_data = fernet.encrypt(original_data)

        with open(file_path, 'wb') as file:
            file.write(encrypted_data)

    except (OSError, ValueError):
        sys.exit(1)

def decrypt_file(file_path: str, key: bytes):
    try:
        fernet = Fernet(key)

        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        with open(file_path, 'wb') as file:
            file.write(decrypted_data)

        return True

    except (InvalidToken, ValueError, OSError) as e:
        return False