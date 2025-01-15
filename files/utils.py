from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from django.conf import settings
import os

SECRET_KEY = settings.SECRET_KEY[:32]  # Use a secure 32-byte key

def encrypt_file(file_content):
    cipher = AES.new(SECRET_KEY.encode('utf-8'), AES.MODE_CBC)
    iv = cipher.iv
    encrypted_content = cipher.encrypt(pad(file_content, AES.block_size))
    return iv + encrypted_content

def decrypt_file(encrypted_content):
    iv = encrypted_content[:16]
    encrypted_data = encrypted_content[16:]
    cipher = AES.new(SECRET_KEY.encode('utf-8'), AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_data), AES.block_size)


def save_file(file, filename):
    directory = "encrypted_files"
    # Create the directory if it doesn't exist
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    file_path = os.path.join(directory, filename)
    with open(file_path, "wb") as f:
        for chunk in file.chunks():  # Use chunks for large files
            f.write(chunk)
    return file_path