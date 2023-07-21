import tarfile
import gnupg
import os
import cv2
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import getpass
import base64 
import numpy as np
import csv
from io import StringIO

gpg = gnupg.GPG()
PASS_KEY = None

def encrypt_folder(foldername):
    for root, dirs, files in os.walk(foldername):
        for filename in files:
            filename_path = os.path.join(root, filename)
            with open(filename_path, "rb") as file:
                status = gpg.encrypt(file, passphrase='kamal', output=filename_path)

def decrypt_folder(foldername):
    output_folder = foldername.split('.')[0]
    os.makedirs(output_folder)
    with open(foldername, "rb") as file:
        decrypted_data = gpg.decrypt_file(file, output=output_folder)

    return encrypted_file, decrypted_folder

def get_cryptor():
    global PASS_KEY
    if not PASS_KEY:
        PASS_KEY = getpass.getpass("Enter your password: ")

    passphrase = bytes(PASS_KEY, 'utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    return Fernet(key)

def encrypt_file(file):
    cryptor = get_cryptor()

    with open(file, 'rb') as f:
        encrypted_data = cryptor.encrypt(f.read())

    with open(f"{file}.encrypted", 'wb') as f:
        f.write(encrypted_data)

    os.remove(file)

def decrypt_file(file, store_locally=False):
    cryptor = get_cryptor()

    with open(file, 'rb') as f:
        decrypted_data = cryptor.decrypt(f.read())

    real_file = file.replace('.encrypted', '')
    if store_locally:
        with open(real_file, 'wb') as f:
            f.write(decrypted_data)
        os.remove(file)

    if real_file.endswith('txt'):
        return decrypted_data.decode('utf-8')
    elif real_file.endswith(('jpg', 'png', 'jpeg')):
        arr = np.frombuffer(decrypted_data, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        return img
        # print(img.shape)
        # cv2.imshow('test', img)
        # cv2.waitKey(0)
    elif real_file.endswith('csv'):
        csv_file_string = StringIO(decrypted_data.decode())
        # csv_file = csv.reader(csv_file_string)
        # for row in csv_file:
        #     print(row)
        return csv_file_string

    return decrypted_data

def encrypt_folder(folder):
    for root, dirs, files in os.walk(folder):
        for filename in files:
            filename_path = os.path.join(root, filename)
            if not filename.endswith('encrypted'):
                encrypt_file(filename_path)

def decrypt_folder(folder):
    for root, dirs, files in os.walk(folder):
        for filename in files:
            filename_path = os.path.join(root, filename)
            decrypted_data = decrypt_file(filename_path)
            print(type(decrypted_data))

            


if __name__ == '__main__':
    # encrypt_folder('folder_to_encrypt')
    # encrypt_folder('./folder_to_encrypt')
    decrypt_folder('./folder_to_encrypt')
    