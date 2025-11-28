import os
import re
from cryptography.fernet import Fernet

def sanitize_filename(name):
    # Replace separators with underscores
    name = name.replace('|', '_')
    # Remove invalid characters
    name = re.sub(r'[<>:"/\\?*]', '', name)
    # Limit length to avoid issues
    return name.strip().rstrip('.')[:200]

class Encryptor:
    def __init__(self, key_file="secret.key"):
        self.key_file = key_file
        self.key = self.load_or_create_key()
        self.cipher_suite = Fernet(self.key)

    def load_or_create_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(key)
            return key

    def encrypt(self, data):
        if not data:
            return b""
        return self.cipher_suite.encrypt(data.encode())

    def decrypt(self, data):
        if not data:
            return ""
        try:
            return self.cipher_suite.decrypt(data).decode()
        except Exception:
            return ""

def download_file(url, path, params=None, headers=None):
    import requests
    try:
        response = requests.get(url, params=params, headers=headers, stream=True)
        if response.status_code == 200:
            with open(path, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            return True, "Success"
        else:
            return False, f"Status {response.status_code}"
    except Exception as e:
        return False, str(e)
