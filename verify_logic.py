import os
from utils import Encryptor, sanitize_filename

def test_sanitize():
    print("Testing sanitize_filename...")
    assert sanitize_filename("test/file:name") == "testfilename"
    assert sanitize_filename("valid_name") == "valid_name"
    print("sanitize_filename passed!")

def test_encryption():
    print("Testing Encryptor...")
    enc = Encryptor("test_secret.key")
    original = "my_secret_api_key"
    encrypted = enc.encrypt(original)
    decrypted = enc.decrypt(encrypted)
    assert original == decrypted
    assert enc.decrypt(b"invalid") == ""
    print("Encryptor passed!")

def test_imports():
    print("Testing imports...")
    try:
        from trello_client import TrelloClient
        from main import TrelloDownloaderApp
        print("Imports passed!")
    except ImportError as e:
        print(f"Import failed: {e}")

if __name__ == "__main__":
    test_sanitize()
    test_encryption()
    test_imports()
    print("All verification steps passed!")
