import secrets
import os
import base64
import hashlib
from pathlib import Path
import os
from cryptography.fernet import Fernet


BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = os.path.join(BASE_DIR, 'keys')


def encrypt_data(data: str, key: bytes) -> bytes:
    """
    Encrypts data using an encryption key.

    Args:
        data (str): The data to encrypt.
        key (bytes): The encryption key in bytes format.

    Returns:
        bytes: The encrypted data in base64 format.
    """
    # Create a Fernet object with the encryption key.
    cipher_suite = Fernet(key)

    # Encrypt the data.
    encrypted_data = cipher_suite.encrypt(data.encode())

    # Convert the encrypted data to base64 format.
    return base64.b64encode(encrypted_data)


def decrypt_data(ciphertext: str, key: bytes) -> str:
    """
    Decrypts the encrypted data using an encryption key.

    Args:
        ciphertext (str): The encrypted data in base64 format.
        key (bytes): The encryption key in bytes format.

    Returns:
        str: The decrypted data as a string.
    """
    # Convert the ciphertext from string to bytes
    ciphertext_bytes = eval(ciphertext.encode())

    # Decode the ciphertext from base64 and convert it to bytes
    ciphertext_bytes = base64.b64decode(ciphertext_bytes)

    # Create a Fernet object with the encryption key.
    fernet = Fernet(key)

   # Decrypt the data and then decode to a string (UTF-8).
    plaintext = fernet.decrypt(ciphertext_bytes).decode("utf-8")
    return plaintext


def generate_key(password: str, salt: str = None) -> bytes:
    """
    Generates an encryption key from a user's password and a random salt.

    Args:
        password (str): The user's plaintext password.
        salt (str, optional): A random salt. If not provided, one will be generated.

    Returns:
        bytes: The encryption key.
    """
    # Generate a random salt if one is not provided
    if salt is None:
        salt = secrets.token_hex(16)

    # Use the hash of the user's password and the random salt to derive an encryption key
    hashed_password = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        dklen=32,
        password=password.encode(),
        salt=salt.encode(),
        iterations=100000,
    )

    return base64.urlsafe_b64encode(hashed_password)


def get_user_key_path(user_id: int) -> str:
    """
    Generates a unique path for the file storing the user's encryption key.

    Args:
        user_id (int): The user's ID for whom the path is generated.

    Returns:
        str: The full path to the file containing the user's encryption key.
    """
    return os.path.join(KEYS_DIR, f'user_{user_id}_key.key')


def store_user_key(user_id: int, key: bytes, master_key: bytes) -> None:
    """
    Stores the encryption key in a secure location, encrypting the key with a master key.

    Args:
        user_id (int): The user's ID.
        key (bytes): The user's encryption key.
        master_key (bytes): The master key to encrypt the user's key.
    """
    # Generate a unique path for the user's encrypted key
    key_path = get_user_key_path(user_id)

    # Encrypt the user's key with the master key before storing it
    cipher_suite = Fernet(master_key)
    encrypted_key = cipher_suite.encrypt(key)

    # Store the encrypted key in the file
    with open(key_path, 'wb') as key_file:
        key_file.write(encrypted_key)


def load_user_key(user_id: int, master_key: bytes) -> bytes or None:
    """
    Loads the user's encryption key from its file and decrypts it using a master key.

    Args:
        user_id (int): The user's ID whose key is to be loaded.
        master_key (bytes): The master key used to decrypt the user's key.

    Returns:
        bytes or None: The decrypted user's encryption key if found, or None if the file is not found.
    """
    key_path = get_user_key_path(user_id)
    try:
        with open(key_path, 'rb') as key_file:
            encrypted_key = key_file.read()
        
        # Decrypt the key using the master key
        cipher_suite = Fernet(master_key)
        key = cipher_suite.decrypt(encrypted_key)
        
        return key
    except FileNotFoundError:
        return None