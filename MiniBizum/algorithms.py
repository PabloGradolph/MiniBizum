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
    Cifra los datos utilizando una clave de cifrado.

    Args:
        data (str): Los datos a cifrar.
        key (str): La clave de cifrado en formato base64.

    Returns:
        bytes: Los datos cifrados en formato base64.
    """
    # Crea un objeto Fernet con la clave de cifrado.
    cipher_suite = Fernet(key)

    # Cifra los datos.
    encrypted_data = cipher_suite.encrypt(data.encode())

    # Convierte los datos cifrados a formato base64.
    return base64.b64encode(encrypted_data)


def decrypt_data(ciphertext: str, key: bytes) -> str:
    """
    Descifra los datos cifrados utilizando una clave de cifrado.

    Args:
        ciphertext (str): Los datos cifrados en formato base64.
        key (bytes): La clave de cifrado en bytes.

    Returns:
        str: Los datos descifrados como una cadena de caracteres.
    """
    # # Convierte el ciphertext de cadena de caracteres a bytes
    ciphertext_bytes = eval(ciphertext.encode())

    # Decodifica el ciphertext de base64 y conviértelo a bytes
    ciphertext_bytes = base64.b64decode(ciphertext_bytes)

    # Crea un objeto Fernet con la clave de cifrado.
    fernet = Fernet(key)

    # Descifra los datos y luego decodifica a una cadena de caracteres (UTF-8).
    plaintext = fernet.decrypt(ciphertext_bytes).decode("utf-8")
    return plaintext


def generate_key(password: str, salt: str = None) -> bytes:
    """
    Genera una clave de cifrado a partir de la contraseña del usuario y un salt aleatorio.

    Args:
        password (str): La contraseña del usuario en texto plano.
        salt (str, optional): Un salt aleatorio. Si no se proporciona, se generará uno.

    Returns:
        bytes: La clave de cifrado.
    """
    # Genera un salt aleatorio si no se proporciona uno
    if salt is None:
        salt = secrets.token_hex(16)

    # Utiliza el hash de la contraseña del usuario y el salt aleatorio para derivar una clave de cifrado
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
    Genera una ruta única para el archivo que almacena la clave de cifrado del usuario.

    Args:
        user_id (int): El ID del usuario para el que se genera la ruta.

    Returns:
        str: La ruta completa al archivo que contiene la clave de cifrado del usuario.
    """
    return os.path.join(KEYS_DIR, f'user_{user_id}_key.key')


def store_user_key(user_id: int, key: bytes, master_key: bytes):
    """
    Almacena la clave de cifrado en un lugar seguro, cifrando la clave con una clave maestra.

    Args:
        user_id: El ID del usuario.
        key: La clave de cifrado del usuario.
        master_key: La clave maestra para cifrar la clave de usuario.
    """

    # Genera una ruta única para la clave cifrada del usuario
    key_path = get_user_key_path(user_id)

    # Cifra la clave del usuario con la clave maestra antes de almacenarla
    cipher_suite = Fernet(master_key)
    encrypted_key = cipher_suite.encrypt(key)

    # Almacena la clave cifrada en el archivo
    with open(key_path, 'wb') as key_file:
        key_file.write(encrypted_key)


def load_user_key(user_id: int, master_key: bytes) -> bytes or None:
    """
    Carga la clave de cifrado del usuario desde su archivo y la descifra utilizando una clave maestra.

    Args:
        user_id (int): El ID del usuario cuya clave se va a cargar.
        master_key (bytes): La clave maestra utilizada para descifrar la clave del usuario.

    Returns:
        bytes or None: La clave de cifrado del usuario descifrada si se encuentra, o None si no se encuentra el archivo.
    """
    key_path = get_user_key_path(user_id)
    try:
        with open(key_path, 'rb') as key_file:
            encrypted_key = key_file.read()
        
        # Descifra la clave utilizando la clave maestra
        cipher_suite = Fernet(master_key)
        key = cipher_suite.decrypt(encrypted_key)
        
        return key
    except FileNotFoundError:
        return None