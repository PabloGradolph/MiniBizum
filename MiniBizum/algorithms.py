import secrets
import os
import base64
import hashlib

import cryptography.fernet
from cryptography.fernet import Fernet


def encrypt_data(data: str, key) -> bytes:
    # Abre el archivo en modo lectura y lee su contenido
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return base64.b64encode(encrypted_data)


def decrypt_data(ciphertext, key):
    """
    Descifra los datos del usuario.

    Args:
        ciphertext: Los datos cifrados a descifrar.
        key: La clave de cifrado.

    Returns:
        Los datos descifrados.
    """

    # Crea un objeto Fernet con la clave de cifrado.
    fernet = cryptography.fernet.Fernet(key.encode())

    # Descifra los datos.
    plaintext = fernet.decrypt(base64.b64decode(ciphertext))
    return plaintext


def generate_key(password, salt):
    """
    Genera una clave de cifrado a partir de la contraseña del usuario y un salt aleatorio.

    Args:
        password: La contraseña del usuario en texto plano.
        salt: Un salt aleatorio.

    Returns:
        La clave de cifrado.
    """

    # Genera un salt aleatorio.
    if salt is None:
        salt = secrets.token_hex(16)

    # Utiliza el hash de la contraseña del usuario y el salt aleatorio para derivar una clave de cifrado.
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    derived_key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        dklen=32,
        password=hashed_password.encode(),
        salt=salt.encode(),
        iterations=100000,
    )

    return derived_key.hex()


def store_key(key):
    """
    Almacena la clave de cifrado en un lugar seguro.

    Args:
        key: La clave de cifrado.
    """

    # Almacena la clave de cifrado en un lugar seguro, como un servidor remoto o un dispositivo de almacenamiento
    # externo.
    # Por ejemplo, podrías almacenarla en un archivo encriptado o en una base de datos segura.

    print("La clave de cifrado se ha almacenado de forma segura.")
