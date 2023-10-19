import secrets
import os
import base64
import hashlib
from cryptography.fernet import Fernet

def encrypt_data(data: str) -> bytes:
    # Abre el archivo en modo lectura y lee su contenido
    with open('MiniBizum/project_key.txt', 'rb') as archivo:
        key = archivo.read()
    
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data
