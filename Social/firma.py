from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import ast

def generate_keys():
    # Generar un par de claves RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Obtener la clave pública
    public_key = private_key.public_key()

    # Serializar las claves en formato PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

def sign_transaction(private_key_pem, transaction_message, amount):
    # Cargar la clave privada desde su representación en bytes
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    # Firmar la transacción
    concat = f"{transaction_message}{amount}"
    message = bytes(concat, 'utf-8')
    print(message)
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature

def verify_signature(public_key_pem, signature, transaction_message, amount):
    # Deserialize the public key
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    
    # Verificar la transacción
    concat = f"{transaction_message}{amount}"
    message = bytes(concat, 'utf-8')

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def store_private_key(master_key, private_key, user_id):
    # Cifrar la clave privada con la clave maestra
    cipher_suite = Fernet(master_key)
    encrypted_private_key = cipher_suite.encrypt(private_key)

    # Guardar la clave privada cifrada en el directorio /keys
    with open(f'./keys/user_{user_id}_private_key.pem', 'wb') as file:
        file.write(encrypted_private_key)

def decrypt_private_key(master_key, encrypted_private_key):
    # Desencriptar la clave privada con la clave maestra
    cipher_suite = Fernet(master_key)
    private_key_pem = cipher_suite.decrypt(encrypted_private_key)

    # Deserializar la clave privada
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )

    return private_key