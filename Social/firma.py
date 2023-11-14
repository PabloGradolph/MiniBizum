from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet

def generate_keys():
    # Generar una clave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generar una clave pública
    public_key = private_key.public_key()

    return private_key, public_key

def sign_transaction(private_key, transaction_message, amount):
    # Firmar la transacción
    message = f"{transaction_message}{amount}"
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

def verify_signature(public_key, signature, transaction_message, amount):
    # Verificar la transacción
    message = f"{transaction_message}{amount}"
    try:
        public_key.verify(
            signature,
            message.encode(),
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
    # Serializar la clave privada
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Cifrar la clave privada con la clave maestra
    cipher_suite = Fernet(master_key)
    encrypted_private_key = cipher_suite.encrypt(private_key_bytes)

    # Guardar la clave privada cifrada en el directorio /keys
    with open(f'/keys/{user_id}_private_key.pem', 'wb') as file:
        file.write(encrypted_private_key)

def decrypt_private_key(master_key, encrypted_private_key):
    # Desencriptar la clave privada con la clave maestra
    cipher_suite = Fernet(master_key)
    private_key_bytes = cipher_suite.decrypt(encrypted_private_key)

    # Deserializar la clave privada
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
    )

    return private_key