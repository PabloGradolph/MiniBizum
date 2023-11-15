from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, RSAPrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import ast

def generate_keys() -> (bytes, bytes):
    """
    Generate a pair of RSA keys.

    Returns:
        Tuple[bytes, bytes]: A tuple containing the private and public keys in PEM format.
    """

    # Generate a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Obtain the corresponding public key
    public_key = private_key.public_key()

    # Serialize the keys in PEM format
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


def sign_transaction(private_key: RSAPrivateKey, transaction_message: str, amount: float) -> bytes:
    """
    Sign a transaction using the provided private key.

    Args:
        private_key (RSAPrivateKey): The RSA private key for signing the transaction.
        transaction_message (str): The transaction message.
        amount (int/float): The transaction amount.

    Returns:
        bytes: The digital signature of the transaction.
    """
    # Concatenate the transaction message with the amount
    concat = f"{transaction_message}{amount}"
    message = bytes(concat, 'utf-8')
    
    # Sign the transaction
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def verify_signature(public_key_pem: bytes, signature: bytes, transaction_message: str, amount: float) -> bool:
    """
    Verify a signature for a given transaction message and amount using a public key.

    Args:
        public_key_pem (bytes): The PEM encoded public key.
        signature (bytes): The signature to verify.
        transaction_message (str): The transaction message.
        amount (float): The transaction amount.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    # Deserialize the public key
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    
    # Concatenate the transaction message with the amount
    concat = f"{transaction_message}{amount}"
    message = bytes(concat, 'utf-8')

    try:
        # Verify the transaction
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


def store_private_key(master_key: bytes, private_key: bytes, user_id: int) -> None:
    """
    Encrypt and store a private key using a master key.

    Args:
        master_key (bytes): The master key used for encryption.
        private_key (bytes): The private key to be encrypted and stored.
        user_id (int): The user identifier for whom the key is stored.

    Returns:
        None
    """
    # Encrypt the private key with the master key
    cipher_suite = Fernet(master_key)
    encrypted_private_key = cipher_suite.encrypt(private_key)

    # Save the encrypted private key in the /keys directory
    with open(f'./keys/user_{user_id}_private_key.pem', 'wb') as file:
        file.write(encrypted_private_key)


def get_user_key_path(user_id: int) -> str:
    """
    Generate a unique path for the file storing the user's encryption key.

    Args:
        user_id (int): The user ID for which the path is generated.

    Returns:
        str: The full path to the file containing the user's encryption key.
    """
    return f'./keys/user_{user_id}_private_key.pem'


def decrypt_private_key(master_key: bytes, encrypted_private_key_path: str) -> RSAPrivateKey:
    """
    Decrypt a private key using a master key.

    Args:
        master_key (bytes): The master key used for decryption.
        encrypted_private_key_path (str): The file path to the encrypted private key.

    Returns:
        RSAPrivateKey: The decrypted RSA private key.
    """
    # Decrypt the private key with the master key
    with open(encrypted_private_key_path, 'rb') as file:
        encrypted_private_key = file.read()
    
    cipher_suite = Fernet(master_key)
    private_key_pem = cipher_suite.decrypt(encrypted_private_key)

    # Deserialize the private key
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend(),
    )

    return private_key