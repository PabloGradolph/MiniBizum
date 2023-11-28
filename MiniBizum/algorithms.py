import secrets
import os
import base64
import hashlib
from pathlib import Path
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.contrib.auth.models import User
from Social.models import Profile


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


def generate_dh_keys() -> (DHPrivateKey, DHPublicKey):
    """
    Generates a pair of Diffie-Hellman (DH) keys - private and public.

    This method creates a new set of DH parameters and then generates a key pair
    based on these parameters. The key pair consists of a private key and a corresponding 
    public key. These keys can be used for secure key exchange in cryptographic communication.

    Returns:
        DHPrivateKey: The generated private key for DH key exchange.
        DHPublicKey: The corresponding public key for DH key exchange.

    The keys are generated with a size of 2048 bits, offering a good balance between 
    security and performance. The generator value is set to 2, which is a common choice 
    for DH key generation.
    """
    # Parameters: p -> large prime number of 2048 bits. g -> generator.
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2

    params_numbers = dh.DHParameterNumbers(p,g)
    parameters = params_numbers.parameters(default_backend())
    dh_private_key = parameters.generate_private_key()
    dh_public_key = dh_private_key.public_key()
    return dh_private_key, dh_public_key


def encrypt_private_key(private_key_pem: bytes, password: str, salt: str) -> bytes:
    """
    Encrypts a PEM formatted private key using a password and a salt.

    This method derives a cryptographic key from the provided password and salt,
    and then uses this key to encrypt the provided private key.

    Args:
        private_key_pem (bytes): The PEM formatted private key to be encrypted.
        password (str): The password used for generating the encryption key.
        salt (str): The salt used in conjunction with the password to generate the encryption key.

    Returns:
        bytes: The encrypted private key.
    """
    # Derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt.encode()),
        iterations=1000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # Encrypt the private key
    f = Fernet(key)
    encrypted_private_key = f.encrypt(private_key_pem)
    return encrypted_private_key



def store_user_keys(user, private_key: DHPrivateKey, public_key: DHPublicKey, password: str, salt: str) -> None:
    """
    Stores a user's private and public keys in a profile, encrypting the private key.

    This method takes a user's private and public keys, along with a password and salt,
    and stores the keys in the user's profile. The private key is encrypted before storage
    for security purposes.

    Args:
        user: The user object to which these keys belong.
        private_key (serialization.PrivateKey): The user's private key.
        public_key (serialization.PublicKey): The user's public key.
        password (str): The password used for encrypting the private key.
        salt (str): The salt used in conjunction with the password for encryption.

    Returns:
        None
    """

    # Convert private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Convert public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Encrypt the private key
    encrypted_private_key = encrypt_private_key(private_key_pem, password, salt)

    # Retrieve and update user profile with keys
    user_profile = Profile.objects.get(user=user)
    user_profile.dh_public_key = public_key_pem
    user_profile.encrypted_dh_private_key = encrypted_private_key
    user_profile.save()



def retrieve_private_key(user: User, password: str) -> DHPrivateKey:
    """
    Retrieves and decrypts a user's encrypted private key using their password.

    This method derives a cryptographic key from the user's password and uses it
    to decrypt the user's stored private key. The method assumes that the user's
    password is stored in a specific format (algorithm$hash$salt).

    Args:
        user: The user object from whom the private key is to be retrieved.
        password (str): The password for decrypting the private key.

    Returns:
        serialization.PrivateKey: The decrypted private key.
    """

    # Retrieve the algorithm, hash, and salt from the stored user password
    algorithm, hash, stored_salt = user.password.split('$', 2)

    # Convert the stored salt to bytes
    salt = bytes(stored_salt.encode())

    # Derive a key for Fernet using the password and salt
    key = base64.urlsafe_b64encode(PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000,
        backend=default_backend()
    ).derive(password.encode()))

    f = Fernet(key)
    user_profile = Profile.objects.get(user=user)
    encrypted_private_key = user_profile.encrypted_dh_private_key
    private_key_pem = f.decrypt(encrypted_private_key)

    # Load the private key from PEM format
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    return private_key


def retrieve_public_dh_key(user: User) -> DHPublicKey:
    """
    Retrieves a user's public Diffie-Hellman (DH) key.

    This method extracts the user's public DH key, which is stored in PEM format
    in the user's profile, and converts it into a PublicKey object.

    Args:
        user (User): The user object from whom the public DH key is to be retrieved.

    Returns:
        serialization.PublicKey: The user's public DH key.
    """

    # Retrieve the public key in PEM format from the user's profile
    recipient_public_key_pem = user.profile.dh_public_key

    # Load the public key from PEM format
    recipient_public_key = serialization.load_pem_public_key(
        recipient_public_key_pem,
        backend=default_backend()
    )

    return recipient_public_key


def get_shared_key(dh_private_key: DHPrivateKey, sender_public_key: DHPublicKey) -> bytes:
    """
    Generates a shared key using Diffie-Hellman key exchange.

    This method uses a private Diffie-Hellman key and a sender's public key to
    generate a shared secret key. This key is then processed using HKDF to derive
    a final shared key, which is encoded in base64.

    Args:
        dh_private_key (DHPrivateKey): The private DH key for generating the shared key.
        sender_public_key (DHPublicKey): The sender's public DH key.

    Returns:
        bytes: The derived and base64-encoded shared key.
    """

    # Perform Diffie-Hellman key exchange to get shared key
    shared_key = dh_private_key.exchange(sender_public_key)

    # Derive a final shared key using HKDF
    shared_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend()
    ).derive(shared_key)

    # Encode the shared key in base64
    shared_key = base64.urlsafe_b64encode(shared_key)
    return shared_key