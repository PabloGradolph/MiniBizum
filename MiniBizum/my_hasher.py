from django.contrib.auth.hashers import BasePasswordHasher
from django.utils.crypto import constant_time_compare
import hashlib
import secrets


class MyPasswordHasher(BasePasswordHasher):
    """
    A custom password hasher that uses SHA-256 and a unique salt.
    This hasher provides methods for password encoding, verification, and providing a safe summary.
    """
    algorithm = "custom_sha256"

    def salt(self):
        """
        Generates a random salt.

        Returns:
            str: A randomly generated salt.
        """
        return secrets.token_hex(16)

    def encode(self, password: str, salt: str) -> str:
        """
        Encodes the plaintext password with the given salt, returning the hashed password.

        Args:
            password (str): The plaintext password to hash.
            salt (str): The salt to use in the hashing process.

        Returns:
            str: The hashed password in the format expected by Django.
        """
        salt = self.salt()
        salted_password = password + salt
        hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
        return f"{self.algorithm}${hashed_password}${salt}", salt

    def verify(self, password: str, encoded: str) -> bool:
        """
        Checks if the provided plaintext password matches the stored hashed password.

        Args:
            password (str): The plaintext password to verify.
            encoded (str): The stored hashed password.

        Returns:
            bool: True if the password matches, False otherwise.
        """
        algorithm, hashed_password, salt = encoded.split('$', 2)
        assert algorithm == self.algorithm

        salted_password = password + salt
        calculated_hash = hashlib.sha256(salted_password.encode()).hexdigest()

        # Compare in constant time to prevent timing attacks
        return constant_time_compare(calculated_hash, hashed_password)

    def safe_summary(self, encoded: str) -> dict:
        """
        Provides a non-sensitive summary of the stored password.

        Args:
            encoded (str): The encoded password.

        Returns:
            dict: A dictionary containing algorithm, hash, and salt.
        """
        algorithm, hash, salt = encoded.split('$', 2)
        return {
            'algorithm': algorithm,
            'hash': hash,
            'salt': salt,
        }
