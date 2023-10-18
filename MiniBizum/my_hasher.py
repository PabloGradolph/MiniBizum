from django.contrib.auth.hashers import BasePasswordHasher
from django.utils.crypto import constant_time_compare
import hashlib
import secrets

class MyPasswordHasher(BasePasswordHasher):
    """
    Hasher de contraseñas personalizado que utiliza SHA-256 y un salt único.
    """
    algorithm = "custom_sha256"

    def salt(self):
        # Generamos un salt aleatorio.
        return secrets.token_hex(16)

    def encode(self, password, salt):
        """
        Toma una contraseña en texto plano y un salt, y devuelve la contraseña hasheada.
        """
        # Usamos tu método de creación de contraseña, que internamente genera un hash y concatena el salt.
        salt = self.salt()
        salted_password = password + salt
        hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
        # Devolvemos esto en el formato que Django espera.
        return f"{self.algorithm}${hashed_password}${salt}"

    def verify(self, password, encoded):
        """
        Comprueba si la contraseña proporcionada en texto plano coincide con el hash almacenado.
        """
        algorithm, hashed_password, salt = encoded.split('$', 2)
        assert algorithm == self.algorithm

        # Utilizamos tu método de verificación de contraseña.
        salted_password = password + salt
        calculated_hash = hashlib.sha256(salted_password.encode()).hexdigest()

        # La comparación debe realizarse en tiempo constante para evitar ataques de temporización.
        return constant_time_compare(calculated_hash, hashed_password)

    def safe_summary(self, encoded):
        """
        Proporciona un resumen no sensible de la contraseña almacenada.
        """
        algorithm, hash, salt = encoded.split('$', 2)
        return {
            'algorithm': algorithm,
            'hash': hash,
            'salt': salt,
        }