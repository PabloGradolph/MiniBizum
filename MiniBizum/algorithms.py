import secrets
import os
import base64
import hashlib


# def make_password(password: str) -> str:
#     # Generamos un salt aleatorio: Evita ciertos ataques y que dos usuarios con la misma contraseña tengan el
#     # mismo hash.
#     secure_salt = secrets.token_hex(16)
#     salted_password = password + secure_salt

#     # Calculamos el hash de la contraseña combinada.
#     hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()

#     # Devolvemos el hash y el salt, para que ambos puedan ser almacenados.
#     return f"{hashed_password}${secure_salt}"  # Nota: almacenamos ambos en una sola cadena para conveniencia.


# def check_password(stored_password: str, user_input_password: str) -> bool:
#     # Dividimos el hash y el salt.
#     parts = stored_password.split("$")
#     if len(parts) != 2:
#         raise ValueError("La contraseña almacenada tiene un formato incorrecto.")

#     # Obtenemos el hash y el salt.
#     hashed_password = parts[0]
#     secure_salt = parts[1]

#     # Repetimos el proceso de hashing en la contraseña que el usuario ha ingresado para autenticarse.
#     salted_password = user_input_password + secure_salt
#     calculated_hash = hashlib.sha256(salted_password.encode()).hexdigest()

#     # Si los hashes coinciden, la contraseña es correcta.
#     return hashed_password == calculated_hash
