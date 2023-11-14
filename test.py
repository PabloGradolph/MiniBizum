from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def generar_claves():
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

def firmar_mensaje(private_key, mensaje):
    # Cargar la clave privada desde su representación en bytes
    private_key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend()
    )

    # Firmar el mensaje
    firma = private_key.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return firma

def verificar_firma(public_key, mensaje, firma):
    # Cargar la clave pública desde su representación en bytes
    public_key = serialization.load_pem_public_key(
        public_key,
        backend=default_backend()
    )

    try:
        # Verificar la firma
        public_key.verify(
            firma,
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Ejemplo de uso
private_key, public_key = generar_claves()
print("Clave privada:", private_key, "\nClave pública:", public_key)

mensaje = b"Este es un mensaje de ejemplo."

firma = firmar_mensaje(private_key, mensaje)
print("Firma:", firma)

verificacion = verificar_firma(public_key, mensaje, firma)
print("Verificacion de firma:", verificacion)