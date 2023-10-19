# 💳 MiniBizum
La aplicacion desarrollada es una red social que permite la posibilidad de mandar dinero a tus amigos, familiares, etc. de una manera sencilla y rapida. De igual manera permite a los usuarios publicar mensajes en cada una de las transacciones que hacen para que sus 'amigos' puedan verlos.
# 💡 Contenido
- [Funcionalidades](#funcionalidades)
- [Ejecución](#ejecución)
- [Consideraciones](#consideraciones)
- [Cifrado simétrico](#cifrado-simétrico)
  - [Cifrado y descifrado con AES-128](#cifrado-y-descifrado-con-aes-128)
- [Funciones hash o HMAC](#funciones-hash-o-hmac)
    - [Función resumen con SHA-256](#función-resumen-con-sha-256)
- [Autenticación](#autenticación)
    - [Infraestructura de Clave Pública (PKI)](#infraestructura-de-clave-pública-pki)
- [Firma digital](#firma-digital)
    - [Firma y verificación con RSA](#firma-y-verificación-con-rsa)
- [Mejoras realizadas](#mejoras-realizadas)
- [Conclusión](#conclusión)

# Funcionalidades
En cuanto a las funcionalidades, observamos las siguientes:
- **Registro de usuarios:** El usuario se registra en la aplicación con su nombre, apellidos, email, y contraseña. Los cuales estan cifrados para proteger la información del usuario y evitar posibles ataques.

# Prueba el Proyecto 🚀
1. Clona el repositorio: `git clone https://github.com/PabloGradolph/SciencesPath.git`
2. Instala las dependencias necesarias: `pip install -r requirements.txt`
3. Configura los ajustes de tu base de datos en `settings.py` (Puedes usar la configuración que viene por defecto con sqlite3)
4. Aplica las migraciones con: `python manage.py migrate`
5. Ejecuta el servidor de desarrollo: `python manage.py runserver`
