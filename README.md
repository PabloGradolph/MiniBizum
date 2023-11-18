# 💳 MiniBizum
La aplicacion desarrollada es una red social que permite la posibilidad de mandar dinero a tus amigos, familiares, etc. de una manera sencilla y rapida. De igual manera permite a los usuarios publicar mensajes en cada una de las transacciones que hacen para que sus _amigos_ puedan verlos.

Todo esto con la total seguridad debido a las características criptográficas incluidas en la aplicación, como cifrado de datos personales de los usuarios, cifrado de extremo a extremo de las transacciones entre usuarios, firmas y certificados de las claves públicas de los usuarios.
# 💡 Contenido
- [Ejecución](#ejecución)
- [Funcionalidades](#funcionalidades)

# Ejecución
1. Clona el repositorio: `git clone https://github.com/PabloGradolph/SciencesPath.git`
2. Instala las dependencias necesarias: `pip install -r requirements.txt`
3. Configura los ajustes de tu base de datos en `settings.py` (Puedes usar la configuración que viene por defecto con sqlite3)
4. Aplica las migraciones con: `python manage.py migrate`
5. Crea la autoridad de certificación (CA): `python manage.py createCA`
6. Ejecuta el servidor de desarrollo: `python manage.py runserver`

# Funcionalidades
En cuanto a las funcionalidades, observamos las siguientes:
- **Registro de usuarios:** El usuario se registra en la aplicación con su nombre, apellidos, email, y contraseña. Los cuales estan cifrados para proteger la información del usuario y evitar posibles ataques.
- **Envío de transacciones:** El usuario puede mandar dinero a otros usuarios de la aplicación de forma segura mediante el uso de cifrado de datos sensibles y firma de la transacción para que el recipiente se asegure de la procedencia del dinero.
- **Solicitud de transacciones:** El usuario puede solicitar dinero a otros usuarios de forma segura ya que solo ambos podrán ver la cantidad y el concepto de la solicitud protegiéndolos de posibles ataques.

## 👥 Authors

- [@PabloGradolph](https://github.com/PabloGradolph)
- [@victorvalchez](https://www.github.com/victorvalchez)


![Logo](https://upload.wikimedia.org/wikipedia/commons/4/47/Acronimo_y_nombre_uc3m.png)

