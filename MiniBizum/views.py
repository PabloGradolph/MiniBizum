from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from .forms import CustomUserCreationForm
from django.db import IntegrityError
import re
import hashlib
import secrets


def main(request):
    return render(request, 'main.html', {})


def signup_view(request):
    # Método GET del formulario.
    if request.method == 'GET':
        form = CustomUserCreationForm()
        return render(request, 'logs/register.html', {'form': form})
    
    # Método POST del formulario.
    else:
        form = CustomUserCreationForm()
        username = request.POST['username']
        email = request.POST['email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']

        # Gestión de errores.
        if len(username) > 35:
                return render(request, 'logs/register.html', {'form': form, 'error': 'El nombre de usuario es demasiado largo.'})
        
        if password1 == password2:
            if re.match(r'^[a-zA-Z]+$', username):
                if User.objects.filter(email=email).exists():
                    return render(request, 'logs/register.html', {'form': form, 'error': 'El email ya está registrado.'})
                try:
                    user = User()
                    user.username = username
                    user.email = email
                    user.is_superuser = False
                    user.is_staff = False

                    # Ciframos la contraseña
                    user.password = make_password(password=password1)

                    user.save()
                    login(request, user)
                    return redirect('home')
                except IntegrityError:
                    return render(request, 'logs/register.html', {'form': form, 'error': 'El usuario ya existe'})
            else:
                return render(request, 'logs/register.html', {'form': form, 'error': 'El nombre de usuario debe contener solo letras'})
        return render(request, 'logs/register.html', {'form': form, 'error': 'Las contraseñas no coinciden'})


def login_view(request):
    if request.method == 'GET':
        return render(request, 'logs/login.html', {'form': AuthenticationForm})
    else:
        username = request.POST['username']
        password = request.POST['password'] # Esta es la contraseña en texto plano ingresada por el usuario

        # Comprobamos si el usuario existe en la base de datos.
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return render(request, 'logs/login.html', {'form': AuthenticationForm,
                'error': 'Usuario no encontrado'}
            )

        # Si el usuario existe, procedemos a verificar la contraseña.
        stored_password = user.password
        if check_password(stored_password, password):
            # Autenticamos al usuario si la contraseña es correcta.
            user.backend = 'django.contrib.auth.backends.ModelBackend' 
            login(request, user)
            return redirect('home')
        else:
            return render(request, 'logs/login.html', {'form': AuthenticationForm,
                'error': 'Contraseña incorrecta.'}
            )


def logout_view(request):
    logout(request)
    return redirect('login')


def make_password(password):
    # Generamos un salt aleatorio: Evita ciertos ataques
    secure_salt = secrets.token_hex(16)
    salted_password = password + secure_salt

    # Calculamos el has de la contraseña combinada.
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()

    # Devolvemos el hash y el salt, para que ambos puedan ser almacenados.
    return f"{hashed_password}${secure_salt}" # Nota: almacenamos ambos en una sola cadena para conveniencia.


def check_password(stored_password, user_input_password):
    # Dividimos el hash y el salt.
    parts = stored_password.split("$")
    if len(parts) != 2:
        raise ValueError("La contraseña almacenada tiene un formato incorrecto.")
    
    hashed_password = parts[0]
    secure_salt = parts[1]

    # Repetimos el proceso de hashing en la contraseña que el usuario ha ingresado para autenticarse.
    salted_password = user_input_password + secure_salt
    calculated_hash = hashlib.sha256(salted_password.encode()).hexdigest()

    # Si los hashes coinciden, la contraseña es correcta.
    return hashed_password == calculated_hash