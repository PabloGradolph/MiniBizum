from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from .forms import CustomUserCreationForm
from .my_hasher import MyPasswordHasher
from .algorithms import encrypt_data, generate_key, decrypt_data, store_user_key, load_user_key
from Social.firma import generate_keys, store_private_key
from Social.certificate import create_certificate_for_user, load_ca_private_key_and_certificate
from django.conf import settings
import re


master_key = settings.MASTER_KEY


@login_required(login_url='login')
def main(request):
    user_key = load_user_key(request.user.id, master_key)
    email = request.user.email
    phone = request.user.profile.phone_number
    request.user.email = decrypt_data(email, user_key)
    request.user.profile.phone_number = decrypt_data(phone, user_key)
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
        phone = request.POST['phone']
        
        # Gestión de errores.
        if len(username) > 35:
            return render(request, 'logs/register.html',
                          {'form': form, 'error': 'El nombre de usuario es demasiado largo.'})

        if len(phone) != 9:
            return render(request, 'logs/register.html',
                          {'form': form, 'error': 'Introduce un número de teléfono válido.'})

        patron = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@#$%^&+=!(){}[\]:;<>,.?~\\|_\-])(?=\S+$).{8,}$'
        if not re.match(patron, password1):
            return render(request, 'logs/register.html',
                          {'form': form, 'error': 'La contraseña no cumple los requisitos.'})

        if password1 == password2:
            if User.objects.filter(email=email).exists():
                return render(request, 'logs/register.html',
                            {'form': form, 'error': 'El email ya está registrado.'})
            try:
                hasher = MyPasswordHasher()
                user = User()
                user.username = username
                user.is_superuser = False
                user.is_staff = False

                # Ciframos la contraseña y el email.
                user.password, salt = hasher.encode(password1, None)
                key = generate_key(password1, salt)
                user.email = encrypt_data(email, key)
                user.save()

                # Ciframos el número de teléfono y actualizamos el perfil del usuario con el mismo.
                profile = user.profile
                profile.phone_number = encrypt_data(phone, key)
                
                private_key, public_key = generate_keys()

                ca_private_key_pem, ca_certificate_pem = load_ca_private_key_and_certificate()
                user_certificate_pem = create_certificate_for_user(public_key, ca_private_key_pem, ca_certificate_pem, user.id, username, email, phone)
                profile.certificate = user_certificate_pem
                store_private_key(master_key, private_key, user.id)
                profile.save()

                # Almacenamos la clave del usuario de manera segura.
                store_user_key(user.id, key, master_key)

                
                login(request, user)
                return redirect('home')
                
            except IntegrityError:
                return render(request, 'logs/register.html', {'form': form, 'error': 'El usuario ya existe'})
        return render(request, 'logs/register.html', {'form': form, 'error': 'Las contraseñas no coinciden'})


def login_view(request):
    if request.method == 'GET':
        return render(request, 'logs/login.html', {'form': AuthenticationForm})
    else:
        username = request.POST['username']
        password = request.POST['password']  

        # Comprobamos si el usuario existe en la base de datos.
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return render(request, 'logs/login.html', {'form': AuthenticationForm,
                                                       'error': 'Usuario no encontrado'}
                          )

        # Si el usuario existe, procedemos a verificar la contraseña.
        stored_password = user.password
        hasher = MyPasswordHasher()
        if hasher.verify(password, stored_password):
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
