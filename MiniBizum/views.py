from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from .forms import CustomUserCreationForm
from .my_hasher import MyPasswordHasher
import re


@login_required(login_url='login')
def main(request):
    if request.user.is_authenticated:
        return render(request, 'main.html', {})
    else:
        return render(request, '/logs/login.html', {})


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
            return render(request, '/logs/register.html',
                          {'form': form, 'error': 'El nombre de usuario es demasiado largo.'})

        if password1 == password2:
            if re.match(r'^[a-zA-Z]+$', username):
                if User.objects.filter(email=email).exists():
                    return render(request, 'logs/register.html',
                                  {'form': form, 'error': 'El email ya está registrado.'})
                try:
                    hasher = MyPasswordHasher()
                    user = User()
                    user.username = username
                    user.email = email
                    user.is_superuser = False
                    user.is_staff = False

                    # Ciframos la contraseña
                    user.password = hasher.encode(password=password1)

                    user.save()
                    login(request, user)
                    return redirect('home')
                except IntegrityError:
                    return render(request, 'logs/register.html', {'form': form, 'error': 'El usuario ya existe'})
            else:
                return render(request, 'logs/register.html',
                              {'form': form, 'error': 'El nombre de usuario debe contener solo letras'})
        return render(request, 'logs/register.html', {'form': form, 'error': 'Las contraseñas no coinciden'})


def login_view(request):
    if request.method == 'GET':
        return render(request, 'logs/login.html', {'form': AuthenticationForm})
    else:
        username = request.POST['username']
        password = request.POST['password']  # Esta es la contraseña en texto plano ingresada por el usuario

        # Comprobamos si el usuario existe en la base de datos.
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:  # TODO Hacer que salte error si el usuario no existe
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
