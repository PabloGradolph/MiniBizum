from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.db import IntegrityError
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from .forms import CustomUserCreationForm
from .my_hasher import MyPasswordHasher
from .algorithms import encrypt_data, generate_key, store_user_key, generate_dh_keys, store_user_keys
from Social.firma import generate_keys, store_private_key
from Social.certificate import create_certificate_for_user, load_ca_private_key_and_certificate
from django.conf import settings
import re


master_key = settings.MASTER_KEY


def signup_view(request):
    """
    Handles user registration with custom validations and encryption.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponse: The registration page on GET or POST with errors, or a redirection to 'home' on successful registration.
    """
    if request.method == 'GET':
        # Display the registration form for GET request
        form = CustomUserCreationForm()
        return render(request, 'logs/register.html', {'form': form})
    else:
        # Process the registration form on POST
        form = CustomUserCreationForm()
        username = request.POST['username']
        email = request.POST['email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        phone = request.POST['phone']
        
        # Custom validations
        if len(username) > 15 or not re.match(r'^[\w.]+$', username):
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
                # Create the user
                hasher = MyPasswordHasher()
                user = User()
                user.username = username
                user.is_superuser = False
                user.is_staff = False

                # Encrypt password and email.
                user.password, salt = hasher.encode(password1, None)
                key = generate_key(password1, salt)
                user.email = encrypt_data(email, key)
                user.save()

                # Encrypt the phone number and update the user's profile
                profile = user.profile
                profile.phone_number = encrypt_data(phone, key)
                
                # Generate keys and user certificate
                private_key, public_key = generate_keys()
                ca_private_key_pem, ca_certificate_pem = load_ca_private_key_and_certificate()
                user_certificate_pem = create_certificate_for_user(public_key, ca_private_key_pem, ca_certificate_pem, user.id, username, email, phone)
                profile.certificate = user_certificate_pem
                store_private_key(master_key, private_key, user.id)

                # Store the user key securely
                store_user_key(user.id, key, master_key)
                profile.save()
                dh_private_key, dh_public_key = generate_dh_keys()
                store_user_keys(user, dh_private_key, dh_public_key, user.password, salt)

                # Login the user
                login(request, user)
                return redirect('home')
                
            except IntegrityError:
                return render(request, 'logs/register.html', {'form': form, 'error': 'El usuario ya existe'})
        return render(request, 'logs/register.html', {'form': form, 'error': 'Las contraseñas no coinciden'})


def login_view(request):
    """
    Handles the login process for users.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponse: The login page on GET, or redirects to 'home' on successful login, or returns login page with error on failure.
    """
    if request.method == 'GET':
        # Display the login form for GET request
        return render(request, 'logs/login.html', {'form': AuthenticationForm})
    else:
        # Process the login form on POST
        username = request.POST['username']
        password = request.POST['password']  

        # Check if the user exists in the database
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return render(request, 'logs/login.html', {'form': AuthenticationForm,
                                                       'error': 'Usuario no encontrado'}
                          )

        # If the user exists, proceed to verify the password
        stored_password = user.password
        hasher = MyPasswordHasher()
        if hasher.verify(password, stored_password):
            # Authenticate the user if the password is correct
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, user)
            return redirect('home')
        else:
            return render(request, 'logs/login.html', {'form': AuthenticationForm,
                                                       'error': 'Contraseña incorrecta.'}
                          )


def logout_view(request):
    """
    Handles the logout process for users.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponseRedirect: Redirects to the login page after logging out.
    """
    # Log out the user and redirect to the login page
    logout(request)
    return redirect('login')
